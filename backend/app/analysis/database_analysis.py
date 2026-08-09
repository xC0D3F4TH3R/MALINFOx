"""MALINFO — Database File Analysis (SQLite, MDB, ACCDB)

Analysis of database files for embedded artifacts and sensitive data.
"""
from __future__ import annotations

import logging
import sqlite3
import subprocess
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.database_analysis")


def analyze_database(file_path: Path) -> dict:
    """
    Analyze database file (SQLite, MDB, ACCDB).
    """
    result: dict = {
        "available": True,
        "format": "Database",
        "db_type": "",
        "tables": [],
        "table_details": {},
        "sqlite_info": {},
        "sensitive_data": [],
        "urls": [],
        "ips": [],
        "domains": [],
        "emails": [],
        "executables": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read(8192)

        result["entropy"] = round(shannon_entropy(data), 3)

        # Detect database type
        if data[:16] == b"SQLite format 3\x00":
            result["db_type"] = "SQLite"
            result["format"] = "SQLite Database"
            _analyze_sqlite(file_path, result)
        elif data[:16] == b"Standard Jet DB":
            result["db_type"] = "MDB"
            result["format"] = "Microsoft Access (MDB)"
            _analyze_mdb(file_path, result)
        elif file_path.suffix.lower() == ".accdb":
            result["db_type"] = "ACCDB"
            result["format"] = "Microsoft Access (ACCDB)"
            _analyze_accdb(file_path, result)
        else:
            result["errors"].append("Unsupported database format")

    except Exception as exc:
        logger.debug(f"Database analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_sqlite(file_path: Path, result: dict) -> None:
    """Analyze SQLite database."""
    try:
        conn = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Get database info
        cursor.execute("PRAGMA page_count;")
        page_count = cursor.fetchone()[0]
        cursor.execute("PRAGMA page_size;")
        page_size = cursor.fetchone()[0]
        result["sqlite_info"]["page_count"] = page_count
        result["sqlite_info"]["page_size"] = page_size
        result["sqlite_info"]["database_size"] = page_count * page_size

        cursor.execute("PRAGMA freelist_count;")
        result["sqlite_info"]["freelist_count"] = cursor.fetchone()[0]

        cursor.execute("PRAGMA schema_version;")
        result["sqlite_info"]["schema_version"] = cursor.fetchone()[0]

        # Get tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [row[0] for row in cursor.fetchall()]
        result["tables"] = tables

        # Analyze each table
        for table in tables:
            if table.startswith(("sqlite_", "android_")):
                continue  # Skip system tables

            try:
                cursor.execute(f"PRAGMA table_info({table});")
                columns = cursor.fetchall()
                col_info = [{"name": c[1], "type": c[2], "notnull": c[3], "pk": c[5]} for c in columns]

                cursor.execute(f"SELECT COUNT(*) FROM {table};")
                row_count = cursor.fetchone()[0]

                result["table_details"][table] = {
                    "columns": col_info,
                    "row_count": row_count,
                }

                # Sample data for sensitive info detection
                if row_count > 0:
                    cursor.execute(f"SELECT * FROM {table} LIMIT 10;")
                    rows = cursor.fetchall()
                    result["table_details"][table]["sample_rows"] = rows

                    # Check for sensitive data
                    _check_table_for_sensitive(table, col_info, rows, result)

            except Exception as exc:
                logger.debug(f"Failed to analyze table {table}: {exc}")
                result["table_details"][table] = {"error": str(exc)}

        # Check for browser databases
        _detect_browser_db(tables, result)

        conn.close()

    except sqlite3.DatabaseError as exc:
        result["errors"].append(f"SQLite error: {exc}")
    except Exception as exc:
        result["errors"].append(f"SQLite analysis failed: {exc}")


def _check_table_for_sensitive(table: str, columns: list, rows: list, result: dict) -> None:
    """Check table data for sensitive information."""
    import re

    sensitive_columns = [
        "password", "passwd", "pwd", "secret", "token", "key", "apikey",
        "username", "user", "email", "login", "credential", "auth",
        "session", "cookie", "jwt", "bearer", "oauth",
        "url", "uri", "endpoint", "host", "server", "c2", "command",
        "ip", "address", "domain", "hostname",
    ]

    for col in columns:
        col_name = col["name"].lower()
        for sensitive in sensitive_columns:
            if sensitive in col_name:
                result["sensitive_data"].append({
                    "table": table,
                    "column": col["name"],
                    "type": sensitive,
                })
                break

    # Check row data
    for row in rows:
        for value in row:
            if value is None:
                continue
            str_val = str(value)

            # URLs
            urls = re.findall(r'https?://[^\s"\']+', str_val)
            for url in urls:
                result["urls"].append({"table": table, "url": url})

            # IPs
            ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', str_val)
            for ip in ips:
                result["ips"].append({"table": table, "ip": ip})

            # Domains
            domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|tk|cc|io|onion|gov|edu|in|co|me|club|site|online|link)\b', str_val, re.IGNORECASE)
            for domain in domains:
                result["domains"].append({"table": table, "domain": domain})

            # Emails
            emails = re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', str_val)
            for email in emails:
                result["emails"].append({"table": table, "email": email})

            # Executable paths
            if str_val.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".py")):
                result["executables"].append({"table": table, "path": str_val})


def _detect_browser_db(tables: list, result: dict) -> None:
    """Detect browser database types."""
    browser_indicators = {
        "Chrome": ["urls", "downloads", "history", "cookies", "logins", "keywords", "shortcuts", "favicons", "top_sites"],
        "Firefox": ["moz_places", "moz_historyvisits", "moz_bookmarks", "moz_cookies", "moz_logins", "moz_formhistory"],
        "Edge": ["urls", "downloads", "history", "cookies", "logins", "keywords"],  # Similar to Chrome
        "Safari": ["history_items", "history_visits", "bookmarks", "downloads"],
    }

    for browser, indicators in browser_indicators.items():
        matches = [t for t in tables if any(ind in t.lower() for ind in indicators)]
        if len(matches) >= 3:
            result["browser_database"] = browser
            result["browser_tables"] = matches
            break


def _analyze_mdb(file_path: Path, result: dict) -> None:
    """Analyze MDB (Access) database using mdbtools."""
    try:
        # List tables
        proc = subprocess.run(
            ["mdb-tables", "-1", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            tables = proc.stdout.strip().split("\n")
            result["tables"] = [t for t in tables if t]

            # Export schema
            proc = subprocess.run(
                ["mdb-schema", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if proc.returncode == 0:
                result["schema"] = proc.stdout[:5000]

            # Export data for each table (limited)
            for table in result["tables"][:10]:
                proc = subprocess.run(
                    ["mdb-export", str(file_path), table],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if proc.returncode == 0:
                    lines = proc.stdout.strip().split("\n")
                    if len(lines) > 1:
                        headers = lines[0].split(",")
                        result["table_details"][table] = {
                            "columns": headers,
                            "row_count": len(lines) - 1,
                            "sample_rows": [l.split(",") for l in lines[1:6]],
                        }

    except FileNotFoundError:
        result["errors"].append("mdbtools not installed (mdb-tables, mdb-schema, mdb-export)")
    except Exception as exc:
        result["errors"].append(f"MDB analysis failed: {exc}")


def _analyze_accdb(file_path: Path, result: dict) -> None:
    """Analyze ACCDB (Access 2007+) database."""
    # ACCDB uses ACE engine - try mdbtools with --accdb flag
    try:
        proc = subprocess.run(
            ["mdb-tables", "-1", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            tables = proc.stdout.strip().split("\n")
            result["tables"] = [t for t in tables if t]
        else:
            result["errors"].append("mdbtools may not support ACCDB format")
    except FileNotFoundError:
        result["errors"].append("mdbtools not installed")
    except Exception as exc:
        result["errors"].append(f"ACCDB analysis failed: {exc}")


def analyze_database_file(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_database(file_path)