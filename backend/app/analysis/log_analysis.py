"""MALINFO — Log File Analysis (EVTX, Sysmon, Zeek, Suricata, generic)

Analysis of log files with MITRE ATT&CK mapping.
"""
from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Optional

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.log_analysis")


def analyze_log(file_path: Path) -> dict:
    """
    Analyze log file.
    Supports: EVTX, Sysmon, Zeek/Bro, Suricata Eve, generic text/CSV/TSV
    """
    result: dict = {
        "available": True,
        "format": "Log File",
        "log_type": "",
        "parser": "",
        "entries": [],
        "entry_count": 0,
        "time_range": {},
        "mitre_techniques": [],
        "suspicious_indicators": [],
        "process_creates": [],
        "network_connections": [],
        "file_operations": [],
        "registry_operations": [],
        "dns_queries": [],
        "http_requests": [],
        "alerts": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read(8192)

        result["entropy"] = round(shannon_entropy(data), 3)

        ext = file_path.suffix.lower()

        # Detect log type
        if ext == ".evtx":
            result["log_type"] = "EVTX"
            _analyze_evtx(file_path, result)
        elif ext in (".json", ".eve.json", ".jsonl"):
            # Check for Suricata Eve or Zeek
            text = data.decode("utf-8", errors="ignore")
            if "event_type" in text and ("flow" in text or "alert" in text or "dns" in text or "http" in text):
                result["log_type"] = "Suricata Eve"
                _analyze_suricata_eve(file_path, result)
            elif "ts" in text and ("uid" in text or "id.orig_h" in text):
                result["log_type"] = "Zeek/Bro"
                _analyze_zeek(file_path, result)
            else:
                result["log_type"] = "JSON Lines"
                _analyze_json_lines(file_path, result)
        elif ext in (".log", ".txt", ".csv", ".tsv"):
            result["log_type"] = "Text/CSV/TSV"
            _analyze_text_log(file_path, result)
        else:
            # Try to detect by content
            text = data.decode("utf-8", errors="ignore")
            if "event_type" in text and ("flow" in text or "alert" in text):
                result["log_type"] = "Suricata Eve"
                _analyze_suricata_eve(file_path, result)
            elif "ts" in text and "uid" in text and "id.orig_h" in text:
                result["log_type"] = "Zeek/Bro"
                _analyze_zeek(file_path, result)
            else:
                result["log_type"] = "Generic Text"
                _analyze_text_log(file_path, result)

    except Exception as exc:
        logger.debug(f"Log analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_evtx(file_path: Path, result: dict) -> None:
    """Analyze Windows EVTX log."""
    try:
        import Evtx.Evtx as evtx

        log = evtx.Evtx(str(file_path))
        result["parser"] = "python-evtx"

        # Get file info
        result["file_header"] = {
            "magic": log.get_file_header().signature().hex(),
            "first_chunk": log.get_file_header().first_chunk_number(),
            "last_chunk": log.get_file_header().last_chunk_number(),
            "next_record": log.get_file_header().next_record_number(),
        }

        # Parse records (limit to first 1000)
        count = 0
        for record in log.records():
            if count >= 1000:
                break

            try:
                xml = record.xml()
                result["entries"].append(xml[:2000])
                count += 1

                # Quick MITRE detection
                _detect_mitre_from_xml(xml, result)

            except Exception:
                pass

        result["entry_count"] = count

        # Check for Sysmon
        if any("Microsoft-Windows-Sysmon" in e for e in result["entries"]):
            result["parser"] = "python-evtx (Sysmon)"
            result["log_type"] = "Sysmon (EVTX)"

    except ImportError:
        result["errors"].append("python-evtx not installed")
    except Exception as exc:
        result["errors"].append(f"EVTX analysis failed: {exc}")


def _analyze_suricata_eve(file_path: Path, result: dict) -> None:
    """Analyze Suricata Eve JSON logs."""
    try:
        result["parser"] = "Suricata Eve JSON"
        count = 0

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if count >= 1000:
                    break
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    result["entries"].append(event)
                    count += 1

                    event_type = event.get("event_type", "")

                    if event_type == "alert":
                        result["alerts"].append(event)
                        _detect_mitre_from_suricata_alert(event, result)
                    elif event_type == "dns":
                        result["dns_queries"].append(event)
                    elif event_type == "http":
                        result["http_requests"].append(event)
                    elif event_type == "flow":
                        result["network_connections"].append(event)
                    elif event_type == "tls":
                        # TLS certificate info
                        pass
                    elif event_type == "ssh":
                        # SSH info
                        pass
                    elif event_type == "files":
                        # File info
                        pass

                except json.JSONDecodeError:
                    pass

        result["entry_count"] = count

    except Exception as exc:
        result["errors"].append(f"Suricata Eve analysis failed: {exc}")


def _analyze_zeek(file_path: Path, result: dict) -> None:
    """Analyze Zeek/Bro logs (JSON format)."""
    try:
        result["parser"] = "Zeek/Bro JSON"
        count = 0

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if count >= 1000:
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    event = json.loads(line)
                    result["entries"].append(event)
                    count += 1

                    # Detect log type from fields
                    if "id.orig_h" in event and "id.resp_h" in event:
                        result["network_connections"].append(event)
                    if "query" in event and "answers" in event:
                        result["dns_queries"].append(event)
                    if "method" in event and "uri" in event:
                        result["http_requests"].append(event)
                    if "ts" in event and "uid" in event:
                        pass

                except json.JSONDecodeError:
                    pass

        result["entry_count"] = count

    except Exception as exc:
        result["errors"].append(f"Zeek analysis failed: {exc}")


def _analyze_json_lines(file_path: Path, result: dict) -> None:
    """Analyze generic JSON Lines log."""
    try:
        result["parser"] = "JSON Lines"
        count = 0

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if count >= 1000:
                    break
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    result["entries"].append(event)
                    count += 1

                    # Try to extract common fields
                    _extract_iocs_from_json(event, result)

                except json.JSONDecodeError:
                    pass

        result["entry_count"] = count

    except Exception as exc:
        result["errors"].append(f"JSON Lines analysis failed: {exc}")


def _analyze_text_log(file_path: Path, result: dict) -> None:
    """Analyze generic text/CSV/TSV log."""
    try:
        result["parser"] = "Text/CSV/TSV"
        count = 0

        with open(file_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if count >= 1000:
                    break
                line = line.strip()
                if not line:
                    continue

                result["entries"].append(line[:1000])
                count += 1

                # Extract IOCs
                _extract_iocs_from_text(line, result)

                # Detect Sysmon patterns
                if "EventID" in line and ("Process Create" in line or "Network Connection" in line):
                    result["log_type"] = "Sysmon (Text)"

        result["entry_count"] = count

    except Exception as exc:
        result["errors"].append(f"Text log analysis failed: {exc}")


def _detect_mitre_from_xml(xml: str, result: dict) -> None:
    """Detect MITRE ATT&CK techniques from EVTX XML."""
    mitre_patterns = {
        "T1059": ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32"],
        "T1055": ["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", "OpenProcess"],
        "T1027": ["base64", "encodedcommand", "obfuscated", "xor", "aes", "rc4"],
        "T1547": ["Run", "RunOnce", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "T1053": ["schtasks", "at.exe", "TaskScheduler"],
        "T1012": ["regsvr32", "rundll32", "sc.exe", "services.exe"],
        "T1105": ["certutil", "bitsadmin", "powershell.*download", "wget", "curl", "Invoke-WebRequest"],
        "T1003": ["lsass", "sekurlsa", "mimikatz", "gsecdump"],
        "T1005": ["copy", "xcopy", "robocopy", "compress"],
        "T1016": ["net view", "net group", "net user", "dsquery", "adfind"],
        "T1069": ["net localgroup", "net group", "Get-LocalGroup"],
        "T1082": ["systeminfo", "hostname", "whoami", "ipconfig"],
        "T1083": ["dir", "ls", "Get-ChildItem", "Find-Files"],
        "T1087": ["net user", "whoami", "Get-LocalUser"],
    }

    xml_lower = xml.lower()
    for technique, keywords in mitre_patterns.items():
        if any(kw.lower() in xml_lower for kw in keywords):
            if technique not in result["mitre_techniques"]:
                result["mitre_techniques"].append(technique)


def _detect_mitre_from_suricata_alert(event: dict, result: dict) -> None:
    """Detect MITRE from Suricata alert."""
    alert = event.get("alert", {})
    signature = alert.get("signature", "").lower()
    category = alert.get("category", "").lower()

    mitre_map = {
        "T1071": ["command and control", "c2", "beacon", "trojan", "botnet"],
        "T1041": ["exfiltration", "data theft", "data leak"],
        "T1068": ["exploit", "vulnerability", "cve-"],
        "T1499": ["dos", "denial of service", "flood"],
        "T1040": ["sniffing", "traffic capture", "mitm"],
        "T1573": ["encrypted channel", "tls", "ssl", "https"],
    }

    for technique, keywords in mitre_map.items():
        if any(kw in signature or kw in category for kw in keywords):
            if technique not in result["mitre_techniques"]:
                result["mitre_techniques"].append(technique)


def _extract_iocs_from_json(event: dict, result: dict) -> None:
    """Extract IOCs from JSON event."""

    def extract_from_value(value):
        if isinstance(value, str):
            urls = re.findall(r'https?://[^\s"\']+', value)
            for url in urls:
                if url not in [u.get("url") for u in result["urls"]]:
                    result["urls"].append({"url": url})

            ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', value)
            for ip in ips:
                if ip not in [i.get("ip") for i in result["ips"]]:
                    result["ips"].append({"ip": ip})

            domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|tk|cc|io|onion|gov|edu|in|co|me|club|site|online|link)\b', value, re.IGNORECASE)
            for domain in domains:
                if domain not in [d.get("domain") for d in result["domains"]]:
                    result["domains"].append({"domain": domain})

    for key, value in event.items():
        if isinstance(value, dict):
            extract_from_value(json.dumps(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (str, dict)):
                    extract_from_value(json.dumps(item) if isinstance(item, dict) else item)
        else:
            extract_from_value(value)


def _extract_iocs_from_text(text: str, result: dict) -> None:
    """Extract IOCs from text line."""

    urls = re.findall(r'https?://[^\s"\']+', text)
    for url in urls:
        if url not in [u.get("url") for u in result["urls"]]:
            result["urls"].append({"url": url})

    ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', text)
    for ip in ips:
        if ip not in [i.get("ip") for i in result["ips"]]:
            result["ips"].append({"ip": ip})

    domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|tk|cc|io|onion|gov|edu|in|co|me|club|site|online|link)\b', text, re.IGNORECASE)
    for domain in domains:
        if domain not in [d.get("domain") for d in result["domains"]]:
            result["domains"].append({"domain": domain})


def analyze_log_file(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_log(file_path)