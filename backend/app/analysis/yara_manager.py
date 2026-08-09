"""
MALINFO — YARA Rule Management System.

Comprehensive YARA rule management with feeds, versioning, compilation caching,
performance metrics, rule testing harness, and false positive tracking.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("malinfo.yara_manager")

# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class YaraRule:
    """Represents a single YARA rule."""
    rule_id: str
    name: str
    namespace: str
    source: str
    file_path: str
    content: str
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    severity: str = "medium"
    mitre_techniques: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1
    enabled: bool = True
    hash: str = ""
    
    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(self.content.encode()).hexdigest()[:16]


@dataclass
class YaraRuleset:
    """A collection of YARA rules compiled together."""
    ruleset_id: str
    name: str
    description: str
    rules: list[YaraRule] = field(default_factory=list)
    compiled_path: str | None = None
    compiled_at: datetime | None = None
    compilation_time_ms: float = 0
    rule_count: int = 0
    enabled_rule_count: int = 0
    performance_stats: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1


@dataclass
class YaraFeed:
    """External YARA rule feed configuration."""
    feed_id: str
    name: str
    url: str
    auth_type: str = "none"  # none, bearer, basic, api_key
    auth_config: dict = field(default_factory=dict)
    schedule: str = "daily"  # hourly, daily, weekly
    filters: dict = field(default_factory=dict)  # tag, author, severity filters
    last_sync: datetime | None = None
    last_sync_status: str = "never"
    rules_imported: int = 0
    enabled: bool = True


# ──────────────────────────────────────────────────────────────────────────────

class YaraManager:
    """
    Central YARA rule management system.
    
    Features:
    - Rule versioning and compilation caching
    - External feed synchronization (MalwareBazaar, YARA-Rules, custom)
    - Performance monitoring and optimization
    - Rule testing harness with false positive tracking
    - Incremental compilation
    - Parallel compilation worker pool
    """
    
    def __init__(self, base_dir: Path | None = None):
        self.base_dir = base_dir or Path("/opt/malinfo/rules/yara")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.rules_dir = self.base_dir / "sources"
        self.compiled_dir = self.base_dir / "compiled"
        self.feeds_dir = self.base_dir / "feeds"
        self.test_cases_dir = self.base_dir / "test_cases"
        self.metadata_db = self.base_dir / "metadata.sqlite"
        self.performance_db = self.base_dir / "performance.sqlite"
        
        for d in [self.rules_dir, self.compiled_dir, self.feeds_dir, self.test_cases_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        self._init_databases()
        self._load_feeds()
        
        # Compilation lock to prevent concurrent compiles
        self._compile_lock = threading.Lock()
        
        # In-memory cache
        self._ruleset_cache: dict[str, YaraRuleset] = {}
        self._rule_cache: dict[str, YaraRule] = {}
    
    def _init_databases(self):
        """Initialize SQLite databases for metadata and performance tracking."""
        import sqlite3
        
        # Metadata DB
        with sqlite3.connect(self.metadata_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    namespace TEXT,
                    source TEXT,
                    file_path TEXT,
                    content_hash TEXT,
                    tags TEXT,  -- JSON array
                    meta TEXT,  -- JSON object
                    severity TEXT,
                    mitre_techniques TEXT,  -- JSON array
                    enabled INTEGER DEFAULT 1,
                    version INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rulesets (
                    ruleset_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    rule_ids TEXT,  -- JSON array
                    compiled_path TEXT,
                    compiled_at TEXT,
                    compilation_time_ms REAL,
                    rule_count INTEGER,
                    enabled_rule_count INTEGER,
                    performance_stats TEXT,  -- JSON
                    version INTEGER DEFAULT 1,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feeds (
                    feed_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    auth_type TEXT,
                    auth_config TEXT,  -- JSON
                    schedule TEXT,
                    filters TEXT,  -- JSON
                    last_sync TEXT,
                    last_sync_status TEXT,
                    rules_imported INTEGER DEFAULT 0,
                    enabled INTEGER DEFAULT 1
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS test_cases (
                    test_id TEXT PRIMARY KEY,
                    rule_id TEXT,
                    sample_path TEXT,
                    expected_match INTEGER,  -- 1 for should match, 0 for should not
                    created_at TEXT
                )
            """)
        
        # Performance DB
        with sqlite3.connect(self.performance_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rule_performance (
                    rule_id TEXT PRIMARY KEY,
                    total_scans INTEGER DEFAULT 0,
                    total_matches INTEGER DEFAULT 0,
                    total_time_ms REAL DEFAULT 0,
                    avg_time_ms REAL DEFAULT 0,
                    max_time_ms REAL DEFAULT 0,
                    min_time_ms REAL DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    last_scan_at TEXT,
                    updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ruleset_performance (
                    ruleset_id TEXT PRIMARY KEY,
                    total_scans INTEGER DEFAULT 0,
                    total_time_ms REAL DEFAULT 0,
                    avg_time_ms REAL DEFAULT 0,
                    rule_count INTEGER DEFAULT 0,
                    last_scan_at TEXT,
                    updated_at TEXT
                )
            """)
    
    def _load_feeds(self):
        """Load feed configurations from database."""
        import sqlite3
        with sqlite3.connect(self.metadata_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM feeds WHERE enabled = 1")
            for row in cursor:
                feed = YaraFeed(
                    feed_id=row["feed_id"],
                    name=row["name"],
                    url=row["url"],
                    auth_type=row["auth_type"],
                    auth_config=json.loads(row["auth_config"]) if row["auth_config"] else {},
                    schedule=row["schedule"],
                    filters=json.loads(row["filters"]) if row["filters"] else {},
                    last_sync=datetime.fromisoformat(row["last_sync"]) if row["last_sync"] else None,
                    last_sync_status=row["last_sync_status"],
                    rules_imported=row["rules_imported"],
                    enabled=bool(row["enabled"]),
                )
                self._save_feed(feed)
    
    # ──────────────────────────────────────────────────────────────────────────
    # Feed Management
    # ──────────────────────────────────────────────────────────────────────────
    
    def add_feed(self, feed: YaraFeed) -> bool:
        """Add a new YARA feed."""
        try:
            import sqlite3
            with sqlite3.connect(self.metadata_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO feeds 
                    (feed_id, name, url, auth_type, auth_config, schedule, filters, 
                     last_sync, last_sync_status, rules_imported, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    feed.feed_id, feed.name, feed.url, feed.auth_type,
                    json.dumps(feed.auth_config), feed.schedule,
                    json.dumps(feed.filters),
                    feed.last_sync.isoformat() if feed.last_sync else None,
                    feed.last_sync_status, feed.rules_imported, int(feed.enabled)
                ))
            self._save_feed(feed)
            return True
        except Exception as exc:
            logger.exception(f"Failed to add feed {feed.feed_id}: {exc}")
            return False
    
    def _save_feed(self, feed: YaraFeed):
        """Save feed to local file for reference."""
        feed_file = self.feeds_dir / f"{feed.feed_id}.json"
        with open(feed_file, "w") as f:
            json.dump({
                "feed_id": feed.feed_id,
                "name": feed.name,
                "url": feed.url,
                "auth_type": feed.auth_type,
                "auth_config": feed.auth_config,
                "schedule": feed.schedule,
                "filters": feed.filters,
                "last_sync": feed.last_sync.isoformat() if feed.last_sync else None,
                "last_sync_status": feed.last_sync_status,
                "rules_imported": feed.rules_imported,
                "enabled": feed.enabled,
            }, f, indent=2)
    
    def sync_feed(self, feed_id: str) -> dict:
        """Synchronize a single feed."""
        feed_file = self.feeds_dir / f"{feed_id}.json"
        if not feed_file.exists():
            return {"success": False, "error": "Feed not found"}
        
        with open(feed_file) as f:
            feed_data = json.load(f)
        
        feed = YaraFeed(**feed_data)
        result = {"success": False, "rules_imported": 0, "errors": []}
        
        try:
            # Download feed
            import requests
            headers = {}
            if feed.auth_type == "bearer" and feed.auth_config.get("token"):
                headers["Authorization"] = f"Bearer {feed.auth_config['token']}"
            elif feed.auth_type == "basic" and feed.auth_config.get("username") and feed.auth_config.get("password"):
                import base64
                creds = base64.b64encode(f"{feed.auth_config['username']}:{feed.auth_config['password']}".encode()).decode()
                headers["Authorization"] = f"Basic {creds}"
            elif feed.auth_type == "api_key" and feed.auth_config.get("key"):
                headers[feed.auth_config.get("header", "X-API-Key")] = feed.auth_config["key"]
            
            response = requests.get(feed.url, headers=headers, timeout=60)
            response.raise_for_status()
            
            # Parse rules from response (could be .yar files, zip, tar, or JSON)
            content = response.content
            rules_imported = 0
            
            # Try to detect format
            if feed.url.endswith(".zip") or content[:2] == b"PK":
                rules_imported = self._import_from_zip(content, feed_id, feed.filters)
            elif feed.url.endswith((".tar", ".tar.gz", ".tgz")):
                rules_imported = self._import_from_tar(content, feed_id, feed.filters)
            elif feed.url.endswith(".yar") or feed.url.endswith(".yara"):
                rules_imported = self._import_single_rule(content, feed_id, feed.filters)
            elif content[:1] in (b"{", b"["):
                rules_imported = self._import_from_json(content, feed_id, feed.filters)
            else:
                # Assume raw YARA rules
                rules_imported = self._import_raw_rules(content, feed_id, feed.filters)
            
            # Update feed status
            feed.last_sync = datetime.utcnow()
            feed.last_sync_status = "success"
            feed.rules_imported = rules_imported
            self.add_feed(feed)
            
            result["success"] = True
            result["rules_imported"] = rules_imported
            
        except Exception as exc:
            logger.exception(f"Feed sync failed for {feed_id}: {exc}")
            feed.last_sync = datetime.utcnow()
            feed.last_sync_status = f"error: {exc}"
            self.add_feed(feed)
            result["errors"].append(str(exc))
        
        return result
    
    def sync_all_feeds(self) -> dict:
        """Synchronize all enabled feeds."""
        results = {}
        for feed_file in self.feeds_dir.glob("*.json"):
            feed_id = feed_file.stem
            results[feed_id] = self.sync_feed(feed_id)
        return results
    
    def _import_from_zip(self, content: bytes, feed_id: str, filters: dict) -> int:
        """Import YARA rules from ZIP archive."""
        import zipfile
        imported = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "feed.zip"
            zip_path.write_bytes(content)
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(tmpdir)
                for extracted in Path(tmpdir).rglob("*.yar"):
                    imported += self._import_rule_file(extracted, feed_id, filters)
                for extracted in Path(tmpdir).rglob("*.yara"):
                    imported += self._import_rule_file(extracted, feed_id, filters)
        return imported
    
    def _import_from_tar(self, content: bytes, feed_id: str, filters: dict) -> int:
        """Import YARA rules from TAR archive."""
        import tarfile
        imported = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            tar_path = Path(tmpdir) / "feed.tar"
            tar_path.write_bytes(content)
            with tarfile.open(tar_path, "r:*") as tf:
                # Secure extraction: validate members before extracting
                for member in tf.getmembers():
                    if member.name.endswith((".yar", ".yara")):
                        # Validate path to prevent directory traversal
                        if not os.path.isabs(member.name) and ".." not in member.name:
                            tf.extract(member, tmpdir)
                for extracted in Path(tmpdir).rglob("*.yar"):
                    imported += self._import_rule_file(extracted, feed_id, filters)
                for extracted in Path(tmpdir).rglob("*.yara"):
                    imported += self._import_rule_file(extracted, feed_id, filters)
        return imported
    
    def _import_from_json(self, content: bytes, feed_id: str, filters: dict) -> int:
        """Import YARA rules from JSON (e.g., MalwareBazaar format)."""
        try:
            data = json.loads(content)
            imported = 0
            # Handle different JSON formats
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "rule" in item:
                        imported += self._import_rule_content(item["rule"], feed_id, filters)
            elif isinstance(data, dict):
                if "rules" in data:
                    for rule in data["rules"]:
                        imported += self._import_rule_content(rule, feed_id, filters)
                elif "rule" in data:
                    imported += self._import_rule_content(data["rule"], feed_id, filters)
            return imported
        except Exception as exc:
            logger.exception(f"JSON import failed: {exc}")
            return 0
    
    def _import_raw_rules(self, content: bytes, feed_id: str, filters: dict) -> int:
        """Import raw YARA rule text."""
        try:
            text = content.decode("utf-8", errors="ignore")
            # Split by rule boundaries
            rules = re.split(r'\n(?=rule\s+\w+\s*{)', text)
            imported = 0
            for rule_text in rules:
                if rule_text.strip().startswith("rule "):
                    imported += self._import_rule_content(rule_text, feed_id, filters)
            return imported
        except Exception as exc:
            logger.exception(f"Raw import failed: {exc}")
            return 0
    
    def _import_single_rule(self, content: bytes, feed_id: str, filters: dict) -> int:
        """Import a single .yar/.yara file."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".yar", delete=False) as f:
            f.write(content)
            tmp_path = Path(f.name)
        try:
            return self._import_rule_file(tmp_path, feed_id, filters)
        finally:
            tmp_path.unlink(missing_ok=True)
    
    def _import_rule_file(self, file_path: Path, feed_id: str, filters: dict) -> int:
        """Import rules from a .yar/.yara file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return self._import_rule_content(content, feed_id, filters, str(file_path))
        except Exception as exc:
            logger.exception(f"Rule file import failed for {file_path}: {exc}")
            return 0
    
    def _import_rule_content(self, content: str, feed_id: str, filters: dict, source_file: str | None = None) -> int:
        """Parse and import YARA rule content."""
        imported = 0
        
        # Parse individual rules from content
        # Simple regex-based parsing (for production, use yara-python's parser)
        rule_pattern = r'rule\s+(\w+)\s*(?::\s*[\w\s,]+)?\s*{'
        matches = list(re.finditer(rule_pattern, content))
        
        for i, match in enumerate(matches):
            rule_name = match.group(1)
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            rule_text = content[start:end]
            
            # Extract metadata
            meta = self._extract_rule_meta(rule_text)
            
            # Apply filters
            if not self._passes_filters(meta, filters):
                continue
            
            # Create rule object
            rule = YaraRule(
                rule_id=hashlib.sha256(f"{feed_id}:{rule_name}".encode()).hexdigest()[:16],
                name=rule_name,
                namespace=feed_id,
                source=feed_id,
                file_path=source_file or f"{feed_id}/{rule_name}.yar",
                content=rule_text,
                tags=meta.get("tags", []),
                meta=meta.get("meta", {}),
                severity=meta.get("meta", {}).get("severity", "medium"),
                mitre_techniques=meta.get("meta", {}).get("mitre_attack", []),
            )
            
            if self.add_rule(rule):
                imported += 1
        
        return imported
    
    def _extract_rule_meta(self, rule_text: str) -> dict:
        """Extract meta and tags from rule text."""
        meta = {"meta": {}, "tags": []}
        
        # Extract meta block
        meta_match = re.search(r'meta:\s*{([^}]+)}', rule_text, re.DOTALL)
        if meta_match:
            meta_text = meta_match.group(1)
            for line in meta_text.split('\n'):
                line = line.strip()
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"')
                    if key == "tags":
                        meta["tags"] = [t.strip() for t in value.split(',')]
                    else:
                        meta["meta"][key] = value
        
        # Extract tags from rule declaration
        tag_match = re.search(r'rule\s+\w+\s*:\s*([\w\s,]+)\s*{', rule_text)
        if tag_match:
            meta["tags"] = [t.strip() for t in tag_match.group(1).split(',')]
        
        return meta
    
    def _passes_filters(self, meta: dict, filters: dict) -> bool:
        """Check if rule passes feed filters."""
        if not filters:
            return True
        
        # Filter by severity
        if "severity" in filters:
            severity = meta.get("meta", {}).get("severity", "medium")
            if severity not in filters["severity"]:
                return False
        
        # Filter by tags
        if "tags" in filters:
            rule_tags = set(meta.get("tags", []))
            filter_tags = set(filters["tags"])
            if not rule_tags & filter_tags:
                return False
        
        # Filter by author
        if "author" in filters:
            author = meta.get("meta", {}).get("author", "")
            if author not in filters["author"]:
                return False
        
        return True
    
    # ──────────────────────────────────────────────────────────────────────────
    # Rule Management
    # ──────────────────────────────────────────────────────────────────────────
    
    def add_rule(self, rule: YaraRule) -> bool:
        """Add or update a YARA rule."""
        try:
            import sqlite3
            with sqlite3.connect(self.metadata_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO rules
                    (rule_id, name, namespace, source, file_path, content_hash,
                     tags, meta, severity, mitre_techniques, enabled, version,
                     created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    rule.rule_id, rule.name, rule.namespace, rule.source,
                    rule.file_path, rule.hash,
                    json.dumps(rule.tags), json.dumps(rule.meta),
                    rule.severity, json.dumps(rule.mitre_techniques),
                    int(rule.enabled), rule.version,
                    rule.created_at.isoformat(), rule.updated_at.isoformat()
                ))
            
            # Save rule content to file
            rule_file = self.rules_dir / rule.namespace / f"{rule.name}.yar"
            rule_file.parent.mkdir(parents=True, exist_ok=True)
            rule_file.write_text(rule.content)
            
            # Update cache
            self._rule_cache[rule.rule_id] = rule
            
            # Invalidate rulesets that might include this rule
            self._invalidate_rulesets_for_rule(rule.rule_id)
            
            return True
        except Exception as exc:
            logger.exception(f"Failed to add rule {rule.rule_id}: {exc}")
            return False
    
    def get_rule(self, rule_id: str) -> YaraRule | None:
        """Get a rule by ID."""
        if rule_id in self._rule_cache:
            return self._rule_cache[rule_id]
        
        import sqlite3
        with sqlite3.connect(self.metadata_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM rules WHERE rule_id = ?", (rule_id,))
            row = cursor.fetchone()
            if row:
                rule = YaraRule(
                    rule_id=row["rule_id"],
                    name=row["name"],
                    namespace=row["namespace"],
                    source=row["source"],
                    file_path=row["file_path"],
                    content=Path(row["file_path"]).read_text() if Path(row["file_path"]).exists() else "",
                    tags=json.loads(row["tags"]) if row["tags"] else [],
                    meta=json.loads(row["meta"]) if row["meta"] else {},
                    severity=row["severity"],
                    mitre_techniques=json.loads(row["mitre_techniques"]) if row["mitre_techniques"] else [],
                    enabled=bool(row["enabled"]),
                    version=row["version"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                    hash=row["content_hash"],
                )
                self._rule_cache[rule_id] = rule
                return rule
        return None
    
    def list_rules(self, namespace: str | None = None, enabled_only: bool = True, limit: int = 1000) -> list[YaraRule]:
        """List rules with optional filtering."""
        import sqlite3
        query = "SELECT rule_id FROM rules WHERE 1=1"
        params = []
        if namespace:
            query += " AND namespace = ?"
            params.append(namespace)
        if enabled_only:
            query += " AND enabled = 1"
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        
        with sqlite3.connect(self.metadata_db) as conn:
            cursor = conn.execute(query, params)
            rules = []
            for row in cursor:
                rule = self.get_rule(row[0])
                if rule:
                    rules.append(rule)
            return rules
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule."""
        try:
            rule = self.get_rule(rule_id)
            if not rule:
                return False
            
            import sqlite3
            with sqlite3.connect(self.metadata_db) as conn:
                conn.execute("DELETE FROM rules WHERE rule_id = ?", (rule_id,))
            
            # Delete rule file
            rule_file = self.rules_dir / rule.namespace / f"{rule.name}.yar"
            rule_file.unlink(missing_ok=True)
            
            # Remove from cache
            self._rule_cache.pop(rule_id, None)
            
            # Invalidate rulesets
            self._invalidate_rulesets_for_rule(rule_id)
            
            return True
        except Exception as exc:
            logger.exception(f"Failed to delete rule {rule_id}: {exc}")
            return False
    
    def _invalidate_rulesets_for_rule(self, rule_id: str):
        """Mark rulesets containing this rule as needing recompilation."""
        import sqlite3
        with sqlite3.connect(self.metadata_db) as conn:
            conn.execute("""
                UPDATE rulesets 
                SET version = version + 1, updated_at = ?
                WHERE rule_ids LIKE ?
            """, (datetime.utcnow().isoformat(), f"%{rule_id}%"))
    
    # ──────────────────────────────────────────────────────────────────────────
    # Ruleset Management
    # ──────────────────────────────────────────────────────────────────────────
    
    def create_ruleset(self, ruleset: YaraRuleset) -> bool:
        """Create a new ruleset."""
        try:
            import sqlite3
            with sqlite3.connect(self.metadata_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO rulesets
                    (ruleset_id, name, description, rule_ids, compiled_path,
                     compiled_at, compilation_time_ms, rule_count, enabled_rule_count,
                     performance_stats, version, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ruleset.ruleset_id, ruleset.name, ruleset.description,
                    json.dumps([r.rule_id for r in ruleset.rules]),
                    ruleset.compiled_path,
                    ruleset.compiled_at.isoformat() if ruleset.compiled_at else None,
                    ruleset.compilation_time_ms,
                    ruleset.rule_count,
                    ruleset.enabled_rule_count,
                    json.dumps(ruleset.performance_stats),
                    ruleset.version,
                    ruleset.created_at.isoformat(),
                    ruleset.updated_at.isoformat(),
                ))
            self._ruleset_cache[ruleset.ruleset_id] = ruleset
            return True
        except Exception as exc:
            logger.exception(f"Failed to create ruleset {ruleset.ruleset_id}: {exc}")
            return False
    
    def compile_ruleset(self, ruleset_id: str, force: bool = False) -> dict:
        """Compile a ruleset to binary format."""
        with self._compile_lock:
            ruleset = self.get_ruleset(ruleset_id)
            if not ruleset:
                return {"success": False, "error": "Ruleset not found"}
            
            # Check if recompilation needed
            if not force and ruleset.compiled_path and Path(ruleset.compiled_path).exists():
                # Check if any source rules are newer
                needs_recompile = False
                for rule_id in json.loads(ruleset.rule_ids) if isinstance(ruleset.rule_ids, str) else ruleset.rule_ids:
                    rule = self.get_rule(rule_id)
                    if rule and rule.updated_at > (ruleset.compiled_at or datetime.min):
                        needs_recompile = True
                        break
                if not needs_recompile:
                    return {"success": True, "compiled_path": ruleset.compiled_path, "cached": True}
            
            start_time = time.time()
            
            try:
                # Collect all rule contents
                rule_contents = []
                enabled_count = 0
                for rule_id in json.loads(ruleset.rule_ids) if isinstance(ruleset.rule_ids, str) else ruleset.rule_ids:
                    rule = self.get_rule(rule_id)
                    if rule and rule.enabled:
                        rule_contents.append(rule.content)
                        enabled_count += 1
                
                if not rule_contents:
                    return {"success": False, "error": "No enabled rules in ruleset"}
                
                # Write combined rules to temp file
                with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
                    f.write("\n\n".join(rule_contents))
                    temp_rule_file = Path(f.name)
                
                try:
                    # Compile with yara
                    compiled_path = self.compiled_dir / f"{ruleset_id}.yarac"
                    result = subprocess.run(
                        ["yara", "-c", str(temp_rule_file), str(compiled_path)],
                        capture_output=True, text=True, timeout=300
                    )
                    
                    if result.returncode != 0:
                        return {"success": False, "error": f"Compilation failed: {result.stderr}"}
                    
                    compilation_time = (time.time() - start_time) * 1000
                    
                    # Update ruleset
                    ruleset.compiled_path = str(compiled_path)
                    ruleset.compiled_at = datetime.utcnow()
                    ruleset.compilation_time_ms = compilation_time
                    ruleset.enabled_rule_count = enabled_count
                    ruleset.version += 1
                    ruleset.updated_at = datetime.utcnow()
                    
                    # Performance stats
                    ruleset.performance_stats = {
                        "last_compilation_ms": compilation_time,
                        "rule_count": len(rule_contents),
                        "enabled_count": enabled_count,
                        "compiled_size_bytes": compiled_path.stat().st_size,
                    }
                    
                    self.create_ruleset(ruleset)
                    
                    return {
                        "success": True,
                        "compiled_path": str(compiled_path),
                        "compilation_time_ms": compilation_time,
                        "enabled_rules": enabled_count,
                    }
                    
                finally:
                    temp_rule_file.unlink(missing_ok=True)
                    
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Compilation timeout"}
            except Exception as exc:
                logger.exception(f"Ruleset compilation failed: {exc}")
                return {"success": False, "error": str(exc)}
    
    def get_ruleset(self, ruleset_id: str) -> YaraRuleset | None:
        """Get a ruleset by ID."""
        if ruleset_id in self._ruleset_cache:
            return self._ruleset_cache[ruleset_id]
        
        import sqlite3
        with sqlite3.connect(self.metadata_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM rulesets WHERE ruleset_id = ?", (ruleset_id,))
            row = cursor.fetchone()
            if row:
                rule_ids = json.loads(row["rule_ids"]) if row["rule_ids"] else []
                rules = [self.get_rule(rid) for rid in rule_ids]
                rules = [r for r in rules if r]
                
                ruleset = YaraRuleset(
                    ruleset_id=row["ruleset_id"],
                    name=row["name"],
                    description=row["description"],
                    rules=rules,
                    compiled_path=row["compiled_path"],
                    compiled_at=datetime.fromisoformat(row["compiled_at"]) if row["compiled_at"] else None,
                    compilation_time_ms=row["compilation_time_ms"],
                    rule_count=row["rule_count"],
                    enabled_rule_count=row["enabled_rule_count"],
                    performance_stats=json.loads(row["performance_stats"]) if row["performance_stats"] else {},
                    version=row["version"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    updated_at=datetime.fromisoformat(row["updated_at"]),
                )
                self._ruleset_cache[ruleset_id] = ruleset
                return ruleset
        return None
    
    def list_rulesets(self) -> list[YaraRuleset]:
        """List all rulesets."""
        import sqlite3
        with sqlite3.connect(self.metadata_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT ruleset_id FROM rulesets ORDER BY updated_at DESC")
            return [self.get_ruleset(row[0]) for row in cursor if self.get_ruleset(row[0])]
    
    # ──────────────────────────────────────────────────────────────────────────
    # Scanning
    # ──────────────────────────────────────────────────────────────────────────
    
    def scan_file(self, file_path: Path, ruleset_id: str | None = None, timeout: int = 60) -> dict:
        """Scan a file with YARA rules."""
        if ruleset_id:
            ruleset = self.get_ruleset(ruleset_id)
            if not ruleset or not ruleset.compiled_path:
                # Try to compile
                compile_result = self.compile_ruleset(ruleset_id)
                if not compile_result["success"]:
                    return {"error": "Ruleset not compiled", "details": compile_result}
                ruleset = self.get_ruleset(ruleset_id)
            compiled_path = ruleset.compiled_path
        else:
            # Use default ruleset (first available)
            rulesets = self.list_rulesets()
            if not rulesets:
                return {"error": "No rulesets available"}
            ruleset = rulesets[0]
            if not ruleset.compiled_path:
                self.compile_ruleset(ruleset.ruleset_id)
                ruleset = self.get_ruleset(ruleset.ruleset_id)
            compiled_path = ruleset.compiled_path
        
        start_time = time.time()
        matches = []
        
        try:
            result = subprocess.run(
                ["yara", "-C", compiled_path, str(file_path)],
                capture_output=True, text=True, timeout=timeout
            )
            
            scan_time = (time.time() - start_time) * 1000
            
            if result.returncode in (0, 1):  # 0 = matches, 1 = no matches
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split(' ', 2)
                        if len(parts) >= 2:
                            rule_name = parts[0]
                            namespace = parts[1] if len(parts) > 1 else ""
                            tags = parts[2] if len(parts) > 2 else ""
                            matches.append({
                                "rule": rule_name,
                                "namespace": namespace,
                                "tags": tags.split() if tags else [],
                            })
            
            # Update performance stats
            self._record_scan_performance(ruleset_id or "default", scan_time, len(matches))
            
            return {
                "matches": matches,
                "match_count": len(matches),
                "scan_time_ms": scan_time,
                "ruleset": ruleset_id or "default",
            }
            
        except subprocess.TimeoutExpired:
            return {"error": "Scan timeout", "scan_time_ms": timeout * 1000}
        except Exception as exc:
            logger.exception(f"YARA scan failed: {exc}")
            return {"error": str(exc)}
    
    def scan_bytes(self, data: bytes, ruleset_id: str | None = None, timeout: int = 60) -> dict:
        """Scan raw bytes with YARA rules."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            tmp_path = Path(f.name)
        try:
            return self.scan_file(tmp_path, ruleset_id, timeout)
        finally:
            tmp_path.unlink(missing_ok=True)
    
    def _record_scan_performance(self, ruleset_id: str, scan_time_ms: float, match_count: int):
        """Record scan performance metrics."""
        import sqlite3
        with sqlite3.connect(self.performance_db) as conn:
            conn.execute("""
                INSERT INTO ruleset_performance (ruleset_id, total_scans, total_time_ms, avg_time_ms, rule_count, last_scan_at, updated_at)
                VALUES (?, 1, ?, ?, 0, ?, ?)
                ON CONFLICT(ruleset_id) DO UPDATE SET
                    total_scans = total_scans + 1,
                    total_time_ms = total_time_ms + ?,
                    avg_time_ms = total_time_ms / total_scans,
                    last_scan_at = ?,
                    updated_at = ?
            """, (ruleset_id, scan_time_ms, scan_time_ms, datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
                  scan_time_ms, datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
    
    # ──────────────────────────────────────────────────────────────────────────
    # Testing & Validation
    # ──────────────────────────────────────────────────────────────────────────
    
    def add_test_case(self, rule_id: str, sample_path: Path, expected_match: bool) -> bool:
        """Add a test case for a rule (positive or negative)."""
        try:
            import sqlite3
            test_id = hashlib.sha256(f"{rule_id}:{sample_path}:{expected_match}".encode()).hexdigest()[:16]
            with sqlite3.connect(self.metadata_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO test_cases
                    (test_id, rule_id, sample_path, expected_match, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (test_id, rule_id, str(sample_path), int(expected_match), datetime.utcnow().isoformat()))
            
            # Copy sample to test_cases dir
            test_dir = self.test_cases_dir / rule_id / ("positive" if expected_match else "negative")
            test_dir.mkdir(parents=True, exist_ok=True)
            dest = test_dir / sample_path.name
            shutil.copy2(sample_path, dest)
            
            return True
        except Exception as exc:
            logger.exception(f"Failed to add test case: {exc}")
            return False
    
    def run_rule_tests(self, rule_id: str) -> dict:
        """Run all test cases for a rule."""
        import sqlite3
        with sqlite3.connect(self.metadata_db) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM test_cases WHERE rule_id = ?", (rule_id,))
            test_cases = cursor.fetchall()
        
        if not test_cases:
            return {"success": True, "message": "No test cases", "passed": 0, "failed": 0}
        
        # Create temporary ruleset with just this rule
        rule = self.get_rule(rule_id)
        if not rule:
            return {"success": False, "error": "Rule not found"}
        
        temp_ruleset_id = f"test_{rule_id}"
        temp_ruleset = YaraRuleset(
            ruleset_id=temp_ruleset_id,
            name=f"Test ruleset for {rule.name}",
            description="Auto-generated test ruleset",
            rules=[rule],
        )
        self.create_ruleset(temp_ruleset)
        self.compile_ruleset(temp_ruleset_id)
        
        passed = 0
        failed = 0
        results = []
        
        for tc in test_cases:
            sample_path = Path(tc["sample_path"])
            if not sample_path.exists():
                # Try test_cases dir
                test_dir = self.test_cases_dir / rule_id / ("positive" if tc["expected_match"] else "negative")
                sample_path = test_dir / sample_path.name
            
            if not sample_path.exists():
                results.append({
                    "test_id": tc["test_id"],
                    "sample": str(sample_path),
                    "expected": bool(tc["expected_match"]),
                    "actual": None,
                    "passed": False,
                    "error": "Sample not found",
                })
                failed += 1
                continue
            
            scan_result = self.scan_file(sample_path, temp_ruleset_id)
            actual_match = scan_result.get("match_count", 0) > 0
            expected = bool(tc["expected_match"])
            
            test_passed = actual_match == expected
            if test_passed:
                passed += 1
            else:
                failed += 1
            
            results.append({
                "test_id": tc["test_id"],
                "sample": str(sample_path),
                "expected": expected,
                "actual": actual_match,
                "passed": test_passed,
                "scan_time_ms": scan_result.get("scan_time_ms", 0),
            })
        
        return {
            "success": True,
            "rule_id": rule_id,
            "passed": passed,
            "failed": failed,
            "total": len(test_cases),
            "results": results,
        }
    
    def validate_rule_syntax(self, rule_content: str) -> dict:
        """Validate YARA rule syntax without importing."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
            f.write(rule_content)
            tmp_path = Path(f.name)
        
        try:
            result = subprocess.run(
                ["yara", "-c", str(tmp_path), "/dev/null"],
                capture_output=True, text=True, timeout=30
            )
            # yara -c returns 0 on success, non-zero on syntax error
            return {
                "valid": result.returncode == 0,
                "errors": result.stderr if result.returncode != 0 else None,
            }
        except Exception as exc:
            return {"valid": False, "errors": str(exc)}
        finally:
            tmp_path.unlink(missing_ok=True)
    
    # ──────────────────────────────────────────────────────────────────────────
    # Performance & Optimization
    # ──────────────────────────────────────────────────────────────────────────
    
    def get_performance_stats(self, ruleset_id: str | None = None) -> dict:
        """Get performance statistics."""
        import sqlite3
        with sqlite3.connect(self.performance_db) as conn:
            conn.row_factory = sqlite3.Row
            
            if ruleset_id:
                cursor = conn.execute("SELECT * FROM ruleset_performance WHERE ruleset_id = ?", (ruleset_id,))
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return {}
            else:
                cursor = conn.execute("SELECT * FROM ruleset_performance ORDER BY avg_time_ms DESC")
                return [dict(row) for row in cursor]
    
    def get_slow_rules(self, ruleset_id: str | None = None, threshold_ms: float = 100) -> list[dict]:
        """Get rules that exceed performance threshold."""
        import sqlite3
        with sqlite3.connect(self.performance_db) as conn:
            conn.row_factory = sqlite3.Row
            if ruleset_id:
                # Would need per-rule performance tracking
                cursor = conn.execute("""
                    SELECT r.rule_id, r.name, r.namespace, rp.avg_time_ms, rp.max_time_ms, rp.total_scans
                    FROM rules r
                    JOIN rule_performance rp ON r.rule_id = rp.rule_id
                    WHERE rp.avg_time_ms > ?
                    ORDER BY rp.avg_time_ms DESC
                """, (threshold_ms,))
            else:
                cursor = conn.execute("""
                    SELECT r.rule_id, r.name, r.namespace, rp.avg_time_ms, rp.max_time_ms, rp.total_scans
                    FROM rules r
                    JOIN rule_performance rp ON r.rule_id = rp.rule_id
                    WHERE rp.avg_time_ms > ?
                    ORDER BY rp.avg_time_ms DESC
                """, (threshold_ms,))
            return [dict(row) for row in cursor]
    
    def optimize_ruleset(self, ruleset_id: str) -> dict:
        """Optimize a ruleset by disabling slow rules."""
        slow_rules = self.get_slow_rules(ruleset_id, threshold_ms=500)
        disabled = 0
        for rule_info in slow_rules:
            rule = self.get_rule(rule_info["rule_id"])
            if rule and rule.enabled:
                rule.enabled = False
                self.add_rule(rule)
                disabled += 1
        
        if disabled > 0:
            self.compile_ruleset(ruleset_id, force=True)
        
        return {"disabled_rules": disabled, "slow_rules": slow_rules}


# ──────────────────────────────────────────────────────────────────────────────
# Default Feeds Configuration
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_FEEDS = [
    YaraFeed(
        feed_id="yara-rules",
        name="YARA-Rules Project",
        url="https://github.com/YARA-Rules/rules/archive/refs/heads/master.zip",
        schedule="daily",
        filters={"tags": ["malware", "apt", "rat", "ransomware", "banker"]},
    ),
    YaraFeed(
        feed_id="malwarebazaar",
        name="MalwareBazaar YARA Rules",
        url="https://bazaar.abuse.ch/export/yara/",
        schedule="daily",
        auth_type="none",
    ),
    YaraFeed(
        feed_id="elastic",
        name="Elastic Security Rules",
        url="https://github.com/elastic/detection-rules/archive/refs/heads/main.zip",
        schedule="weekly",
        filters={"tags": ["malware", "threat"]},
    ),
]


def initialize_default_feeds(manager: YaraManager):
    """Initialize default YARA feeds."""
    for feed in DEFAULT_FEEDS:
        if not (manager.feeds_dir / f"{feed.feed_id}.json").exists():
            manager.add_feed(feed)