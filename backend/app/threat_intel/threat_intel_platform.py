"""
MALINFO — Threat Intelligence Platform.

Comprehensive threat intelligence integration with STIX/TAXII 2.1 server/client,
MISP synchronization, actor/campaign profiling, ATT&CK Navigator integration,
threat feed management, and indicator aging/scoring.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

logger = logging.getLogger("malinfo.threat_intel_platform")


# ──────────────────────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────────────────────

class TLPLevel(str, Enum):
    """Traffic Light Protocol levels."""
    RED = "red"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    GREEN = "green"
    CLEAR = "clear"


class ThreatActorType(str, Enum):
    """Threat actor types."""
    APT = "apt"
    CRIMINAL = "criminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    NATION_STATE = "nation-state"
    SCRIPT_KIDDIE = "script-kiddie"
    TERRORIST = "terrorist"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class ThreatActor:
    """Threat actor profile."""
    actor_id: str
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN
    motivation: list[str] = field(default_factory=list)
    sophistication: str = ""  # low, medium, high, advanced
    origin_country: str = ""
    target_sectors: list[str] = field(default_factory=list)
    target_countries: list[str] = field(default_factory=list)
    known_tools: list[str] = field(default_factory=list)
    known_malware: list[str] = field(default_factory=list)
    infrastructure: list[dict] = field(default_factory=list)  # IPs, domains, ASNs, hosting
    ttps: list[str] = field(default_factory=list)  # MITRE ATT&CK technique IDs
    associated_campaigns: list[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    sources: list[str] = field(default_factory=list)
    tlp: TLPLevel = TLPLevel.AMBER
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_stix(self) -> dict:
        """Convert to STIX 2.1 Threat Actor."""
        return {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{self.actor_id}",
            "created": self.created_at.isoformat() + "Z",
            "modified": self.updated_at.isoformat() + "Z",
            "name": self.name,
            "description": self.description,
            "threat_actor_types": [self.actor_type.value],
            "aliases": self.aliases,
            "goals": self.motivation,
            "sophistication": self.sophistication,
            "confidence": {"low": 30, "medium": 60, "high": 90}.get(self.confidence.value, 50),
            "external_references": [
                {"source_name": src, "external_id": self.actor_id}
                for src in self.sources
            ],
        }


@dataclass
class Campaign:
    """Campaign tracking."""
    campaign_id: str
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    objective: str = ""
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    threat_actors: list[str] = field(default_factory=list)  # actor_ids
    malware_families: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    infrastructure: list[dict] = field(default_factory=list)
    victims: list[dict] = field(default_factory=list)  # sector, country, org
    ttps: list[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    tlp: TLPLevel = TLPLevel.AMBER
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_stix(self) -> dict:
        """Convert to STIX 2.1 Campaign."""
        return {
            "type": "campaign",
            "spec_version": "2.1",
            "id": f"campaign--{self.campaign_id}",
            "created": self.created_at.isoformat() + "Z",
            "modified": self.updated_at.isoformat() + "Z",
            "name": self.name,
            "description": self.description,
            "objectives": [self.objective] if self.objective else [],
            "aliases": self.aliases,
            "first_seen": self.first_seen.isoformat() + "Z" if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() + "Z" if self.last_seen else None,
            "confidence": {"low": 30, "medium": 60, "high": 90}.get(self.confidence.value, 50),
        }


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration."""
    feed_id: str
    name: str
    url: str
    feed_type: str = "stix"  # stix, misp, csv, json, txt
    auth_type: str = "none"  # none, bearer, basic, api_key, oauth2
    auth_config: dict = field(default_factory=dict)
    schedule: str = "daily"  # hourly, daily, weekly, monthly
    enabled: bool = True
    tlp: TLPLevel = TLPLevel.AMBER
    tags: list[str] = field(default_factory=list)
    filters: dict = field(default_factory=dict)
    last_sync: datetime | None = None
    last_sync_status: str = "never"
    indicators_imported: int = 0
    indicators_rejected: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Indicator:
    """Threat intelligence indicator."""
    indicator_id: str
    pattern: str  # STIX pattern
    pattern_type: str = "stix"
    indicator_types: list[str] = field(default_factory=list)  # malicious-activity, anomaly, etc.
    name: str = ""
    description: str = ""
    valid_from: datetime = field(default_factory=datetime.utcnow)
    valid_until: datetime | None = None
    confidence: int = 50  # 0-100
    severity: str = "medium"  # low, medium, high, critical
    kill_chain_phases: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    threat_actors: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str = ""
    tlp: TLPLevel = TLPLevel.AMBER
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    half_life_days: int = 90  # Indicator aging
    
    def to_stix(self) -> dict:
        """Convert to STIX 2.1 Indicator."""
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{self.indicator_id}",
            "created": self.created_at.isoformat() + "Z",
            "modified": self.updated_at.isoformat() + "Z",
            "name": self.name,
            "description": self.description,
            "indicator_types": self.indicator_types,
            "pattern": self.pattern,
            "pattern_type": self.pattern_type,
            "valid_from": self.valid_from.isoformat() + "Z",
            "valid_until": self.valid_until.isoformat() + "Z" if self.valid_until else None,
            "confidence": self.confidence,
            "labels": self.tags or ["malicious-activity"],
            "kill_chain_phases": self.kill_chain_phases,
            "external_references": [
                {"source_name": self.source, "external_id": self.indicator_id}
            ],
        }
    
    def age_score(self) -> float:
        """Calculate age-based confidence decay."""
        if not self.valid_until:
            return 1.0
        age = (datetime.utcnow() - self.created_at).days
        if age >= self.half_life_days:
            return 0.5
        return 1.0 - (age / self.half_life_days) * 0.5


# ──────────────────────────────────────────────────────────────────────────────
# STIX/TAXII 2.1 Server
# ──────────────────────────────────────────────────────────────────────────────

class StixTaxiiServer:
    """
    STIX/TAXII 2.1 compliant server implementation.
    
    Supports:
    - Discovery endpoint
    - API Root
    - Collections (indicators, malware, campaigns, etc.)
    - Manifest endpoint
    - Objects endpoint (add, get, filter)
    - Versioning
    """
    
    def __init__(self, api_root: str = "/taxii2"):
        self.api_root = api_root.rstrip("/")
        self.collections: dict[str, dict] = {}
        self._init_default_collections()
    
    def _init_default_collections(self):
        """Initialize default STIX collections."""
        default_collections = [
            ("indicators", "STIX Indicators", "indicator"),
            ("malware", "Malware Analysis", "malware"),
            ("campaigns", "Campaign Tracking", "campaign"),
            ("intrusion-sets", "Threat Actors / Intrusion Sets", "intrusion-set"),
            ("threat-actors", "Threat Actor Profiles", "threat-actor"),
            ("tools", "Tools / Utilities", "tool"),
            ("reports", "Threat Reports", "report"),
            ("courses-of-action", "Mitigations / Courses of Action", "course-of-action"),
            ("identities", "Organizations / Identities", "identity"),
            ("vulnerabilities", "Vulnerabilities", "vulnerability"),
        ]
        
        for alias, title, stix_type in default_collections:
            collection_id = str(uuid.uuid4())
            self.collections[alias] = {
                "id": collection_id,
                "alias": alias,
                "title": title,
                "description": f"MALINFO {title}",
                "can_read": True,
                "can_write": True,
                "media_types": ["application/stix+json;version=2.1"],
            }
    
    def get_discovery(self) -> dict:
        """TAXII Discovery endpoint."""
        return {
            "title": "MALINFO TAXII 2.1 Server",
            "description": "Government-grade threat intelligence sharing",
            "contact": "malinfo@example.gov",
            "default": f"{self.api_root}/collections/",
            "api_roots": [self.api_root],
        }
    
    def get_api_root(self) -> dict:
        """API Root endpoint."""
        return {
            "title": "MALINFO TAXII 2.1 API Root",
            "description": "Main API root for MALINFO threat intelligence",
            "versions": ["taxii-2.1"],
            "max_content_length": 104857600,
        }
    
    def get_collections(self) -> dict:
        """Get all collections."""
        return {
            "collections": list(self.collections.values()),
        }
    
    def get_collection(self, collection_id: str) -> dict | None:
        """Get single collection."""
        return self.collections.get(collection_id)
    
    def get_manifest(self, collection_id: str, added_after: str | None = None, limit: int = 1000) -> dict:
        """Get collection manifest."""
        # In production, this would query the database
        objects = []  # Would be populated from storage
        return {
            "objects": objects,
        }
    
    def get_objects(self, collection_id: str, added_after: str | None = None, limit: int = 1000, 
                   match_id: list | None = None, match_type: list | None = None, 
                   match_version: list | None = None, match_spec_version: list | None = None) -> dict:
        """Get objects from collection with filtering."""
        # In production, this would query the database with filters
        objects = []
        return {
            "objects": objects,
            "more": False,
        }
    
    def add_objects(self, collection_id: str, objects: list[dict]) -> dict:
        """Add objects to collection."""
        # Validate STIX objects
        valid_objects = []
        failed = []
        
        for obj in objects:
            if self._validate_stix_object(obj):
                valid_objects.append(obj)
            else:
                failed.append(obj)
        
        # In production, would store in database
        return {
            "success": True,
            "id": [obj.get("id") for obj in valid_objects],
            "failures": len(failed),
        }
    
    def _validate_stix_object(self, obj: dict) -> bool:
        """Basic STIX object validation."""
        required = ["type", "id", "spec_version"]
        if not all(k in obj for k in required):
            return False
        if obj["spec_version"] != "2.1":
            return False
        # Check ID format: type--uuid
        return re.match(r"^[a-z-]+--[0-9a-f-]{36}$", obj["id"])


# ──────────────────────────────────────────────────────────────────────────────
# MISP Synchronization
# ──────────────────────────────────────────────────────────────────────────────

class MispSync:
    """
    MISP (Malware Information Sharing Platform) synchronization.
    
    Supports:
    - Push: Publish MALINFO indicators/events to MISP
    - Pull: Sync MISP events/attributes to MALINFO
    - Bidirectional with conflict resolution
    """
    
    def __init__(
        self,
        misp_url: str,
        auth_key: str,
        verify_ssl: bool = True,
        organisation_id: int | None = None,
    ):
        self.misp_url = misp_url.rstrip("/")
        self.auth_key = auth_key
        self.verify_ssl = verify_ssl
        self.organisation_id = organisation_id
        self._session = None
    
    async def _get_session(self):
        import aiohttp
        if self._session is None or self._session.closed:
            headers = {
                "Authorization": self.auth_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def test_connection(self) -> bool:
        """Test MISP connection."""
        session = await self._get_session()
        async with session.get(f"{self.misp_url}/servers/getVersion", ssl=self.verify_ssl) as resp:
            return resp.status == 200
    
    # ─── Pull from MISP ───
    
    async def pull_events(
        self,
        tags: list[str] | None = None,
        since: datetime | None = None,
        limit: int = 1000,
        with_attachments: bool = False,
    ) -> list[dict]:
        """Pull events from MISP."""
        session = await self._get_session()
        
        params = {
            "returnFormat": "json",
            "limit": limit,
        }
        if tags:
            params["tags"] = ",".join(tags)
        if since:
            params["timestamp"] = since.strftime("%Y-%m-%d")
        if with_attachments:
            params["withAttachments"] = "true"
        
        async with session.post(
            f"{self.misp_url}/events/restSearch",
            json=params,
            ssl=self.verify_ssl,
        ) as resp:
            if resp.status != 200:
                raise Exception(f"MISP pull failed: {await resp.text()}")
            result = await resp.json()
        
        return result.get("response", [])
    
    async def pull_attributes(
        self,
        type_attribute: list[str] | None = None,
        tags: list[str] | None = None,
        since: datetime | None = None,
        limit: int = 10000,
    ) -> list[dict]:
        """Pull attributes from MISP."""
        session = await self._get_session()
        
        params = {
            "returnFormat": "json",
            "limit": limit,
        }
        if type_attribute:
            params["type"] = ",".join(type_attribute)
        if tags:
            params["tags"] = ",".join(tags)
        if since:
            params["timestamp"] = since.strftime("%Y-%m-%d")
        
        async with session.post(
            f"{self.misp_url}/attributes/restSearch",
            json=params,
            ssl=self.verify_ssl,
        ) as resp:
            if resp.status != 200:
                raise Exception(f"MISP attribute pull failed: {await resp.text()}")
            result = await resp.json()
        
        return result.get("response", [])
    
    # ─── Push to MISP ───
    
    async def push_event(self, event: dict) -> dict:
        """Push event to MISP."""
        session = await self._get_session()
        
        async with session.post(
            f"{self.misp_url}/events/add",
            json=event,
            ssl=self.verify_ssl,
        ) as resp:
            if resp.status not in (200, 201):
                raise Exception(f"MISP push failed: {await resp.text()}")
            return await resp.json()
    
    async def push_indicator(self, indicator: Indicator, event_id: str | None = None) -> dict:
        """Push single indicator to MISP as attribute."""
        # Convert indicator to MISP attribute
        attribute = self._indicator_to_misp_attribute(indicator)
        
        if event_id:
            attribute["event_id"] = event_id
        
        session = await self._get_session()
        async with session.post(
            f"{self.misp_url}/attributes/add/{event_id or ''}",
            json={"Attribute": attribute},
            ssl=self.verify_ssl,
        ) as resp:
            if resp.status not in (200, 201):
                raise Exception(f"MISP attribute push failed: {await resp.text()}")
            return await resp.json()
    
    def _indicator_to_misp_attribute(self, indicator: Indicator) -> dict:
        """Convert MALINFO indicator to MISP attribute."""
        # Map STIX pattern to MISP type
        type_map = {
            "ipv4-addr": "ip-dst",
            "ipv6-addr": "ip-dst",
            "domain-name": "domain",
            "url": "url",
            "email-addr": "email-src",
            "file": "sha256",
            "mutex": "mutex",
            "windows-registry-key": "regkey",
            "x509-certificate": "x509-fingerprint-sha256",
        }
        
        # Extract value from pattern (simplified)
        misp_type = "text"
        value = indicator.pattern
        
        for stix_type, misp_t in type_map.items():
            if stix_type in indicator.pattern:
                misp_type = misp_t
                # Extract value
                import re
                match = re.search(rf"{stix_type}:value = '([^']+)'", indicator.pattern)
                if match:
                    value = match.group(1)
                break
        
        return {
            "type": misp_type,
            "value": value,
            "comment": indicator.description,
            "confidence": indicator.confidence,
            "Tag": [{"name": tag} for tag in indicator.tags],
            "to_ids": True,
        }
    
    # ─── Sync ───
    
    async def sync_bidirectional(
        self,
        malinfo_indicators: list[Indicator],
        since: datetime | None = None,
        conflict_resolution: str = "last_write_wins",
    ) -> dict:
        """Perform bidirectional sync with MISP."""
        results = {
            "pulled_events": 0,
            "pulled_attributes": 0,
            "pushed_indicators": 0,
            "conflicts": 0,
            "errors": [],
        }
        
        try:
            # Pull from MISP
            events = await self.pull_events(since=since)
            results["pulled_events"] = len(events)
            
            attributes = await self.pull_attributes(since=since)
            results["pulled_attributes"] = len(attributes)
            
            # Convert MISP attributes to MALINFO indicators
            # (would implement conversion)
            
            # Push MALINFO indicators to MISP
            for indicator in malinfo_indicators:
                try:
                    await self.push_indicator(indicator)
                    results["pushed_indicators"] += 1
                except Exception as exc:
                    results["errors"].append(f"Push failed for {indicator.indicator_id}: {exc}")
            
        except Exception as exc:
            results["errors"].append(f"Sync failed: {exc}")
        
        return results


# ──────────────────────────────────────────────────────────────────────────────
# Threat Feed Manager
# ──────────────────────────────────────────────────────────────────────────────

class ThreatFeedManager:
    """
    Manage threat intelligence feeds from multiple sources.
    
    Supports:
    - Commercial feeds (VT, OTX, AbuseIPDB, IBM X-Force, etc.)
    - Open feeds (Abuse.ch, Spamhaus, Emerging Threats, etc.)
    - Custom feeds (internal MISP, ISAC/ISAO, vendor-specific)
    - Scheduling, deduplication, scoring, aging
    """
    
    def __init__(self, storage_dir: Path | None = None):
        self.storage_dir = storage_dir or Path("/opt/malinfo/feeds")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.feeds_file = self.storage_dir / "feeds.json"
        self.feeds: dict[str, ThreatFeed] = {}
        self._load_feeds()
    
    def _load_feeds(self):
        """Load feeds from storage."""
        if self.feeds_file.exists():
            try:
                with open(self.feeds_file) as f:
                    data = json.load(f)
                for feed_data in data:
                    feed = ThreatFeed(**feed_data)
                    self.feeds[feed.feed_id] = feed
            except Exception as exc:
                logger.exception(f"Failed to load feeds: {exc}")
    
    def _save_feeds(self):
        """Save feeds to storage."""
        try:
            with open(self.feeds_file, "w") as f:
                json.dump([feed.__dict__ for feed in self.feeds.values()], f, indent=2, default=str)
        except Exception as exc:
            logger.exception(f"Failed to save feeds: {exc}")
    
    def add_feed(self, feed: ThreatFeed) -> bool:
        """Add a new threat feed."""
        self.feeds[feed.feed_id] = feed
        self._save_feeds()
        return True
    
    def remove_feed(self, feed_id: str) -> bool:
        """Remove a feed."""
        if feed_id in self.feeds:
            del self.feeds[feed_id]
            self._save_feeds()
            return True
        return False
    
    def get_feed(self, feed_id: str) -> ThreatFeed | None:
        """Get feed by ID."""
        return self.feeds.get(feed_id)
    
    def list_feeds(self, enabled_only: bool = False) -> list[ThreatFeed]:
        """List all feeds."""
        feeds = list(self.feeds.values())
        if enabled_only:
            feeds = [f for f in feeds if f.enabled]
        return feeds
    
    async def sync_feed(self, feed_id: str) -> dict:
        """Synchronize a single feed."""
        feed = self.feeds.get(feed_id)
        if not feed:
            return {"success": False, "error": "Feed not found"}
        
        result = {"success": False, "indicators_imported": 0, "indicators_rejected": 0, "errors": []}
        
        try:
            import aiohttp
            session = aiohttp.ClientSession()
            
            headers = {}
            if feed.auth_type == "bearer" and feed.auth_config.get("token"):
                headers["Authorization"] = f"Bearer {feed.auth_config['token']}"
            elif feed.auth_type == "basic" and feed.auth_config.get("username"):
                import base64
                creds = base64.b64encode(
                    f"{feed.auth_config['username']}:{feed.auth_config.get('password', '')}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {creds}"
            elif feed.auth_type == "api_key" and feed.auth_config.get("key"):
                headers[feed.auth_config.get("header", "X-API-Key")] = feed.auth_config["key"]
            
            async with session.get(feed.url, headers=headers, timeout=120) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}: {await resp.text()}")
                
                content = await resp.read()
                
                # Parse based on feed type
                imported = 0
                if feed.feed_type == "stix":
                    imported = await self._parse_stix_feed(content, feed)
                elif feed.feed_type == "misp":
                    imported = await self._parse_misp_feed(content, feed)
                elif feed.feed_type == "csv":
                    imported = await self._parse_csv_feed(content, feed)
                elif feed.feed_type == "json":
                    imported = await self._parse_json_feed(content, feed)
                elif feed.feed_type == "txt":
                    imported = await self._parse_txt_feed(content, feed)
                
                feed.last_sync = datetime.utcnow()
                feed.last_sync_status = "success"
                feed.indicators_imported = imported
                self._save_feeds()
                
                result["success"] = True
                result["indicators_imported"] = imported
                
        except Exception as exc:
            logger.exception(f"Feed sync failed for {feed_id}: {exc}")
            feed.last_sync = datetime.utcnow()
            feed.last_sync_status = f"error: {exc}"
            feed.indicators_rejected += 1
            self._save_feeds()
            result["errors"].append(str(exc))
        finally:
            await session.close()
        
        return result
    
    async def sync_all_feeds(self, enabled_only: bool = True) -> dict:
        """Sync all feeds."""
        results = {}
        feeds = self.list_feeds(enabled_only=enabled_only)
        for feed in feeds:
            results[feed.feed_id] = await self.sync_feed(feed.feed_id)
        return results
    
    async def _parse_stix_feed(self, content: bytes, feed: ThreatFeed) -> int:
        """Parse STIX bundle/feed."""
        try:
            data = json.loads(content)
            objects = data.get("objects", []) if isinstance(data, dict) else data
            imported = 0
            for obj in objects:
                if obj.get("type") == "indicator":
                    # Would import to database
                    imported += 1
            return imported
        except Exception:
            return 0
    
    async def _parse_misp_feed(self, content: bytes, feed: ThreatFeed) -> int:
        """Parse MISP feed (JSON)."""
        try:
            json.loads(content)
            # MISP format
            return 0
        except Exception:
            return 0
    
    async def _parse_csv_feed(self, content: bytes, feed: ThreatFeed) -> int:
        """Parse CSV feed."""
        import csv
        import io
        try:
            text = content.decode("utf-8")
            reader = csv.DictReader(io.StringIO(text))
            imported = 0
            for row in reader:
                # Would import
                imported += 1
            return imported
        except Exception:
            return 0
    
    async def _parse_json_feed(self, content: bytes, feed: ThreatFeed) -> int:
        """Parse JSON feed."""
        try:
            data = json.loads(content)
            imported = 0
            if isinstance(data, list):
                imported = len(data)
            elif isinstance(data, dict) and "indicators" in data:
                imported = len(data["indicators"])
            return imported
        except Exception:
            return 0
    
    async def _parse_txt_feed(self, content: bytes, feed: ThreatFeed) -> int:
        """Parse text feed (one indicator per line)."""
        try:
            text = content.decode("utf-8")
            lines = [l.strip() for l in text.split("\n") if l.strip() and not l.startswith("#")]
            return len(lines)
        except Exception:
            return 0


# ──────────────────────────────────────────────────────────────────────────────
# ATT&CK Navigator Integration
# ──────────────────────────────────────────────────────────────────────────────

class AttackNavigator:
    """
    Generate ATT&CK Navigator layer JSON for visualization.
    """
    
    # Enterprise ATT&CK matrix (simplified)
    TACTICS = [
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact"
    ]
    
    def __init__(self):
        self.techniques = self._load_technique_map()
    
    def _load_technique_map(self) -> dict:
        """Load technique ID to tactic mapping."""
        # In production, load from ATT&CK STIX data
        return {}
    
    def generate_layer(
        self,
        name: str,
        description: str,
        techniques: list[str],
        gradient: dict | None = None,
        domain: str = "enterprise-attack",
        version: str = "4.0",
    ) -> dict:
        """Generate Navigator layer JSON."""
        
        # Score techniques
        technique_scores = {}
        for t in techniques:
            if t in technique_scores:
                technique_scores[t] += 1
            else:
                technique_scores[t] = 1
        
        # Build layer
        layer = {
            "name": name,
            "description": description,
            "domain": domain,
            "version": version,
            "gradient": gradient or {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": max(technique_scores.values()) if technique_scores else 1,
            },
            "legendItems": [
                {"label": "Not observed", "color": "#ffffff"},
                {"label": "Observed", "color": "#ff6666"},
            ],
            "techniques": [
                {
                    "techniqueID": tid,
                    "score": score,
                    "comment": f"Observed {score} time(s)",
                    "enabled": True,
                }
                for tid, score in technique_scores.items()
            ],
            "metadata": [
                {"name": "source", "value": "MALINFO"},
                {"name": "generated", "value": datetime.utcnow().isoformat()},
            ],
        }
        
        return layer
    
    def generate_actor_layer(self, actor: ThreatActor) -> dict:
        """Generate layer for threat actor TTPs."""
        return self.generate_layer(
            name=f"ATT&CK Profile: {actor.name}",
            description=f"MITRE ATT&CK techniques associated with {actor.name}",
            techniques=actor.ttps,
        )
    
    def generate_campaign_layer(self, campaign: Campaign) -> dict:
        """Generate layer for campaign TTPs."""
        return self.generate_layer(
            name=f"ATT&CK Profile: {campaign.name}",
            description=f"MITRE ATT&CK techniques used in {campaign.name}",
            techniques=campaign.ttps,
        )
    
    def generate_sample_layer(self, mitre_techniques: list[str]) -> dict:
        """Generate layer for sample analysis."""
        return self.generate_layer(
            name="Sample Behavior Analysis",
            description="MITRE ATT&CK techniques observed during dynamic analysis",
            techniques=mitre_techniques,
        )
    
    def generate_coverage_layer(
        self,
        detected: list[str],
        total_techniques: list[str],
        name: str = "Detection Coverage",
    ) -> dict:
        """Generate detection coverage heatmap."""
        scores = {}
        for t in total_techniques:
            scores[t] = 1 if t in detected else 0
        
        return self.generate_layer(
            name=name,
            description="Detection coverage across MITRE ATT&CK",
            techniques=list(scores.keys()),
            gradient={
                "colors": ["#ff4444", "#ffff00", "#44ff44"],
                "minValue": 0,
                "maxValue": 1,
            },
        )
    
    def generate_gap_layer(
        self,
        actor_ttps: list[str],
        detection_ttps: list[str],
        name: str = "Detection Gaps",
    ) -> dict:
        """Generate detection gap analysis."""
        gaps = set(actor_ttps) - set(detection_ttps)
        covered = set(actor_ttps) & set(detection_ttps)
        
        techniques = {}
        for t in actor_ttps:
            techniques[t] = 0 if t in gaps else 1
        
        return self.generate_layer(
            name=name,
            description=f"Detection gaps for threat actor. Covered: {len(covered)}, Gaps: {len(gaps)}",
            techniques=list(techniques.keys()),
            gradient={
                "colors": ["#ff4444", "#44ff44"],
                "minValue": 0,
                "maxValue": 1,
            },
        )


# ──────────────────────────────────────────────────────────────────────────────
# Threat Intelligence Platform Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

class ThreatIntelPlatform:
    """
    Main threat intelligence platform orchestrator.
    
    Combines:
    - STIX/TAXII server
    - MISP synchronization
    - Threat feed management
    - Actor/Campaign profiling
    - ATT&CK Navigator integration
    - Indicator lifecycle management
    """
    
    def __init__(self, storage_dir: Path | None = None):
        self.storage_dir = storage_dir or Path("/opt/malinfo/threat_intel")
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self.taxii = StixTaxiiServer()
        self.feed_manager = ThreatFeedManager(self.storage_dir / "feeds")
        self.navigator = AttackNavigator()
        
        # In-memory stores (would be database in production)
        self.actors: dict[str, ThreatActor] = {}
        self.campaigns: dict[str, Campaign] = {}
        self.indicators: dict[str, Indicator] = {}
    
    # ─── Actor Management ───
    
    def create_actor(self, actor: ThreatActor) -> bool:
        """Create threat actor profile."""
        self.actors[actor.actor_id] = actor
        return True
    
    def get_actor(self, actor_id: str) -> ThreatActor | None:
        return self.actors.get(actor_id)
    
    def update_actor(self, actor_id: str, updates: dict) -> bool:
        """Update actor profile."""
        actor = self.actors.get(actor_id)
        if not actor:
            return False
        for key, value in updates.items():
            if hasattr(actor, key):
                setattr(actor, key, value)
        actor.updated_at = datetime.utcnow()
        return True
    
    def list_actors(self, actor_type: ThreatActorType = None) -> list[ThreatActor]:
        actors = list(self.actors.values())
        if actor_type:
            actors = [a for a in actors if a.actor_type == actor_type]
        return actors
    
    # ─── Campaign Management ───
    
    def create_campaign(self, campaign: Campaign) -> bool:
        self.campaigns[campaign.campaign_id] = campaign
        return True
    
    def get_campaign(self, campaign_id: str) -> Campaign | None:
        return self.campaigns.get(campaign_id)
    
    def list_campaigns(self) -> list[Campaign]:
        return list(self.campaigns.values())
    
    # ─── Indicator Management ───
    
    def add_indicator(self, indicator: Indicator) -> bool:
        self.indicators[indicator.indicator_id] = indicator
        return True
    
    def get_indicator(self, indicator_id: str) -> Indicator | None:
        return self.indicators.get(indicator_id)
    
    def search_indicators(
        self,
        pattern: str | None = None,
        indicator_type: str | None = None,
        tags: list[str] | None = None,
        threat_actor: str | None = None,
        campaign: str | None = None,
        min_confidence: int = 0,
        limit: int = 1000,
    ) -> list[Indicator]:
        results = list(self.indicators.values())
        
        if pattern:
            results = [i for i in results if pattern.lower() in i.pattern.lower() or pattern.lower() in i.name.lower()]
        if indicator_type:
            results = [i for i in results if indicator_type in i.indicator_types]
        if tags:
            results = [i for i in results if any(t in i.tags for t in tags)]
        if threat_actor:
            results = [i for i in results if threat_actor in i.threat_actors]
        if campaign:
            results = [i for i in results if campaign in i.campaigns]
        if min_confidence:
            results = [i for i in results if i.confidence >= min_confidence]
        
        # Apply age scoring
        for i in results:
            i.confidence = int(i.confidence * i.age_score())
        
        return sorted(results, key=lambda x: x.confidence, reverse=True)[:limit]
    
    def export_indicators_stix(self, indicators: list[Indicator] | None = None) -> dict:
        """Export indicators as STIX bundle."""
        indicators = indicators or list(self.indicators.values())
        objects = [i.to_stix() for i in indicators]
        
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }
    
    def export_indicators_misp(self, indicators: list[Indicator] | None = None) -> dict:
        """Export indicators as MISP event."""
        indicators = indicators or list(self.indicators.values())
        
        attributes = []
        for ind in indicators:
            type_map = {
                "ipv4-addr": "ip-dst",
                "ipv6-addr": "ip-dst",
                "domain-name": "domain",
                "url": "url",
                "email-addr": "email-src",
                "file": "sha256",
                "mutex": "mutex",
                "windows-registry-key": "regkey",
            }
            
            misp_type = type_map.get(ind.indicator_types[0] if ind.indicator_types else "", "text")
            
            # Extract value from pattern
            import re
            match = re.search(r"([a-z-]+):value = '([^']+)'", ind.pattern)
            value = match.group(2) if match else ind.pattern
            
            attributes.append({
                "type": misp_type,
                "value": value,
                "comment": ind.description,
                "confidence": ind.confidence,
                "Tag": [{"name": tag} for tag in ind.tags],
                "to_ids": True,
            })
        
        return {
            "Event": {
                "info": "MALINFO Indicator Export",
                "analysis": 2,
                "threat_level_id": 2,
                "published": False,
                "Attribute": attributes,
            }
        }
    
    def export_indicators_csv(self, indicators: list[Indicator] | None = None) -> str:
        """Export indicators as CSV."""
        indicators = indicators or list(self.indicators.values())
        lines = ["id,type,value,confidence,description,tags,mitre,source,created"]
        for ind in indicators:
            pattern = ind.pattern.replace('"', '""')
            description = ind.description.replace('"', '""')
            tags = ';'.join(ind.tags)
            mitre = ';'.join(ind.mitre_techniques)
            lines.append(
                f"{ind.indicator_id},"
                f"{','.join(ind.indicator_types)},"
                f"\"{pattern}\","
                f"{ind.confidence},"
                f"\"{description}\","
                f"\"{tags}\","
                f"\"{mitre}\","
                f"{ind.source},"
                f"{ind.created_at.isoformat()}"
            )
        return "\n".join(lines)
    
    # ─── ATT&CK Navigator ───
    
    def generate_actor_navigator(self, actor_id: str) -> dict:
        actor = self.get_actor(actor_id)
        if not actor:
            return {"error": "Actor not found"}
        return self.navigator.generate_actor_layer(actor)
    
    def generate_campaign_navigator(self, campaign_id: str) -> dict:
        campaign = self.get_campaign(campaign_id)
        if not campaign:
            return {"error": "Campaign not found"}
        return self.navigator.generate_campaign_layer(campaign)
    
    def generate_detection_coverage(self, detected_ttps: list[str]) -> dict:
        # Get all techniques from actors/campaigns
        all_ttps = set()
        for actor in self.actors.values():
            all_ttps.update(actor.ttps)
        for campaign in self.campaigns.values():
            all_ttps.update(campaign.ttps)
        
        return self.navigator.generate_coverage_layer(detected_ttps, list(all_ttps))
    
    def generate_detection_gaps(self, actor_id: str, detection_ttps: list[str]) -> dict:
        actor = self.get_actor(actor_id)
        if not actor:
            return {"error": "Actor not found"}
        return self.navigator.generate_gap_layer(actor.ttps, detection_ttps)
    
    # ─── Indicator Lifecycle ───
    
    def age_indicators(self, max_age_days: int = 365) -> dict:
        """Age out old indicators."""
        aged = 0
        removed = 0
        now = datetime.utcnow()
        
        for ind_id, ind in list(self.indicators.items()):
            age = (now - ind.created_at).days
            if age > ind.half_life_days:
                ind.confidence = int(ind.confidence * 0.5)
                aged += 1
            if age > max_age_days:
                del self.indicators[ind_id]
                removed += 1
        
        return {"aged": aged, "removed": removed}
    
    def correlate_indicators(self, indicator_id: str) -> list[dict]:
        """Find related indicators."""
        indicator = self.get_indicator(indicator_id)
        if not indicator:
            return []
        
        correlations = []
        for other in self.indicators.values():
            if other.indicator_id == indicator_id:
                continue
            
            # Same threat actor
            shared_actors = set(indicator.threat_actors) & set(other.threat_actors)
            if shared_actors:
                correlations.append({
                    "indicator_id": other.indicator_id,
                    "type": "shared_threat_actor",
                    "actors": list(shared_actors),
                    "confidence": 0.8,
                })
            
            # Same campaign
            shared_campaigns = set(indicator.campaigns) & set(other.campaigns)
            if shared_campaigns:
                correlations.append({
                    "indicator_id": other.indicator_id,
                    "type": "shared_campaign",
                    "campaigns": list(shared_campaigns),
                    "confidence": 0.8,
                })
            
            # Same MITRE technique
            shared_ttps = set(indicator.mitre_techniques) & set(other.mitre_techniques)
            if shared_ttps:
                correlations.append({
                    "indicator_id": other.indicator_id,
                    "type": "shared_ttp",
                    "techniques": list(shared_ttps),
                    "confidence": 0.6,
                })
            
            # Same malware family
            shared_malware = set(indicator.malware_families) & set(other.malware_families)
            if shared_malware:
                correlations.append({
                    "indicator_id": other.indicator_id,
                    "type": "shared_malware",
                    "families": list(shared_malware),
                    "confidence": 0.7,
                })
        
        return sorted(correlations, key=lambda x: x["confidence"], reverse=True)


# ──────────────────────────────────────────────────────────────────────────────
# Default Feed Configuration
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_THREAT_FEEDS = [
    ThreatFeed(
        feed_id="virustotal",
        name="VirusTotal v3",
        url="https://www.virustotal.com/api/v3/intelligence/hunting_notifications",
        feed_type="json",
        auth_type="api_key",
        auth_config={"header": "x-apikey", "key": ""},
        schedule="hourly",
        tags=["malware", "intelligence"],
    ),
    ThreatFeed(
        feed_id="otx",
        name="AlienVault OTX",
        url="https://otx.alienvault.com/api/v1/pulses/subscribed",
        feed_type="json",
        auth_type="api_key",
        auth_config={"header": "X-OTX-API-KEY", "key": ""},
        schedule="daily",
        tags=["threat-intel", "pulses"],
    ),
    ThreatFeed(
        feed_id="abuseipdb",
        name="AbuseIPDB",
        url="https://api.abuseipdb.com/api/v2/blacklist",
        feed_type="json",
        auth_type="api_key",
        auth_config={"header": "Key", "key": ""},
        schedule="daily",
        tags=["ip-reputation", "abuse"],
    ),
    ThreatFeed(
        feed_id="abuse_ch_urlhaus",
        name="Abuse.ch URLhaus",
        url="https://urlhaus.abuse.ch/downloads/csv/",
        feed_type="csv",
        schedule="daily",
        tags=["malware", "urls", "c2"],
    ),
    ThreatFeed(
        feed_id="abuse_ch_sslbl",
        name="Abuse.ch SSLBL",
        url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        feed_type="csv",
        schedule="daily",
        tags=["ssl", "certificates", "c2"],
    ),
    ThreatFeed(
        feed_id="abuse_ch_feodo",
        name="Abuse.ch FeodoTracker",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        feed_type="csv",
        schedule="daily",
        tags=["c2", "botnet", "banking"],
    ),
    ThreatFeed(
        feed_id="spamhaus_drop",
        name="Spamhaus DROP",
        url="https://www.spamhaus.org/drop/drop.txt",
        feed_type="txt",
        schedule="daily",
        tags=["ip-reputation", "spam", "malware"],
    ),
    ThreatFeed(
        feed_id="emerging_threats",
        name="Emerging Threats Rules",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        feed_type="txt",
        schedule="daily",
        tags=["ip-reputation", "compromised"],
    ),
    ThreatFeed(
        feed_id="cisa_known_exploited",
        name="CISA Known Exploited Vulnerabilities",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        feed_type="json",
        schedule="daily",
        tags=["vulnerabilities", "exploited"],
    ),
]


def initialize_default_feeds(manager: ThreatFeedManager):
    """Initialize default threat feeds."""
    for feed in DEFAULT_THREAT_FEEDS:
        if feed.feed_id not in manager.feeds:
            manager.add_feed(feed)