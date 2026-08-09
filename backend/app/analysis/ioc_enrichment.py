"""
MALINFO — Advanced IOC Extraction & Enrichment.

Advanced IOC extraction with passive DNS enrichment, SSL certificate parsing,
DGA detection, C2 framework fingerprinting, MITRE ATT&CK mapping,
and correlation across samples/campaigns.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.ioc_enrichment")

# ──────────────────────────────────────────────────────────────────────────────
# Data Classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class EnrichedIOC:
    """An IOC with enrichment data."""
    ioc_type: str
    value: str
    confidence: float = 0.5
    context: str = ""
    source: str = "static"
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tags: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    enrichment: dict = field(default_factory=dict)
    relationships: list[dict] = field(default_factory=list)
    
    def to_stix(self) -> dict:
        """Convert to STIX 2.1 Indicator."""
        pattern_map = {
            "ip": "[ipv4-addr:value = '{value}']",
            "ipv6": "[ipv6-addr:value = '{value}']",
            "domain": "[domain-name:value = '{value}']",
            "url": "[url:value = '{value}']",
            "email": "[email-addr:value = '{value}']",
            "md5": "[file:hashes.MD5 = '{value}']",
            "sha1": "[file:hashes.SHA-1 = '{value}']",
            "sha256": "[file:hashes.SHA-256 = '{value}']",
            "mutex": "[mutex:name = '{value}']",
            "registry": "[windows-registry-key:key = '{value}']",
        }
        
        pattern = pattern_map.get(self.ioc_type, "[x-malinfo-ioc:value = '{value}']")
        
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{hashlib.sha256(f'{self.ioc_type}:{self.value}'.encode()).hexdigest()[:32]}",
            "created": self.first_seen.isoformat() + "Z",
            "modified": self.last_seen.isoformat() + "Z",
            "name": f"{self.ioc_type}:{self.value}",
            "description": self.context,
            "indicator_types": ["malicious-activity"],
            "pattern": pattern.format(value=self.value),
            "pattern_type": "stix",
            "valid_from": self.first_seen.isoformat() + "Z",
            "labels": self.tags or ["malicious-activity"],
            "confidence": int(self.confidence * 100),
            "external_references": [
                {
                    "source_name": "MALINFO",
                    "external_id": f"{self.ioc_type}:{self.value}",
                }
            ],
        }


@dataclass
class C2Profile:
    """C2 framework profile for fingerprinting."""
    framework: str
    version: str | None = None
    profile_name: str | None = None
    indicators: dict = field(default_factory=dict)
    confidence: float = 0.0


# ──────────────────────────────────────────────────────────────────────────────
# C2 Framework Fingerprints
# ──────────────────────────────────────────────────────────────────────────────

_C2_FRAMEWORKS = {
    "Cobalt Strike": {
        "uris": ["/submit.php", "/gate.php", "/admin.php", "/index.php", "/news.php", "/images/"],
        "user_agents": ["Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko"],
        "headers": {"Cookie": "SESSIONID=", "X-Request-ID": ""},
        "ports": [80, 443, 8080, 8443],
        "watermark": "CS_",
        "pipename": "msagent_",
        "mutant": "CobaltStrike",
        "dns": {"type": "TXT", "subdomains": ["stage", "beacon", "c2"]},
        "ssl": {"self_signed": True, "cert_lifetime_days": 3650},
    },
    "Sliver": {
        "uris": ["/api/", "/rpc/", "/ws/", "/health"],
        "user_agents": ["Sliver/", "Go-http-client/"],
        "headers": {"X-Sliver": "", "Authorization": "Bearer "},
        "ports": [80, 443, 8080, 8443, 8888],
        "watermark": "sliver_",
        "mutant": "Sliver",
        "dns": {"type": "TXT", "subdomains": ["sliver", "implant"]},
        "mtls": True,
    },
    "Mythic": {
        "uris": ["/mythic/", "/agent/", "/callback/"],
        "user_agents": ["Mythic/", "Apollo/"],
        "headers": {"X-Mythic": ""},
        "ports": [80, 443, 8080],
        "mutant": "Mythic",
    },
    "Brute Ratel": {
        "uris": ["/api/v1/", "/brute/", "/ratel/"],
        "user_agents": ["BruteRatel/", "BRc4/"],
        "headers": {"X-BRc4": ""},
        "ports": [443, 8443],
        "watermark": "BRc4",
        "mutant": "BruteRatel",
    },
    "PoshC2": {
        "uris": ["/images/", "/scripts/", "/styles/", "/api/"],
        "user_agents": ["PoshC2/", "PowerShell/"],
        "headers": {"X-PoshC2": ""},
        "ports": [80, 443, 8080],
        "mutant": "PoshC2",
    },
    "Empire": {
        "uris": ["/login/", "/admin/", "/api/"],
        "user_agents": ["Empire/", "PowerShell/"],
        "headers": {"X-Empire": ""},
        "ports": [80, 443],
        "mutant": "Empire",
    },
    "Metasploit": {
        "uris": ["/", "/ads/", "/track/"],
        "user_agents": ["Metasploit/", "Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)"],
        "headers": {"Server": "Apache"},
        "ports": [80, 443, 8080, 8443],
        "pipename": "meterpreter_",
        "mutant": "Metasploit",
    },
    "Covenant": {
        "uris": ["/covenant/", "/api/", "/grunt/"],
        "user_agents": ["Covenant/", "Grunt/"],
        "headers": {"X-Covenant": ""},
        "ports": [443, 8443],
        "mutant": "Covenant",
    },
    "Havoc": {
        "uris": ["/havoc/", "/api/", "/demon/"],
        "user_agents": ["Havoc/", "Demon/"],
        "headers": {"X-Havoc": ""},
        "ports": [443, 8443],
        "mutant": "Havoc",
    },
    "Nimplant": {
        "uris": ["/nimplant/", "/api/"],
        "user_agents": ["Nimplant/"],
        "headers": {"X-Nimplant": ""},
        "ports": [443],
        "mutant": "Nimplant",
    },
    "Merlin": {
        "uris": ["/merlin/", "/api/"],
        "user_agents": ["Merlin/"],
        "headers": {"X-Merlin": ""},
        "ports": [443, 8443],
        "mutant": "Merlin",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# DGA Detection
# ──────────────────────────────────────────────────────────────────────────────

_KNOWN_DGA_PATTERNS = {
    "Necurs": {"tlds": [".bit", ".com", ".net", ".org", ".biz", ".info"], "length_range": (12, 16), "charset": "alphanum"},
    "Gameover ZeuS": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".ru", ".cn"], "length_range": (10, 20)},
    "Conficker": {"tlds": [".com", ".net", ".org", ".info", ".biz", ".ws"], "algorithm": "conficker"},
    "Matsnu": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length_range": (16, 20)},
    "Rovnix": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".ru"], "length_range": (8, 12)},
    "Suppobox": {"tlds": [".com", ".net", ".org"], "length_range": (10, 15)},
    "Tinba": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length_range": (12, 18)},
    "Pykspa": {"tlds": [".com", ".net", ".org", ".info", ".biz", ".ru", ".eu"], "length_range": (12, 16)},
    "Symmi": {"tlds": [".com", ".net", ".org"], "length_range": (12, 16)},
    "Kraken": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length_range": (12, 16)},
    "Gozi": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".ru"], "length_range": (12, 16)},
    "Ramnit": {"tlds": [".com", ".net", ".org"], "length_range": (10, 15)},
    "Dyre": {"tlds": [".com", ".net", ".org"], "length_range": (12, 16)},
    "Locky": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length_range": (12, 16)},
    "Cerber": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".top", ".xyz"], "length_range": (10, 15)},
    "Jaff": {"tlds": [".com", ".net", ".org"], "length_range": (12, 16)},
    "TrickBot": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length_range": (12, 18)},
    "Emotet": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length_range": (12, 16)},
    "QakBot": {"tlds": [".com", ".net", ".org"], "length_range": (12, 16)},
    "IcedID": {"tlds": [".com", ".net", ".org"], "length_range": (12, 16)},
    "BazarLoader": {"tlds": [".com", ".net", ".org"], "length_range": (12, 16)},
}

# ──────────────────────────────────────────────────────────────────────────────
# Passive DNS Cache (in-memory, would be external in production)
# ──────────────────────────────────────────────────────────────────────────────

_passive_dns_cache: dict[str, dict] = {}
_passive_dns_cache_ttl = timedelta(hours=24)


# ──────────────────────────────────────────────────────────────────────────────
# Main Enrichment Functions
# ──────────────────────────────────────────────────────────────────────────────

def extract_and_enrich_iocs(
    file_path: Path,
    strings: list[str] | None = None,
    pe_info: dict | None = None,
    network_data: dict | None = None,
    sandbox_data: dict | None = None,
) -> list[EnrichedIOC]:
    """
    Extract IOCs from multiple sources and enrich them.
    """
    iocs: list[EnrichedIOC] = []
    
    # ─── Extract from strings ───
    if strings:
        iocs.extend(_extract_iocs_from_strings(strings, source="strings"))
    
    # ─── Extract from PE info ───
    if pe_info:
        iocs.extend(_extract_iocs_from_pe(pe_info))
    
    # ─── Extract from network data ───
    if network_data:
        iocs.extend(_extract_iocs_from_network(network_data))
    
    # ─── Extract from sandbox data ───
    if sandbox_data:
        iocs.extend(_extract_iocs_from_sandbox(sandbox_data))
    
    # ─── Deduplicate ───
    iocs = _deduplicate_iocs(iocs)
    
    # ─── Enrich each IOC ───
    for ioc in iocs:
        _enrich_ioc(ioc, file_path)
    
    # ─── Correlate ───
    _correlate_iocs(iocs)
    
    # ─── MITRE Mapping ───
    for ioc in iocs:
        ioc.mitre_techniques = _map_to_mitre(ioc)
    
    return iocs


def _extract_iocs_from_strings(strings: list[str], source: str = "static") -> list[EnrichedIOC]:
    """Extract IOCs from string list."""
    iocs = []
    
    # Regex patterns for different IOC types
    patterns = {
        "ip": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "ipv6": r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        "url": r'\b(?:https?|ftp)://[^\s/$.?#].[^\s]*\b',
        "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha1": r'\b[a-fA-F0-9]{40}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
        "mutex": r'(?:Global\\|Local\\|Session\\|BaseNamedObjects\\)[A-Za-z0-9_\-\.]{3,}',
        "registry": r'(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))[\\][A-Za-z0-9_\-\.\\]{3,}',
        "filepath": r'(?:[A-Za-z]:\\|\\)/[\w\s\-\.\\]+',
        "guid": r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        "btc_address": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "xmr_address": r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
        "eth_address": r'\b0x[a-fA-F0-9]{40}\b',
        "ipfs_hash": r'\bQm[1-9A-HJ-NP-Za-km-z]{44,}\b',
        "onion": r'\b[a-z2-7]{16}\.onion\b',
        "onion_v3": r'\b[a-z2-7]{56}\.onion\b',
    }
    
    text = "\n".join(strings)
    
    for ioc_type, pattern in patterns.items():
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            value = match.group(0)
            
            # Filter out false positives
            if not _is_valid_ioc(ioc_type, value, text):
                continue
            
            # Get context (surrounding text)
            context_start = max(0, match.start() - 200)
            context_end = min(len(text), match.end() + 200)
            context = text[context_start:context_end]
            
            ioc = EnrichedIOC(
                ioc_type=ioc_type,
                value=value.lower() if ioc_type in ["domain", "email", "md5", "sha1", "sha256"] else value,
                confidence=0.6,
                context=context,
                source=source,
                tags=[source],
            )
            iocs.append(ioc)
    
    return iocs


def _is_valid_ioc(ioc_type: str, value: str, context: str) -> bool:
    """Validate IOC to reduce false positives."""
    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
            # Filter private/reserved IPs
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
            # Filter common CDN/cloud ranges (heuristic)
            if ip.is_global:
                return True
        except ValueError:
            return False
    elif ioc_type == "domain":
        # Filter common false positives
        if value.lower().endswith((".com", ".net", ".org", ".io", ".co", ".ai")):
            # Check if it's a known legitimate domain
            common_legit = ["google.com", "microsoft.com", "amazon.com", "github.com", "cloudflare.com", "akamai.com"]
            if any(value.lower().endswith(d) for d in common_legit):
                return False
        # Must have at least one dot and valid TLD
        if "." not in value or len(value.rsplit(".", maxsplit=1)[-1]) < 2:
            return False
    elif ioc_type in ["md5", "sha1", "sha256"]:
        # Check if it looks like a real hash (not just hex string)
        if not re.match(r'^[a-fA-F0-9]+$', value):
            return False
    elif ioc_type == "url":
        # Must have valid URL structure
        try:
            parsed = urlparse(value)
            if not parsed.scheme or not parsed.netloc:
                return False
        except Exception:
            return False
    
    return True


def _extract_iocs_from_pe(pe_info: dict) -> list[EnrichedIOC]:
    """Extract IOCs from PE analysis results."""
    iocs = []
    
    # Imports that are IOCs
    suspicious_apis = pe_info.get("suspicious_api_calls", [])
    for api in suspicious_apis:
        iocs.append(EnrichedIOC(
            ioc_type="api_call",
            value=api,
            confidence=0.7,
            context=f"Imported API: {api}",
            source="pe_analysis",
            tags=["pe", "import", "suspicious_api"],
        ))
    
    # Sections with high entropy
    for section in pe_info.get("sections", []):
        if section.get("entropy", 0) > 7.5:
            iocs.append(EnrichedIOC(
                ioc_type="packed_section",
                value=f"{section.get('name', 'unknown')}:{section.get('entropy', 0)}",
                confidence=0.8,
                context=f"High entropy section: {section.get('name', 'unknown')}",
                source="pe_analysis",
                tags=["pe", "section", "high_entropy", "packed"],
            ))
    
    # Packer indicators
    for indicator in pe_info.get("packer_indicators", []):
        iocs.append(EnrichedIOC(
            ioc_type="packer_indicator",
            value=indicator,
            confidence=0.9,
            context=indicator,
            source="pe_analysis",
            tags=["pe", "packer"],
        ))
    
    # Overlay data
    if pe_info.get("overlay", {}).get("has_overlay"):
        overlay = pe_info["overlay"]
        iocs.append(EnrichedIOC(
            ioc_type="overlay_data",
            value=f"offset:{overlay.get('offset', 0)} size:{overlay.get('size', 0)}",
            confidence=0.7,
            context=f"Overlay data detected: {overlay.get('size', 0)} bytes",
            source="pe_analysis",
            tags=["pe", "overlay"],
        ))
        # Embedded files in overlay
        for embedded in overlay.get("embedded_files", []):
            iocs.append(EnrichedIOC(
                ioc_type="embedded_file",
                value=f"{embedded.get('type', 'unknown')} at offset {embedded.get('offset', 0)}",
                confidence=0.8,
                context=f"Embedded {embedded.get('type', 'file')} in overlay",
                source="pe_analysis",
                tags=["pe", "overlay", "embedded"],
            ))
    
    # Authenticode
    auth = pe_info.get("authenticode", {})
    if auth.get("has_signature"):
        iocs.append(EnrichedIOC(
            ioc_type="certificate",
            value=auth.get("thumbprint_sha256", auth.get("thumbprint_sha1", "unknown")),
            confidence=0.5,
            context=f"Signed by: {auth.get('signer', 'unknown')}",
            source="pe_analysis",
            tags=["pe", "signature", "authenticode"],
            enrichment={
                "signer": auth.get("signer"),
                "issuer": auth.get("issuer"),
                "valid": auth.get("is_valid"),
                "timestamp": auth.get("timestamp"),
            },
        ))
    
    return iocs


def _extract_iocs_from_network(network_data: dict) -> list[EnrichedIOC]:
    """Extract IOCs from network analysis (PCAP, flows)."""
    iocs = []
    
    # C2 candidates from network
    for c2 in network_data.get("c2_candidates", []):
        iocs.append(EnrichedIOC(
            ioc_type="c2_candidate",
            value=c2.get("value", ""),
            confidence=c2.get("confidence", 0.7),
            context=c2.get("context", "Network C2 candidate"),
            source="network_forensics",
            tags=["network", "c2"],
            enrichment=c2,
        ))
    
    # Beaconing
    if network_data.get("beaconing_detected"):
        iocs.append(EnrichedIOC(
            ioc_type="beaconing",
            value="detected",
            confidence=0.8,
            context="Periodic beaconing pattern detected in traffic",
            source="network_forensics",
            tags=["network", "beaconing", "c2"],
        ))
    
    # DNS queries
    for dns in network_data.get("dns_queries", []):
        iocs.append(EnrichedIOC(
            ioc_type="domain",
            value=dns.get("query", ""),
            confidence=0.5,
            context=f"DNS query: {dns.get('type', 'A')}",
            source="network_forensics",
            tags=["network", "dns"],
            enrichment={"dns_type": dns.get("type"), "response": dns.get("response")},
        ))
    
    # HTTP hosts
    for http in network_data.get("http_hosts", []):
        iocs.append(EnrichedIOC(
            ioc_type="domain",
            value=http.get("host", ""),
            confidence=0.6,
            context=f"HTTP Host header: {http.get('host', '')}",
            source="network_forensics",
            tags=["network", "http"],
            enrichment={"uri": http.get("uri"), "method": http.get("method")},
        ))
    
    # JA3 fingerprints
    for ja3 in network_data.get("ja3_fingerprints", []):
        iocs.append(EnrichedIOC(
            ioc_type="ja3",
            value=ja3.get("fingerprint", ""),
            confidence=0.7,
            context=f"JA3 fingerprint: {ja3.get('description', 'unknown')}",
            source="network_forensics",
            tags=["network", "tls", "ja3"],
            enrichment={"ja3s": ja3.get("ja3s"), "description": ja3.get("description")},
        ))
    
    return iocs


def _extract_iocs_from_sandbox(sandbox_data: dict) -> list[EnrichedIOC]:
    """Extract IOCs from sandbox/dynamic analysis."""
    iocs = []
    
    # Dropped files
    for dropped in sandbox_data.get("dropped_files", []):
        iocs.append(EnrichedIOC(
            ioc_type="file_hash",
            value=dropped.get("sha256", ""),
            confidence=0.9,
            context=f"Dropped file: {dropped.get('path', 'unknown')}",
            source="sandbox",
            tags=["sandbox", "dropped_file"],
            enrichment={"path": dropped.get("path"), "size": dropped.get("size")},
        ))
    
    # Registry modifications
    for reg in sandbox_data.get("registry_modifications", []):
        iocs.append(EnrichedIOC(
            ioc_type="registry",
            value=reg.get("key", ""),
            confidence=0.8,
            context=f"Registry {reg.get('operation', 'write')}: {reg.get('key', '')}",
            source="sandbox",
            tags=["sandbox", "registry", "persistence"],
            enrichment={"operation": reg.get("operation"), "value": reg.get("value")},
        ))
    
    # Process creations
    for proc in sandbox_data.get("process_creations", []):
        iocs.append(EnrichedIOC(
            ioc_type="process",
            value=proc.get("command_line", proc.get("image_path", "")),
            confidence=0.7,
            context=f"Process created: {proc.get('image_path', '')}",
            source="sandbox",
            tags=["sandbox", "process"],
            enrichment={"pid": proc.get("pid"), "parent_pid": proc.get("parent_pid")},
        ))
    
    # Network connections from sandbox
    for conn in sandbox_data.get("network_connections", []):
        iocs.append(EnrichedIOC(
            ioc_type="ip",
            value=conn.get("destination_ip", ""),
            confidence=0.8,
            context=f"Sandbox connection to {conn.get('destination_ip', '')}:{conn.get('destination_port', '')}",
            source="sandbox",
            tags=["sandbox", "network"],
            enrichment={"port": conn.get("destination_port"), "protocol": conn.get("protocol")},
        ))
    
    # Mutexes
    for mutex in sandbox_data.get("mutexes", []):
        iocs.append(EnrichedIOC(
            ioc_type="mutex",
            value=mutex,
            confidence=0.8,
            context=f"Mutex created/opened: {mutex}",
            source="sandbox",
            tags=["sandbox", "mutex", "synchronization"],
        ))
    
    # MITRE signatures from sandbox
    for sig in sandbox_data.get("signatures", []):
        iocs.append(EnrichedIOC(
            ioc_type="mitre_signature",
            value=sig.get("name", ""),
            confidence=0.7,
            context=f"Sandbox signature: {sig.get('description', '')}",
            source="sandbox",
            tags=["sandbox", "mitre", sig.get("severity", "medium")],
            enrichment={"mitre": sig.get("mitre"), "severity": sig.get("severity")},
        ))
    
    return iocs


def _enrich_ioc(ioc: EnrichedIOC, file_path: Path):
    """Enrich a single IOC with additional context."""
    
    if ioc.ioc_type == "domain":
        _enrich_domain(ioc)
    elif ioc.ioc_type == "ip":
        _enrich_ip(ioc)
    elif ioc.ioc_type == "url":
        _enrich_url(ioc)
    elif ioc.ioc_type in ["md5", "sha1", "sha256"]:
        _enrich_hash(ioc)
    elif ioc.ioc_type == "certificate":
        _enrich_certificate(ioc)
    elif ioc.ioc_type == "ja3":
        _enrich_ja3(ioc)
    elif ioc.ioc_type == "mutex":
        _enrich_mutex(ioc)
    elif ioc.ioc_type == "c2_candidate":
        _enrich_c2_candidate(ioc)
    
    # Check against threat intel (would integrate with threat_intel module)
    _enrich_with_threat_intel(ioc)


def _enrich_domain(ioc: EnrichedIOC):
    """Enrich domain IOC."""
    domain = ioc.value
    
    # Passive DNS (simulated - would query real passive DNS in production)
    if domain in _passive_dns_cache:
        cached = _passive_dns_cache[domain]
        if datetime.utcnow() - cached["timestamp"] < _passive_dns_cache_ttl:
            ioc.enrichment["passive_dns"] = cached["data"]
            ioc.confidence = max(ioc.confidence, 0.8)
    
    # DGA detection
    dga_result = _check_dga(domain)
    if dga_result["is_dga"]:
        ioc.enrichment["dga"] = dga_result
        ioc.tags.append("dga")
        ioc.confidence = max(ioc.confidence, 0.9)
    
    # Subdomain analysis
    parts = domain.split(".")
    if len(parts) > 2:
        ioc.enrichment["subdomain_count"] = len(parts) - 2
        ioc.enrichment["root_domain"] = ".".join(parts[-2:])
    
    # Entropy
    ioc.enrichment["entropy"] = round(shannon_entropy(domain.encode()), 3)
    
    # C2 framework check
    c2_match = _check_c2_framework_domain(domain)
    if c2_match:
        ioc.enrichment["c2_framework"] = c2_match
        ioc.tags.append("c2")


def _enrich_ip(ioc: EnrichedIOC):
    """Enrich IP IOC."""
    ip_str = ioc.value
    
    try:
        ip = ipaddress.ip_address(ip_str)
        ioc.enrichment["version"] = ip.version
        ioc.enrichment["is_private"] = ip.is_private
        ioc.enrichment["is_loopback"] = ip.is_loopback
        ioc.enrichment["is_multicast"] = ip.is_multicast
        
        # Try reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
            ioc.enrichment["reverse_dns"] = hostname
        except socket.herror:
            pass
        
        # ASN lookup (would use external service)
        ioc.enrichment["asn_lookup_needed"] = True
        
    except ValueError:
        pass


def _enrich_url(ioc: EnrichedIOC):
    """Enrich URL IOC."""
    try:
        parsed = urlparse(ioc.value)
        ioc.enrichment["scheme"] = parsed.scheme
        ioc.enrichment["host"] = parsed.netloc
        ioc.enrichment["path"] = parsed.path
        ioc.enrichment["query"] = parsed.query
        
        # Extract domain from URL
        if parsed.netloc:
            host = parsed.netloc.split(":")[0]
            ioc.enrichment["domain"] = host
            
    except Exception:
        pass


def _enrich_hash(ioc: EnrichedIOC):
    """Enrich file hash IOC."""
    hash_val = ioc.value
    
    # Determine hash type
    if len(hash_val) == 32:
        ioc.enrichment["hash_type"] = "MD5"
    elif len(hash_val) == 40:
        ioc.enrichment["hash_type"] = "SHA1"
    elif len(hash_val) == 64:
        ioc.enrichment["hash_type"] = "SHA256"
    
    # Would query VT, MISP, etc. in production
    ioc.enrichment["threat_intel_lookup_needed"] = True


def _enrich_certificate(ioc: EnrichedIOC):
    """Enrich certificate IOC."""
    # Certificate details already in IOC from PE analysis


def _enrich_ja3(ioc: EnrichedIOC):
    """Enrich JA3 fingerprint."""
    # Would lookup in JA3 database
    ioc.enrichment["ja3_lookup_needed"] = True


def _enrich_mutex(ioc: EnrichedIOC):
    """Enrich mutex IOC."""
    mutex = ioc.value
    
    # Known malware mutex patterns
    known_mutexes = {
        "Global\\{": "Potential malware mutex (GUID format)",
        "Local\\": "Local mutex",
        "BaseNamedObjects\\": "Named object mutex",
    }
    
    for pattern, desc in known_mutexes.items():
        if pattern in mutex:
            ioc.enrichment["pattern"] = pattern
            ioc.enrichment["description"] = desc
            break


def _enrich_c2_candidate(ioc: EnrichedIOC):
    """Enrich C2 candidate."""
    # Check against known C2 frameworks
    c2_match = _check_c2_framework_generic(ioc.value, ioc.context)
    if c2_match:
        ioc.enrichment["c2_framework"] = c2_match
        ioc.confidence = max(ioc.confidence, 0.9)
        ioc.tags.append("c2")


def _check_dga(domain: str) -> dict:
    """Check if domain is likely DGA-generated."""
    # Remove TLD
    parts = domain.split(".")
    if len(parts) < 2:
        return {"is_dga": False}
    
    # Check against known DGA patterns
    for dga_name, dga_info in _KNOWN_DGA_PATTERNS.items():
        tlds = dga_info.get("tlds", [])
        if any(domain.endswith(tld) for tld in tlds):
            # Extract subdomain
            subdomain = ".".join(parts[:-1]) if domain.endswith(tuple(tlds)) else parts[0]
            
            # Check length
            length_range = dga_info.get("length_range", (0, 100))
            if length_range[0] <= len(subdomain) <= length_range[1]:
                # Check entropy
                entropy = shannon_entropy(subdomain.encode())
                if entropy > 3.5:  # High entropy suggests DGA
                    return {
                        "is_dga": True,
                        "family": dga_name,
                        "subdomain": subdomain,
                        "entropy": round(entropy, 3),
                        "confidence": 0.7,
                    }
    
    # Generic high entropy check
    subdomain = parts[0]
    entropy = shannon_entropy(subdomain.encode())
    if len(subdomain) > 12 and entropy > 4.0:
        return {
            "is_dga": True,
            "family": "Unknown/Generic",
            "subdomain": subdomain,
            "entropy": round(entropy, 3),
            "confidence": 0.5,
        }
    
    return {"is_dga": False}


def _check_c2_framework_domain(domain: str) -> dict | None:
    """Check if domain matches known C2 framework patterns."""
    for framework, info in _C2_FRAMEWORKS.items():
        # Check subdomains
        for sub in info.get("dns", {}).get("subdomains", []):
            if sub in domain:
                return {"framework": framework, "indicator": f"subdomain:{sub}"}
        
        # Check watermark
        watermark = info.get("watermark")
        if watermark and watermark in domain:
            return {"framework": framework, "indicator": f"watermark:{watermark}"}
    
    return None


def _check_c2_framework_generic(value: str, context: str) -> dict | None:
    """Generic C2 framework check."""
    combined = f"{value} {context}".lower()
    
    for framework, info in _C2_FRAMEWORKS.items():
        matches = 0
        indicators = []
        
        # Check URIs
        for uri in info.get("uris", []):
            if uri.lower() in combined:
                matches += 1
                indicators.append(f"uri:{uri}")
        
        # Check user agents
        for ua in info.get("user_agents", []):
            if ua.lower() in combined:
                matches += 1
                indicators.append(f"ua:{ua}")
        
        # Check headers
        for header, val in info.get("headers", {}).items():
            if val.lower() in combined:
                matches += 1
                indicators.append(f"header:{header}")
        
        # Check mutant/pipe names
        for key in ["mutant", "pipename", "watermark"]:
            if info.get(key) and info[key].lower() in combined:
                matches += 1
                indicators.append(f"{key}:{info[key]}")
        
        if matches >= 2:
            return {
                "framework": framework,
                "matches": matches,
                "indicators": indicators,
                "confidence": min(0.5 + matches * 0.15, 0.95),
            }
    
    return None


def _enrich_with_threat_intel(ioc: EnrichedIOC):
    """Enrich IOC with threat intelligence (placeholder for integration)."""
    # This would integrate with the threat_intel module
    # For now, mark as needing enrichment
    ioc.enrichment["threat_intel_sources"] = ["virustotal", "otx", "abuseipdb", "misp"]


def _deduplicate_iocs(iocs: list[EnrichedIOC]) -> list[EnrichedIOC]:
    """Deduplicate IOCs by type and value."""
    seen = {}
    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value)
        if key in seen:
            # Merge contexts and take higher confidence
            existing = seen[key]
            existing.context += f" | {ioc.context}"
            existing.confidence = max(existing.confidence, ioc.confidence)
            existing.tags = list(set(existing.tags + ioc.tags))
            existing.enrichment.update(ioc.enrichment)
        else:
            seen[key] = ioc
    return list(seen.values())


def _correlate_iocs(iocs: list[EnrichedIOC]):
    """Find relationships between IOCs."""
    for i, ioc1 in enumerate(iocs):
        for ioc2 in iocs[i+1:]:
            # Same sample relationships
            if ioc1.source == ioc2.source:
                ioc1.relationships.append({
                    "type": "same_source",
                    "target": f"{ioc2.ioc_type}:{ioc2.value}",
                    "source_type": ioc2.ioc_type,
                })
            
            # Domain-IP relationships
            if ioc1.ioc_type == "domain" and ioc2.ioc_type == "ip":
                # Would resolve domain to check
                ioc1.relationships.append({
                    "type": "potential_resolution",
                    "target": f"ip:{ioc2.value}",
                })
            
            # Hash-Dropped file
            if ioc1.ioc_type in ["md5", "sha1", "sha256"] and ioc2.ioc_type == "file_hash":
                if ioc1.value == ioc2.value:
                    ioc1.relationships.append({
                        "type": "same_file",
                        "target": f"file_hash:{ioc2.value}",
                    })
            
            # C2 domain/IP correlation
            if ioc1.ioc_type == "c2_candidate" and ioc2.ioc_type in ["domain", "ip"]:
                ioc1.relationships.append({
                    "type": "c2_infrastructure",
                    "target": f"{ioc2.ioc_type}:{ioc2.value}",
                })


def _map_to_mitre(ioc: EnrichedIOC) -> list[str]:
    """Map IOC to MITRE ATT&CK techniques."""
    techniques = []
    
    mapping = {
        "ip": ["T1071.001", "T1071.002"],  # Web Protocols, File Transfer Protocols
        "domain": ["T1071.001", "T1568.002"],  # Web Protocols, Domain Generation Algorithms
        "url": ["T1071.001", "T1105"],  # Web Protocols, Ingress Tool Transfer
        "email": ["T1566.001"],  # Phishing: Spearphishing Attachment
        "md5": ["T1027.001"],  # Obfuscated/Stored Files: Binary Padding
        "sha1": ["T1027.001"],
        "sha256": ["T1027.001"],
        "mutex": ["T1547.001"],  # Boot or Logon Autostart Execution: Registry Run Keys
        "registry": ["T1547.001", "T1112"],  # Registry Run Keys, Modify Registry
        "filepath": ["T1574.001", "T1574.002"],  # Hijack Execution Flow
        "c2_candidate": ["T1071", "T1105", "T1573"],  # Application Layer Protocol, Ingress Tool Transfer, Encrypted Channel
        "beaconing": ["T1071.001", "T1573.001"],  # Web Protocols, Symmetric Cryptography
        "packer_indicator": ["T1027.002"],  # Software Packing
        "packed_section": ["T1027.002"],
        "overlay_data": ["T1027.006"],  # HTML Smuggling / Overlay
        "certificate": ["T1553.002"],  # Code Signing
        "ja3": ["T1573.001"],  # Encrypted Channel: Symmetric Cryptography
        "dga": ["T1568.002"],  # Domain Generation Algorithms
        "mitre_signature": [],  # Direct mapping from signature
    }
    
    if ioc.ioc_type in mapping:
        techniques.extend(mapping[ioc.ioc_type])
    
    # Add from enrichment
    if "c2_framework" in ioc.enrichment:
        fw = ioc.enrichment["c2_framework"]
        if isinstance(fw, dict) and "framework" in fw:
            framework_map = {
                "Cobalt Strike": ["T1055", "T1059", "T1071", "T1105", "T1573"],
                "Sliver": ["T1055", "T1059", "T1071", "T1105", "T1573"],
                "Mythic": ["T1055", "T1059", "T1071", "T1105"],
                "Brute Ratel": ["T1055", "T1059", "T1071", "T1105", "T1573"],
                "PoshC2": ["T1059.001", "T1071", "T1105"],
                "Empire": ["T1059.001", "T1071", "T1105"],
                "Metasploit": ["T1055", "T1059", "T1071", "T1105"],
                "Covenant": ["T1055", "T1059", "T1071", "T1105"],
                "Havoc": ["T1055", "T1059", "T1071", "T1105", "T1573"],
                "Merlin": ["T1071", "T1105", "T1573"],
            }
            if fw["framework"] in framework_map:
                techniques.extend(framework_map[fw["framework"]])
    
    return list(set(techniques))


# ──────────────────────────────────────────────────────────────────────────────
# Export Functions
# ──────────────────────────────────────────────────────────────────────────────

def iocs_to_stix_bundle(iocs: list[EnrichedIOC]) -> dict:
    """Convert IOCs to STIX 2.1 Bundle."""
    objects = []
    for ioc in iocs:
        objects.append(ioc.to_stix())
    
    return {
        "type": "bundle",
        "id": f"bundle--{hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()[:32]}",
        "spec_version": "2.1",
        "objects": objects,
    }


def iocs_to_misp(iocs: list[EnrichedIOC]) -> dict:
    """Convert IOCs to MISP event format."""
    attributes = []
    for ioc in iocs:
        type_map = {
            "ip": "ip-dst",
            "ipv6": "ip-dst",
            "domain": "domain",
            "url": "url",
            "email": "email-src",
            "md5": "md5",
            "sha1": "sha1",
            "sha256": "sha256",
            "mutex": "mutex",
            "registry": "regkey",
            "filepath": "filename",
            "c2_candidate": "ip-dst",
            "certificate": "x509-fingerprint-sha256",
            "ja3": "ja3-fingerprint-md5",
            "dga": "domain",
        }
        
        misp_type = type_map.get(ioc.ioc_type, "text")
        
        attributes.append({
            "type": misp_type,
            "value": ioc.value,
            "comment": ioc.context,
            "confidence": int(ioc.confidence * 100),
            "tags": ioc.tags,
            "timestamp": int(ioc.first_seen.timestamp()),
            "to_ids": True,
        })
    
    return {
        "Event": {
            "info": "MALINFO IOC Export",
            "analysis": 2,  # Completed
            "threat_level_id": 2,  # Medium
            "published": False,
            "Attribute": attributes,
        }
    }


def iocs_to_csv(iocs: list[EnrichedIOC]) -> str:
    """Convert IOCs to CSV format."""
    lines = ["type,value,confidence,context,source,tags,mitre_techniques,first_seen,last_seen"]
    for ioc in iocs:
        escaped_value = ioc.value.replace('"', '""')
        escaped_context = ioc.context.replace('"', '""')
        tags_str = ';'.join(ioc.tags)
        mitre_str = ';'.join(ioc.mitre_techniques)
        lines.append(
            f"{ioc.ioc_type},"
            f"\"{escaped_value}\","
            f"{ioc.confidence},"
            f"\"{escaped_context}\","
            f"{ioc.source},"
            f"\"{tags_str}\","
            f"\"{mitre_str}\","
            f"{ioc.first_seen.isoformat()},"
            f"{ioc.last_seen.isoformat()}"
        )
    return "\n".join(lines)