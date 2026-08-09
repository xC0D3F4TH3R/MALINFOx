"""
MALINFO — Enhanced Network Forensics.

Advanced network traffic analysis for malware C2 detection and behavioral profiling.
Includes: JA3/JA3S fingerprinting, TLS certificate extraction/validation,
DGA classification (ML), C2 protocol parsers, beaconing statistics,
encrypted traffic analysis, protocol identification.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

logger = logging.getLogger("malinfo.network_forensics_v2")

# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkFlow:
    """Enhanced network flow with full metadata."""
    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # TCP, UDP, ICMP
    start_time: datetime
    end_time: datetime
    duration: float
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    flags: list[str] = field(default_factory=list)
    state: str = ""  # ESTABLISHED, SYN_SENT, etc.
    pid: int | None = None
    process_name: str = ""
    
    # TLS/SSL
    ja3: str | None = None
    ja3s: str | None = None
    tls_version: str = ""
    cipher_suite: str = ""
    sni: str = ""
    cert_fingerprint: str = ""
    cert_chain: list[dict] = field(default_factory=list)
    
    # HTTP
    http_host: str = ""
    http_uri: str = ""
    http_method: str = ""
    http_user_agent: str = ""
    http_status: int = 0
    http_content_type: str = ""
    
    # DNS
    dns_queries: list[dict] = field(default_factory=list)
    
    # Anomalies
    anomalies: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    
    # Enrichment
    asn_info: dict = field(default_factory=dict)
    geo_info: dict = field(default_factory=dict)
    threat_intel: dict = field(default_factory=dict)


@dataclass
class PcapAnalysisResult:
    """Complete PCAP analysis result."""
    pcap_path: str
    file_size: int
    packet_count: int
    start_time: datetime
    end_time: datetime
    duration: float
    
    # Flows
    flows: list[NetworkFlow] = field(default_factory=list)
    flow_count: int = 0
    
    # Protocols
    protocol_distribution: dict = field(default_factory=dict)
    port_distribution: dict = field(default_factory=dict)
    
    # TLS
    tls_flows: list[NetworkFlow] = field(default_factory=list)
    ja3_fingerprints: list[dict] = field(default_factory=list)
    ja3s_fingerprints: list[dict] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    
    # HTTP
    http_flows: list[NetworkFlow] = field(default_factory=list)
    http_hosts: list[str] = field(default_factory=list)
    http_uris: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    
    # DNS
    dns_flows: list[NetworkFlow] = field(default_factory=list)
    dns_queries: list[dict] = field(default_factory=list)
    dga_candidates: list[dict] = field(default_factory=list)
    
    # C2
    c2_candidates: list[dict] = field(default_factory=list)
    beaconing_flows: list[dict] = field(default_factory=list)
    
    # Anomalies
    anomalies: list[dict] = field(default_factory=list)
    
    # Statistics
    top_talkers: list[dict] = field(default_factory=list)
    top_connections: list[dict] = field(default_factory=list)
    entropy_analysis: dict = field(default_factory=dict)
    
    # MITRE
    mitre_techniques: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# JA3/JA3S Fingerprinting
# ──────────────────────────────────────────────────────────────────────────────

# JA3 format: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
# Example: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0

# Known JA3 fingerprints for common malware/browsers
_JA3_FINGERPRINTS = {
    # Browsers (legitimate)
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": {
        "description": "Chrome 80-85 on Windows 10",
        "type": "legitimate",
    },
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": {
        "description": "Firefox 75-80 on Windows 10",
        "type": "legitimate",
    },
    # Cobalt Strike
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-11-10-35-16-23-21-13-18-51-45-43-27-5,29-23-24,0": {
        "description": "Cobalt Strike default",
        "type": "malware",
        "family": "Cobalt Strike",
    },
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-11-10-35-16-23-21-13-18-51-45-43-27-5,29-23-24,0": {
        "description": "Cobalt Strike Malleable Profile (default)",
        "type": "malware",
        "family": "Cobalt Strike",
    },
    # Metasploit
    "771,49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": {
        "description": "Metasploit Meterpreter",
        "type": "malware",
        "family": "Metasploit",
    },
    # Sliver
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-11-10-35-16-23-21-13-18-51-45-43-27-5,29-23-24,0": {
        "description": "Sliver implant",
        "type": "malware",
        "family": "Sliver",
    },
}

# Known JA3S (server) fingerprints
_JA3S_FINGERPRINTS = {
    "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0": {
        "description": "Standard TLS server (nginx/Apache)",
        "type": "legitimate",
    },
}


def calculate_ja3(tls_client_hello: dict) -> str:
    """
    Calculate JA3 fingerprint from TLS Client Hello.
    
    Args:
        tls_client_hello: Parsed TLS Client Hello with fields:
            - version: TLS version (int)
            - ciphers: List of cipher suite IDs (int)
            - extensions: List of extension IDs (int)
            - elliptic_curves: List of curve IDs (int)
            - ec_point_formats: List of point format IDs (int)
    
    Returns:
        JA3 fingerprint string
    """
    version = str(tls_client_hello.get("version", 771))
    ciphers = "-".join(str(c) for c in tls_client_hello.get("ciphers", []))
    extensions = "-".join(str(e) for e in tls_client_hello.get("extensions", []))
    curves = "-".join(str(c) for c in tls_client_hello.get("elliptic_curves", []))
    points = "-".join(str(p) for p in tls_client_hello.get("ec_point_formats", []))
    
    ja3_string = f"{version},{ciphers},{extensions},{curves},{points}"
    # MD5 used for JA3 fingerprint - standard TLS fingerprinting, not security
    return hashlib.md5(ja3_string.encode(), usedforsecurity=False).hexdigest()


def calculate_ja3s(tls_server_hello: dict) -> str:
    """Calculate JA3S fingerprint from TLS Server Hello."""
    version = str(tls_server_hello.get("version", 771))
    cipher = str(tls_server_hello.get("cipher", 0))
    extensions = "-".join(str(e) for e in tls_server_hello.get("extensions", []))

    ja3s_string = f"{version},{cipher},{extensions},,"
    # MD5 used for JA3S fingerprint - standard TLS fingerprinting, not security
    return hashlib.md5(ja3s_string.encode(), usedforsecurity=False).hexdigest()


def lookup_ja3(ja3_hash: str) -> dict:
    """Look up JA3 fingerprint in database."""
    return _JA3_FINGERPRINTS.get(ja3_hash, {
        "description": "Unknown JA3 fingerprint",
        "type": "unknown",
    })


def lookup_ja3s(ja3s_hash: str) -> dict:
    """Look up JA3S fingerprint in database."""
    return _JA3S_FINGERPRINTS.get(ja3s_hash, {
        "description": "Unknown JA3S fingerprint",
        "type": "unknown",
    })


# ──────────────────────────────────────────────────────────────────────────────
# TLS Certificate Extraction
# ──────────────────────────────────────────────────────────────────────────────

def extract_tls_certificates(pcap_path: Path) -> list[dict]:
    """Extract TLS certificates from PCAP."""
    certs = []
    
    try:
        import pyshark
    except ImportError:
        logger.warning("pyshark not installed, cannot extract TLS certificates")
        return certs
    
    try:
        cap = pyshark.FileCapture(str(pcap_path), display_filter="ssl.handshake.certificate")
        for pkt in cap:
            try:
                if hasattr(pkt, "ssl") and hasattr(pkt.ssl, "handshake_certificate"):
                    cert_data = pkt.ssl.handshake_certificate
                    cert_info = parse_certificate(cert_data)
                    if cert_info:
                        cert_info["packet_number"] = pkt.number
                        cert_info["timestamp"] = pkt.sniff_time.isoformat() if hasattr(pkt, "sniff_time") else ""
                        certs.append(cert_info)
            except Exception:
                continue
        cap.close()
    except Exception as exc:
        logger.exception(f"TLS certificate extraction failed: {exc}")
    
    return certs


def parse_certificate(cert_der_b64: str) -> dict | None:
    """Parse DER-encoded certificate from base64."""
    try:
        import base64

        from cryptography import x509
        
        der_bytes = base64.b64decode(cert_der_b64)
        cert = x509.load_der_x509_certificate(der_bytes)
        
        # Calculate fingerprints
        sha1_fp = cert.fingerprint(hashes.SHA1()).hex().upper()
        sha256_fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        
        # Subject/issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        # Validity
        not_before = cert.not_valid_before_utc.isoformat() + "Z"
        not_after = cert.not_valid_after_utc.isoformat() + "Z"
        
        # SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [name.value for name in san_ext.value]
        except Exception:
            pass
        
        # Key info
        pubkey = cert.public_key()
        key_info = {
            "algorithm": pubkey.__class__.__name__,
        }
        if hasattr(pubkey, "key_size"):
            key_info["key_size"] = pubkey.key_size
        elif hasattr(pubkey, "curve"):
            key_info["curve"] = pubkey.curve.name
        
        # Self-signed check
        is_self_signed = subject == issuer
        
        return {
            "sha1_fingerprint": sha1_fp,
            "sha256_fingerprint": sha256_fp,
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "sans": sans,
            "public_key": key_info,
            "is_self_signed": is_self_signed,
            "is_expired": datetime.utcnow() > cert.not_valid_after_utc,
            "days_until_expiry": (cert.not_valid_after_utc - datetime.utcnow()).days,
        }
    except Exception as exc:
        logger.debug(f"Certificate parsing failed: {exc}")
        return None


# Import for certificate parsing
try:
    from cryptography.hazmat.primitives import hashes
except ImportError:
    hashes = None


# ──────────────────────────────────────────────────────────────────────────────
# DGA Classification
# ──────────────────────────────────────────────────────────────────────────────

# Character-level features for DGA detection
_DGA_FEATURES = {
    "length": len,
    "entropy": lambda d: shannon_entropy(d.encode()),
    "digit_ratio": lambda d: sum(c.isdigit() for c in d) / len(d) if d else 0,
    "vowel_ratio": lambda d: sum(c.lower() in "aeiou" for c in d) / len(d) if d else 0,
    "consonant_ratio": lambda d: sum(c.lower() in "bcdfghjklmnpqrstvwxyz" for c in d) / len(d) if d else 0,
    "unique_chars": lambda d: len(set(d)),
    "max_consecutive_consonants": lambda d: max((len(m.group()) for m in re.finditer(r"[bcdfghjklmnpqrstvwxyz]+", d.lower())), default=0),
    "max_consecutive_digits": lambda d: max((len(m.group()) for m in re.finditer(r"\d+", d)), default=0),
    "has_tld": lambda d: 1 if "." in d else 0,
    "subdomain_count": lambda d: d.count("."),
    "hex_ratio": lambda d: sum(c in "0123456789abcdefABCDEF" for c in d) / len(d) if d else 0,
}

# Known DGA families with characteristics
_DGA_FAMILIES = {
    "necurs": {"tlds": [".bit", ".com", ".net", ".org", ".biz", ".info"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "gameover_zeus": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".ru", ".cn"], "length": (10, 20), "entropy": (3.0, 4.5)},
    "conficker": {"tlds": [".com", ".net", ".org", ".info", ".biz", ".ws"], "algorithm": "conficker"},
    "matsnu": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (16, 20), "entropy": (3.5, 4.5)},
    "rovnix": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".ru"], "length": (8, 12), "entropy": (3.0, 4.0)},
    "suppobox": {"tlds": [".com", ".net", ".org"], "length": (10, 15), "entropy": (3.0, 4.0)},
    "tinba": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (12, 18), "entropy": (3.5, 4.5)},
    "pykspa": {"tlds": [".com", ".net", ".org", ".info", ".biz", ".ru", ".eu"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "symmi": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "kraken": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "gozi": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".ru"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "ramnit": {"tlds": [".com", ".net", ".org"], "length": (10, 15), "entropy": (3.0, 4.0)},
    "dyre": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "locky": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "cerber": {"tlds": [".com", ".net", ".org", ".biz", ".info", ".top", ".xyz"], "length": (10, 15), "entropy": (3.0, 4.0)},
    "jaff": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "trickbot": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (12, 18), "entropy": (3.5, 4.5)},
    "emotet": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "qakbot": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "icedid": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "bazarloader": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "pony": {"tlds": [".com", ".net", ".org"], "length": (10, 15), "entropy": (3.0, 4.0)},
    "zeus": {"tlds": [".com", ".net", ".org", ".biz", ".info"], "length": (12, 18), "entropy": (3.5, 4.5)},
    "citadel": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
    "dridex": {"tlds": [".com", ".net", ".org"], "length": (12, 18), "entropy": (3.5, 4.5)},
    "ursnif": {"tlds": [".com", ".net", ".org"], "length": (12, 16), "entropy": (3.5, 4.5)},
}


def extract_domain_features(domain: str) -> dict:
    """Extract numerical features from domain for ML classification."""
    # Remove TLD for subdomain analysis
    parts = domain.split(".")
    if len(parts) > 1:
        subdomain = ".".join(parts[:-1])
        tld = parts[-1]
    else:
        subdomain = domain
        tld = ""
    
    features = {}
    for name, func in _DGA_FEATURES.items():
        try:
            features[name] = func(subdomain)
        except Exception:
            features[name] = 0
    
    features["tld"] = tld
    features["is_ip"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) else 0
    
    return features


def classify_dga(domain: str) -> dict:
    """
    Classify domain as DGA or legitimate using heuristic rules.
    In production, this would use a trained ML model.
    """
    features = extract_domain_features(domain)
    
    # Heuristic scoring
    score = 0
    reasons = []
    
    # High entropy
    if features.get("entropy", 0) > 3.5:
        score += 30
        reasons.append(f"High entropy: {features['entropy']:.2f}")
    
    # Long domain
    if features.get("length", 0) > 15:
        score += 20
        reasons.append(f"Long domain: {features['length']} chars")
    
    # High digit ratio
    if features.get("digit_ratio", 0) > 0.3:
        score += 15
        reasons.append(f"High digit ratio: {features['digit_ratio']:.2f}")
    
    # Hex-like
    if features.get("hex_ratio", 0) > 0.5:
        score += 20
        reasons.append(f"Hex-like characters: {features['hex_ratio']:.2f}")
    
    # Low vowel ratio
    if features.get("vowel_ratio", 0) < 0.2:
        score += 15
        reasons.append(f"Low vowel ratio: {features['vowel_ratio']:.2f}")
    
    # Many consecutive consonants
    if features.get("max_consecutive_consonants", 0) > 5:
        score += 10
        reasons.append(f"Consecutive consonants: {features['max_consecutive_consonants']}")
    
    # Known DGA TLDs
    tld = features.get("tld", "")
    dga_tlds = [".bit", ".top", ".xyz", ".pw", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq"]
    if f".{tld}" in dga_tlds:
        score += 25
        reasons.append(f"DGA-associated TLD: .{tld}")
    
    # Multiple subdomains
    if features.get("subdomain_count", 0) > 3:
        score += 10
        reasons.append(f"Multiple subdomains: {features['subdomain_count']}")
    
    # Match against known families
    matched_families = []
    for family, info in _DGA_FAMILIES.items():
        tlds = info.get("tlds", [])
        if tlds and f".{tld}" in tlds:
            length_range = info.get("length", (0, 100))
            entropy_range = info.get("entropy", (0, 5))
            if length_range[0] <= features.get("length", 0) <= length_range[1]:
                if entropy_range[0] <= features.get("entropy", 0) <= entropy_range[1]:
                    matched_families.append(family)
    
    if matched_families:
        score += 30
        reasons.append(f"Matches known DGA families: {', '.join(matched_families)}")
    
    is_dga = score >= 50
    
    return {
        "is_dga": is_dga,
        "score": score,
        "features": features,
        "reasons": reasons,
        "matched_families": matched_families,
        "confidence": min(score / 100, 1.0) if is_dga else 0,
    }


# ──────────────────────────────────────────────────────────────────────────────
# C2 Protocol Parsers
# ──────────────────────────────────────────────────────────────────────────────

def parse_c2_traffic(flow: NetworkFlow) -> list[dict]:
    """Attempt to parse known C2 protocols from flow data."""
    results = []
    
    # HTTP-based C2
    if flow.http_host and flow.http_uri:
        http_result = parse_http_c2(flow)
        if http_result:
            results.append(http_result)
    
    # DNS-based C2
    if flow.dns_queries:
        dns_result = parse_dns_c2(flow)
        if dns_result:
            results.append(dns_result)
    
    # Custom TCP protocols
    if flow.protocol == "TCP" and flow.bytes_sent > 0:
        tcp_result = parse_custom_tcp_c2(flow)
        if tcp_result:
            results.append(tcp_result)
    
    return results


def parse_http_c2(flow: NetworkFlow) -> dict | None:
    """Parse HTTP-based C2 traffic."""
    # Check for known C2 framework patterns
    for framework, info in _C2_FRAMEWORKS.items():
        matches = 0
        indicators = []
        
        # Check URIs
        for uri in info.get("uris", []):
            if uri in flow.http_uri:
                matches += 1
                indicators.append(f"uri:{uri}")
        
        # Check User-Agent
        for ua in info.get("user_agents", []):
            if ua.lower() in flow.http_user_agent.lower():
                matches += 1
                indicators.append(f"ua:{ua}")
        
        # Check headers
        for header, val in info.get("headers", {}).items():
            if val and val in flow.http_host:
                matches += 1
                indicators.append(f"header:{header}")
        
        if matches >= 2:
            return {
                "protocol": "HTTP",
                "framework": framework,
                "matches": matches,
                "indicators": indicators,
                "confidence": min(0.5 + matches * 0.15, 0.95),
            }
    
    # Generic suspicious HTTP patterns
    suspicious_patterns = [
        (r"/gate\.php", "PHP gate"),
        (r"/submit\.php", "PHP submit"),
        (r"/admin\.php", "Admin panel"),
        (r"/api/v\d+/", "API endpoint"),
        (r"/beacon", "Beacon endpoint"),
        (r"/checkin", "Check-in endpoint"),
        (r"/task", "Task endpoint"),
        (r"/download", "Download endpoint"),
        (r"/upload", "Upload endpoint"),
    ]
    
    for pattern, desc in suspicious_patterns:
        if re.search(pattern, flow.http_uri, re.IGNORECASE):
            return {
                "protocol": "HTTP",
                "framework": "Generic/Unknown",
                "pattern": pattern,
                "description": desc,
                "confidence": 0.4,
            }
    
    return None


def parse_dns_c2(flow: NetworkFlow) -> dict | None:
    """Parse DNS-based C2 (DNS tunneling, TXT records)."""
    for query in flow.dns_queries:
        qname = query.get("query", "")
        qtype = query.get("type", "A")
        
        # TXT record C2
        if qtype == "TXT":
            # Check for encoded data in TXT response
            answers = query.get("answers", [])
            for ans in answers:
                if len(ans) > 100:  # Suspiciously long TXT
                    return {
                        "protocol": "DNS",
                        "type": "TXT tunneling",
                        "query": qname,
                        "answer_length": len(ans),
                        "confidence": 0.7,
                    }
        
        # Subdomain encoding (data exfiltration)
        parts = qname.split(".")
        if len(parts) > 4:
            # Check if subdomains look encoded
            encoded_parts = [p for p in parts[:-2] if len(p) > 20 and re.match(r"^[A-Za-z0-9+/=]+$", p)]
            if len(encoded_parts) > 2:
                return {
                    "protocol": "DNS",
                    "type": "Subdomain encoding",
                    "query": qname,
                    "subdomain_count": len(parts) - 2,
                    "confidence": 0.6,
                }
        
        # High entropy subdomain
        subdomain = parts[0] if parts else ""
        if len(subdomain) > 15 and shannon_entropy(subdomain.encode()) > 3.5:
            return {
                "protocol": "DNS",
                "type": "High entropy subdomain",
                "query": qname,
                "entropy": round(shannon_entropy(subdomain.encode()), 3),
                "confidence": 0.5,
            }
    
    return None


def parse_custom_tcp_c2(flow: NetworkFlow) -> dict | None:
    """Parse custom TCP-based C2 protocols."""
    # Check for common C2 port patterns
    c2_ports = {
        443: "HTTPS/C2",
        8443: "Alt HTTPS/C2",
        8080: "HTTP Proxy/C2",
        80: "HTTP/C2",
        53: "DNS/C2",
        22: "SSH/C2",
        3389: "RDP/C2",
        5900: "VNC/C2",
    }
    
    port_desc = c2_ports.get(flow.dst_port, "")
    if port_desc:
        # Check for beaconing pattern
        if flow.duration > 60 and flow.packets_sent < 10:
            return {
                "protocol": "TCP",
                "type": "Potential beaconing",
                "port": flow.dst_port,
                "service": port_desc,
                "duration": flow.duration,
                "packet_count": flow.packets_sent + flow.packets_received,
                "confidence": 0.4,
            }
    
    # Check for fixed-size packets (heartbeat)
    if flow.packets_sent > 5:
        avg_size = flow.bytes_sent / flow.packets_sent
        if 10 <= avg_size <= 200:  # Typical heartbeat size
            return {
                "protocol": "TCP",
                "type": "Fixed-size packets (heartbeat)",
                "avg_packet_size": round(avg_size, 1),
                "packet_count": flow.packets_sent,
                "confidence": 0.3,
            }
    
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Beaconing Detection
# ──────────────────────────────────────────────────────────────────────────────

def detect_beaconing(flows: list[NetworkFlow], min_interval: float = 30, max_interval: float = 3600) -> list[dict]:
    """
    Detect beaconing patterns in network flows.
    
    Uses coefficient of variation (CV) and autocorrelation to identify
    periodic communication patterns.
    """
    beacons = []
    
    # Group flows by destination
    by_dst = {}
    for flow in flows:
        key = (flow.dst_ip, flow.dst_port)
        if key not in by_dst:
            by_dst[key] = []
        by_dst[key].append(flow)
    
    for (dst_ip, dst_port), dst_flows in by_dst.items():
        if len(dst_flows) < 3:
            continue
        
        # Sort by start time
        dst_flows.sort(key=lambda f: f.start_time)
        
        # Calculate intervals
        intervals = []
        for i in range(1, len(dst_flows)):
            interval = (dst_flows[i].start_time - dst_flows[i-1].start_time).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            continue
        
        # Statistical analysis
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval < min_interval or mean_interval > max_interval:
            continue
        
        # Coefficient of variation
        if HAS_NUMPY:
            cv = np.std(intervals) / mean_interval if mean_interval > 0 else 1
        else:
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            cv = (variance ** 0.5) / mean_interval if mean_interval > 0 else 1
        
        # Low CV indicates regular beaconing
        if cv < 0.3:
            # Calculate jitter
            jitter = max(intervals) - min(intervals)
            
            # Autocorrelation for periodicity
            autocorr = calculate_autocorrelation(intervals)
            
            beacons.append({
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "flow_count": len(dst_flows),
                "mean_interval": round(mean_interval, 2),
                "cv": round(cv, 4),
                "jitter": round(jitter, 2),
                "autocorr": round(autocorr, 4),
                "intervals": [round(i, 2) for i in intervals[:20]],
                "first_seen": dst_flows[0].start_time.isoformat(),
                "last_seen": dst_flows[-1].start_time.isoformat(),
                "confidence": max(0, 1 - cv) * min(autocorr + 0.5, 1),
            })
    
    return beacons


def calculate_autocorrelation(data: list[float], lag: int = 1) -> float:
    """Calculate autocorrelation at given lag."""
    if len(data) <= lag:
        return 0
    
    mean = sum(data) / len(data)
    numerator = sum((data[i] - mean) * (data[i + lag] - mean) for i in range(len(data) - lag))
    denominator = sum((x - mean) ** 2 for x in data)
    
    return numerator / denominator if denominator > 0 else 0


# ──────────────────────────────────────────────────────────────────────────────
# PCAP Analysis Main Function
# ──────────────────────────────────────────────────────────────────────────────

async def analyze_pcap_deep(pcap_path: Path) -> PcapAnalysisResult:
    """
    Deep PCAP analysis with full protocol parsing, TLS, HTTP, DNS,
    C2 detection, beaconing, and anomaly detection.
    """
    result = PcapAnalysisResult(
        pcap_path=str(pcap_path),
        file_size=pcap_path.stat().st_size,
    )
    
    try:
        import pyshark
    except ImportError:
        logger.exception("pyshark not installed, cannot analyze PCAP")
        result.anomalies.append({"type": "error", "message": "pyshark not installed"})
        return result
    
    # Open capture
    cap = pyshark.FileCapture(str(pcap_path))
    
    # First pass: collect basic stats
    packets = []
    for i, pkt in enumerate(cap):
        try:
            packets.append(pkt)
            if i >= 100000:  # Limit for performance
                break
        except Exception:
            continue
    
    if not packets:
        cap.close()
        return result
    
    result.packet_count = len(packets)
    result.start_time = datetime.fromisoformat(packets[0].sniff_time.isoformat()) if hasattr(packets[0], "sniff_time") else datetime.utcnow()
    result.end_time = datetime.fromisoformat(packets[-1].sniff_time.isoformat()) if hasattr(packets[-1], "sniff_time") else datetime.utcnow()
    result.duration = (result.end_time - result.start_time).total_seconds()
    
    # Process packets
    flows_dict = {}
    
    for pkt in packets:
        try:
            flow = _parse_packet(pkt)
            if flow:
                flow_key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.protocol)
                if flow_key not in flows_dict:
                    flows_dict[flow_key] = flow
                else:
                    # Merge into existing flow
                    existing = flows_dict[flow_key]
                    existing.bytes_sent += flow.bytes_sent
                    existing.bytes_received += flow.bytes_received
                    existing.packets_sent += flow.packets_sent
                    existing.packets_received += flow.packets_received
                    existing.end_time = max(existing.end_time, flow.end_time)
                    existing.duration = (existing.end_time - existing.start_time).total_seconds()
                    
                    # Merge HTTP/DNS/TLS data
                    if flow.http_host and not existing.http_host:
                        existing.http_host = flow.http_host
                    if flow.http_uri and not existing.http_uri:
                        existing.http_uri = flow.http_uri
                    if flow.http_user_agent and not existing.http_user_agent:
                        existing.http_user_agent = flow.http_user_agent
                    if flow.ja3 and not existing.ja3:
                        existing.ja3 = flow.ja3
                    if flow.ja3s and not existing.ja3s:
                        existing.ja3s = flow.ja3s
                    if flow.dns_queries:
                        existing.dns_queries.extend(flow.dns_queries)
        except Exception:
            continue
    
    result.flows = list(flows_dict.values())
    result.flow_count = len(result.flows)
    
    # Close capture
    cap.close()
    
    # ─── Post-processing ───
    
    # TLS Analysis
    result.tls_flows = [f for f in result.flows if f.ja3 or f.ja3s]
    for flow in result.tls_flows:
        if flow.ja3:
            ja3_info = lookup_ja3(flow.ja3)
            result.ja3_fingerprints.append({
                "ja3": flow.ja3,
                "flow_id": flow.flow_id,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                **ja3_info,
            })
        if flow.ja3s:
            ja3s_info = lookup_ja3s(flow.ja3s)
            result.ja3s_fingerprints.append({
                "ja3s": flow.ja3s,
                "flow_id": flow.flow_id,
                "src_ip": flow.src_ip,
                **ja3s_info,
            })
    
    # HTTP Analysis
    result.http_flows = [f for f in result.flows if f.http_host]
    for flow in result.http_flows:
        result.http_hosts.append(flow.http_host)
        result.http_uris.append(flow.http_uri)
        result.user_agents.append(flow.http_user_agent)
    
    # DNS Analysis
    result.dns_flows = [f for f in result.flows if f.dns_queries]
    for flow in result.dns_flows:
        for query in flow.dns_queries:
            result.dns_queries.append(query)
            # DGA check
            dga_result = classify_dga(query.get("query", ""))
            if dga_result["is_dga"]:
                result.dga_candidates.append({
                    "flow_id": flow.flow_id,
                    "query": query.get("query", ""),
                    **dga_result,
                })
    
    # C2 Detection
    for flow in result.flows:
        c2_results = parse_c2_traffic(flow)
        for c2 in c2_results:
            result.c2_candidates.append({
                "flow_id": flow.flow_id,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "dst_port": flow.dst_port,
                **c2,
            })
    
    # Beaconing Detection
    result.beaconing_flows = detect_beaconing(result.flows)
    
    # Statistics
    result.protocol_distribution = _calculate_protocol_distribution(result.flows)
    result.port_distribution = _calculate_port_distribution(result.flows)
    result.top_talkers = _calculate_top_talkers(result.flows)
    result.top_connections = _calculate_top_connections(result.flows)
    result.entropy_analysis = _calculate_entropy_analysis(result.flows)
    
    # Anomalies
    result.anomalies = _detect_anomalies(result.flows)
    
    # MITRE Techniques
    result.mitre_techniques = _map_network_to_mitre(result)
    
    # Extract certificates
    result.certificates = extract_tls_certificates(pcap_path)
    
    return result


def _parse_packet(pkt) -> NetworkFlow | None:
    """Parse a single packet into a NetworkFlow."""
    try:
        # Basic IP/port info
        if hasattr(pkt, "ip"):
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
        elif hasattr(pkt, "ipv6"):
            src_ip = pkt.ipv6.src
            dst_ip = pkt.ipv6.dst
        else:
            return None
        
        # Protocol and ports
        protocol = "UNKNOWN"
        src_port = 0
        dst_port = 0
        
        if hasattr(pkt, "tcp"):
            protocol = "TCP"
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            protocol = "UDP"
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)
        elif hasattr(pkt, "icmp"):
            protocol = "ICMP"
        else:
            return None
        
        # Timestamps
        sniff_time = getattr(pkt, "sniff_time", datetime.utcnow())
        if isinstance(sniff_time, str):
            start_time = datetime.fromisoformat(sniff_time)
        else:
            start_time = sniff_time
        
        # Lengths
        length = int(getattr(pkt, "length", 0))
        
        flow = NetworkFlow(
            flow_id=hashlib.sha256(f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}".encode()).hexdigest()[:16],
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            start_time=start_time,
            end_time=start_time,
            duration=0,
            bytes_sent=length if "src" in str(pkt) else 0,
            bytes_received=length if "dst" in str(pkt) else 0,
            packets_sent=1,
            packets_received=1,
        )
        
        # TLS
        if hasattr(pkt, "tls") or hasattr(pkt, "ssl"):
            _parse_tls(pkt, flow)
        
        # HTTP
        if hasattr(pkt, "http"):
            _parse_http(pkt, flow)
        
        # DNS
        if hasattr(pkt, "dns"):
            _parse_dns(pkt, flow)
        
        return flow
        
    except Exception as exc:
        logger.debug(f"Packet parsing failed: {exc}")
        return None


def _parse_tls(pkt, flow: NetworkFlow):
    """Parse TLS/SSL data from packet."""
    try:
        # Try both tls and ssl layer names
        tls_layer = getattr(pkt, "tls", None) or getattr(pkt, "ssl", None)
        if not tls_layer:
            return
        
        # JA3/JA3S
        if hasattr(tls_layer, "handshake_ja3_full"):
            flow.ja3 = tls_layer.handshake_ja3_full
        if hasattr(tls_layer, "handshake_ja3s_full"):
            flow.ja3s = tls_layer.handshake_ja3s_full
        
        # Version
        if hasattr(tls_layer, "handshake_version"):
            version_map = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
            flow.tls_version = version_map.get(int(tls_layer.handshake_version), f"Unknown({tls_layer.handshake_version})")
        
        # Cipher suite
        if hasattr(tls_layer, "handshake_ciphersuite"):
            flow.cipher_suite = tls_layer.handshake_ciphersuite
        
        # SNI
        if hasattr(tls_layer, "handshake_extensions_server_name"):
            flow.sni = tls_layer.handshake_extensions_server_name
        
    except Exception:
        pass


def _parse_http(pkt, flow: NetworkFlow):
    """Parse HTTP data from packet."""
    try:
        http = pkt.http
        if hasattr(http, "host"):
            flow.http_host = http.host
        if hasattr(http, "request_uri"):
            flow.http_uri = http.request_uri
        if hasattr(http, "request_method"):
            flow.http_method = http.request_method
        if hasattr(http, "user_agent"):
            flow.http_user_agent = http.user_agent
        if hasattr(http, "response_code"):
            flow.http_status = int(http.response_code)
        if hasattr(http, "content_type"):
            flow.http_content_type = http.content_type
    except Exception:
        pass


def _parse_dns(pkt, flow: NetworkFlow):
    """Parse DNS data from packet."""
    try:
        dns = pkt.dns
        if hasattr(dns, "qry_name"):
            query = {
                "query": dns.qry_name,
                "type": getattr(dns, "qry_type", "A"),
                "answers": [],
            }
            if hasattr(dns, "resp_name"):
                query["answers"].append(dns.resp_name)
            if hasattr(dns, "resp_addr"):
                query["answers"].append(dns.resp_addr)
            flow.dns_queries.append(query)
    except Exception:
        pass


def _calculate_protocol_distribution(flows: list[NetworkFlow]) -> dict:
    dist = Counter()
    for f in flows:
        dist[f.protocol] += 1
    return dict(dist)


def _calculate_port_distribution(flows: list[NetworkFlow]) -> dict:
    dist = Counter()
    for f in flows:
        dist[f.dst_port] += 1
    return dict(dist.most_common(50))


def _calculate_top_talkers(flows: list[NetworkFlow]) -> list[dict]:
    ip_bytes = Counter()
    for f in flows:
        ip_bytes[f.src_ip] += f.bytes_sent
        ip_bytes[f.dst_ip] += f.bytes_received
    return [{"ip": ip, "bytes": bytes_} for ip, bytes_ in ip_bytes.most_common(20)]


def _calculate_top_connections(flows: list[NetworkFlow]) -> list[dict]:
    conn_bytes = Counter()
    for f in flows:
        key = f"{f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port} ({f.protocol})"
        conn_bytes[key] += f.bytes_sent + f.bytes_received
    return [{"connection": conn, "bytes": bytes_} for conn, bytes_ in conn_bytes.most_common(20)]


def _calculate_entropy_analysis(flows: list[NetworkFlow]) -> dict:
    """Calculate entropy statistics for flows."""
    entropies = []
    for f in flows:
        # Payload entropy would need raw packet data
        # For now, use proxy metrics
        if f.bytes_sent > 0 and f.packets_sent > 0:
            avg_size = f.bytes_sent / f.packets_sent
            entropies.append(min(avg_size / 100, 8))  # Rough proxy
    
    if not entropies:
        return {}
    
    return {
        "mean": round(sum(entropies) / len(entropies), 3),
        "max": round(max(entropies), 3),
        "min": round(min(entropies), 3),
        "high_entropy_flows": sum(1 for e in entropies if e > 6),
    }


def _detect_anomalies(flows: list[NetworkFlow]) -> list[dict]:
    anomalies = []
    
    for f in flows:
        # Long-lived connections with little data
        if f.duration > 3600 and (f.bytes_sent + f.bytes_received) < 1000:
            anomalies.append({
                "type": "long_idle_connection",
                "flow_id": f.flow_id,
                "duration": f.duration,
                "bytes": f.bytes_sent + f.bytes_received,
            })
        
        # High frequency small packets (potential beaconing)
        if f.packets_sent > 100 and f.bytes_sent / f.packets_sent < 50:
            anomalies.append({
                "type": "high_freq_small_packets",
                "flow_id": f.flow_id,
                "avg_packet_size": round(f.bytes_sent / f.packets_sent, 1),
            })
        
        # Non-standard ports for common protocols
        if f.dst_port not in [80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 587, 3389, 5900] and f.protocol == "TCP":
            if f.bytes_sent > 10000:  # Significant traffic on non-standard port
                anomalies.append({
                    "type": "non_standard_port",
                    "flow_id": f.flow_id,
                    "port": f.dst_port,
                    "bytes": f.bytes_sent,
                })
        
        # Self-signed certificates
        if f.cert_fingerprint and "self_signed" in str(f.cert_chain).lower():
            anomalies.append({
                "type": "self_signed_cert",
                "flow_id": f.flow_id,
                "dst_ip": f.dst_ip,
            })
        
        # Expired certificates
        for cert in f.cert_chain:
            if cert.get("is_expired"):
                anomalies.append({
                    "type": "expired_certificate",
                    "flow_id": f.flow_id,
                    "dst_ip": f.dst_ip,
                    "cert_fingerprint": cert.get("sha256_fingerprint"),
                })
    
    return anomalies


def _map_network_to_mitre(result: PcapAnalysisResult) -> list[str]:
    techniques = set()
    
    # Base network communication
    if result.flow_count > 0:
        techniques.add("T1071")  # Application Layer Protocol
    
    if result.tls_flows:
        techniques.add("T1573.001")  # Encrypted Channel: Symmetric Cryptography
    
    if result.http_flows:
        techniques.add("T1071.001")  # Web Protocols
    
    if result.dns_flows:
        techniques.add("T1071.004")  # DNS
    
    if result.beaconing_flows:
        techniques.add("T1071.001")
        techniques.add("T1573.001")
    
    if result.c2_candidates:
        techniques.add("T1071")
        techniques.add("T1105")  # Ingress Tool Transfer
    
    if result.dga_candidates:
        techniques.add("T1568.002")  # Domain Generation Algorithms
    
    for c2 in result.c2_candidates:
        fw = c2.get("framework", "")
        if fw in {"Cobalt Strike", "Sliver"}:
            techniques.update(["T1055", "T1059", "T1071", "T1105", "T1573"])
        elif fw == "Metasploit":
            techniques.update(["T1055", "T1059", "T1071", "T1105"])
        elif fw in ["Mythic", "Brute Ratel", "Havoc"]:
            techniques.update(["T1055", "T1059", "T1071", "T1105", "T1573"])
        elif fw in ["PoshC2", "Empire"]:
            techniques.update(["T1059.001", "T1071", "T1105"])
    
    return sorted(techniques)


# ──────────────────────────────────────────────────────────────────────────────
# Backward Compatibility
# ──────────────────────────────────────────────────────────────────────────────

def analyze_pcap(file_path: Path) -> dict:
    """Backward compatible PCAP analysis."""
    import asyncio
    try:
        result = asyncio.run(analyze_pcap_deep(file_path))
        return {
            "flows": [
                {
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "bytes": f.bytes_sent + f.bytes_received,
                }
                for f in result.flows
            ],
            "dns_queries": result.dns_queries,
            "http_hosts": result.http_hosts,
            "ja3_fingerprints": result.ja3_fingerprints,
            "c2_candidates": result.c2_candidates,
            "beaconing": result.beaconing_flows,
        }
    except Exception as exc:
        return {"error": str(exc), "available": False}