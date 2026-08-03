"""
Indicator-of-Compromise extraction from strings / network artifacts.

This is deliberately conservative: regex-based extraction produces false
positives (a version number can look like an IP). Every IOC is emitted with
a confidence score and a `context` snippet so a human analyst — or a
downstream automated correlation step against threat-intel feeds — makes
the final call rather than the tool asserting certainty it doesn't have.
"""
from __future__ import annotations

import re

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|xyz|top|ru|cn|tk|cc|io|onion|gov|edu|in|co|me|club|site|online|link)\b",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

# Registry-run keys / persistence locations frequently referenced by malware
_REGISTRY_RE = re.compile(
    r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"']+", re.IGNORECASE
)

# Well-known benign infra we deliberately downweight to cut obvious noise
# (this is NOT an allowlist for skipping analysis — just a confidence hint).
_LOW_VALUE_DOMAINS = {
    "schemas.microsoft.com", "schemas.openxmlformats.org", "www.w3.org",
    "xmlns.com", "ns.adobe.com", "microsoft.com", "apple.com",
}
_PRIVATE_IP_RE = re.compile(
    r"^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)"
)


def _confidence_for_domain(domain: str) -> float:
    if domain.lower() in _LOW_VALUE_DOMAINS:
        return 0.1
    if domain.count(".") >= 3 or any(ch.isdigit() for ch in domain.split(".")[0]):
        return 0.6  # subdomain depth / numeric labels correlate with DGA-style C2
    return 0.4


def extract_iocs_from_strings(strings: list[str]) -> list[dict]:
    iocs: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add(ioc_type: str, value: str, context: str, confidence: float) -> None:
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        iocs.append({
            "ioc_type": ioc_type,
            "value": value,
            "context": context[:200],
            "confidence": round(confidence, 2),
        })

    for s in strings:
        for m in _URL_RE.finditer(s):
            _add("url", m.group(), s, 0.7)
        for m in _IPV4_RE.finditer(s):
            ip = m.group()
            if _PRIVATE_IP_RE.match(ip):
                continue  # private/loopback ranges are near-certainly noise, not C2
            _add("ip", ip, s, 0.55)
        for m in _EMAIL_RE.finditer(s):
            _add("email", m.group(), s, 0.3)
        for m in _REGISTRY_RE.finditer(s):
            _add("registry_key", m.group(), s, 0.5)
        for m in _DOMAIN_RE.finditer(s):
            domain = m.group().rstrip(".")
            _add("domain", domain, s, _confidence_for_domain(domain))

    # Sort highest-confidence first so a triaging analyst sees the most
    # actionable indicators immediately.
    iocs.sort(key=lambda i: i["confidence"], reverse=True)
    return iocs


def flag_likely_c2(iocs: list[dict]) -> list[dict]:
    """
    Promote IP/URL/domain IOCs that co-occur with strong contextual signals
    (raw socket API names, beacon-style paths, known C2 framework markers)
    to an explicit `c2` classification. This is a heuristic pre-filter, not
    a verdict — always cross-reference against threat intel (VT/OTX/AbuseIPDB)
    before publishing attribution in a report.
    """
    c2_context_markers = (
        "cmd.exe", "powershell", "/gate.php", "/panel", "beacon", "checkin",
        "c2", "wmic", "reg add", "schtasks", "InternetOpen", "WinExec",
        "CreateRemoteThread", "VirtualAllocEx", "curl -s", "wget ",
    )
    promoted = []
    for ioc in iocs:
        if ioc["ioc_type"] not in ("ip", "url", "domain"):
            continue
        ctx = (ioc.get("context") or "").lower()
        if any(marker.lower() in ctx for marker in c2_context_markers):
            promoted.append({**ioc, "ioc_type": "c2_candidate", "confidence": min(1.0, ioc["confidence"] + 0.25)})
    return promoted
