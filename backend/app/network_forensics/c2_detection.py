"""
C2 (command-and-control) server detail extraction.

Correlates network-forensics output (beaconing destinations, DNS queries,
HTTP hosts) with static-analysis IOCs to build the "C2 server details"
section of the final report: IP, associated domain(s), protocol, first/last
seen, and the confidence basis for the call.
"""
from __future__ import annotations


def extract_c2_details(network_report: dict, static_iocs: list[dict]) -> list[dict]:
    if not network_report.get("available"):
        return []

    c2_entries: list[dict] = []
    static_c2_values = {i["value"] for i in static_iocs if i["ioc_type"] == "c2_candidate"}
    dns_queries = set(network_report.get("dns_queries", []))
    http_hosts = set(network_report.get("http_hosts", []))

    for beacon in network_report.get("beaconing_candidates", []):
        dest = beacon["destination"]
        confidence = 0.5 + (beacon["regularity_score"] * 0.4)  # regularity alone gets you to ~0.9 max

        associated_domains = [
            d for d in dns_queries | http_hosts
            if d and (True)  # domains resolved during this session are relevant context
        ]

        reasons = [(f"Periodic beaconing to {dest} (regularity {beacon['regularity_score']}, "
                   f"{beacon['event_count']} check-ins, ~{beacon['mean_interval_sec']}s interval)")]
        if dest in static_c2_values:
            confidence = min(1.0, confidence + 0.2)
            reasons.append("IP also flagged as C2 candidate during static string analysis")

        c2_entries.append({
            "ip": dest,
            "associated_domains": associated_domains[:10],
            "check_in_count": beacon["event_count"],
            "mean_interval_sec": beacon["mean_interval_sec"],
            "confidence": round(confidence, 2),
            "reasons": reasons,
        })

    # Any static C2 candidate NOT already captured via beaconing still
    # belongs in the report — just at lower confidence since it lacks
    # network-layer corroboration.
    captured_ips = {e["ip"] for e in c2_entries}
    for value in static_c2_values:
        if value not in captured_ips:
            c2_entries.append({
                "ip": value if _looks_like_ip(value) else None,
                "domain": value if not _looks_like_ip(value) else None,
                "associated_domains": [],
                "check_in_count": None,
                "mean_interval_sec": None,
                "confidence": 0.4,
                "reasons": ["Identified via static string/context analysis only — no network corroboration available"],
            })

    c2_entries.sort(key=lambda e: e["confidence"], reverse=True)
    return c2_entries


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
