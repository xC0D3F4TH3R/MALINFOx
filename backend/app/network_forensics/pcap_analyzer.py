"""
PCAP-based network forensics.

Parses a packet capture (from a sandbox detonation or a submitted PCAP)
and extracts connection metadata, DNS queries, and HTTP host headers —
the raw material for C2 identification. Built on `scapy`, which is pure
Python and requires no external capture-format dependency.
"""
from __future__ import annotations

import itertools
import logging
from collections import Counter, defaultdict
from pathlib import Path

logger = logging.getLogger("malinfo.network_forensics")

_PRIVATE_PREFIXES = ("10.", "127.", "169.254.", "192.168.")


def _is_private_ip(ip: str) -> bool:
    if ip.startswith(_PRIVATE_PREFIXES):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def analyze_pcap(pcap_path: Path) -> dict:
    try:
        from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap
    except ImportError:
        return {"available": False, "error": "scapy not installed"}

    if not pcap_path.exists():
        return {"available": False, "error": f"PCAP not found: {pcap_path}"}

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        return {"available": False, "error": f"Failed to read PCAP: {exc}"}

    connections: Counter = Counter()
    dns_queries: list[str] = []
    external_ips: set[str] = set()
    http_hosts: list[str] = []
    timestamps_by_dest: defaultdict[str, list[float]] = defaultdict(list)
    total_bytes = 0

    for pkt in packets:
        total_bytes += len(pkt)

        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
            if not _is_private_ip(dst):
                external_ips.add(dst)
                timestamps_by_dest[dst].append(float(pkt.time))
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
            connections[(src, dst, proto)] += 1

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                dns_queries.append(qname)
            except Exception:
                pass

        if pkt.haslayer(Raw):
            try:
                payload = bytes(pkt[Raw]).decode(errors="ignore")
                if payload.startswith(("GET ", "POST ", "CONNECT ")):
                    for line in payload.split("\r\n"):
                        if line.lower().startswith("host:"):
                            http_hosts.append(line.split(":", 1)[1].strip())
            except Exception:
                pass

    beaconing = _detect_beaconing(timestamps_by_dest)

    return {
        "available": True,
        "packet_count": len(packets),
        "total_bytes": total_bytes,
        "unique_external_ips": sorted(external_ips),
        "top_connections": [
            {"src": s, "dst": d, "proto": p, "packet_count": c}
            for (s, d, p), c in connections.most_common(20)
        ],
        "dns_queries": sorted(set(dns_queries)),
        "http_hosts": sorted(set(http_hosts)),
        "beaconing_detected": beaconing["detected"],
        "beaconing_candidates": beaconing["candidates"],
    }


def _detect_beaconing(timestamps_by_dest: dict[str, list[float]], min_events: int = 5, jitter_tolerance: float = 0.15) -> dict:
    """
    Flags destinations contacted at suspiciously regular intervals — the
    classic signature of C2 check-in ("beaconing") behaviour, as opposed to
    the bursty, irregular pattern of normal human/browser traffic.
    """
    candidates = []
    for dest, times in timestamps_by_dest.items():
        if len(times) < min_events:
            continue
        times = sorted(times)
        intervals = [t2 - t1 for t1, t2 in itertools.pairwise(times) if (t2 - t1) > 0]
        if len(intervals) < min_events - 1:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        stddev = variance ** 0.5
        coefficient_of_variation = stddev / mean_interval
        if coefficient_of_variation <= jitter_tolerance:
            candidates.append({
                "destination": dest,
                "event_count": len(times),
                "mean_interval_sec": round(mean_interval, 2),
                "regularity_score": round(1 - coefficient_of_variation, 3),
            })

    candidates.sort(key=lambda c: c["regularity_score"], reverse=True)
    return {"detected": len(candidates) > 0, "candidates": candidates}
