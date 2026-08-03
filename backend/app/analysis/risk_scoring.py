"""
Composite risk scoring.

Combines YARA hits, entropy, suspicious API/symbol usage, IOC confidence,
and (when available) sandbox/network findings into a single 0-100 score
and a human-readable verdict. Weights are configurable and should be tuned
against a labelled dataset before relying on this for automated blocking
decisions — out of the box this is meant for triage prioritization, not a
sole source of truth.
"""
from __future__ import annotations

_YARA_SEVERITY_WEIGHTS = {"low": 5, "medium": 12, "high": 22, "critical": 35}


def score_static_report(report: dict) -> dict:
    score = 0.0
    reasons: list[str] = []

    # --- YARA matches ---------------------------------------------------------
    yara = report.get("yara", {})
    for match in yara.get("matches", []):
        severity = (match.get("meta", {}) or {}).get("severity", "low")
        weight = _YARA_SEVERITY_WEIGHTS.get(severity, 5)
        score += weight
        reasons.append(f"YARA rule '{match['rule']}' matched ({severity} severity)")

    # --- Entropy ----------------------------------------------------------
    entropy = report.get("entropy", 0)
    if entropy >= 7.5:
        score += 15
        reasons.append(f"Very high file entropy ({entropy}) — likely packed or encrypted")
    elif entropy >= 6.8:
        score += 7
        reasons.append(f"Elevated file entropy ({entropy}) — possibly packed/compressed")

    # --- Format-specific findings -------------------------------------------
    fmt = report.get("format_specific", {})

    pe = fmt.get("pe")
    if pe and pe.get("available"):
        n_susp = len(pe.get("suspicious_api_calls", []))
        if n_susp:
            score += min(20, n_susp * 3)
            reasons.append(f"{n_susp} suspicious Windows API import(s): {', '.join(pe['suspicious_api_calls'][:6])}")
        if pe.get("packer_indicators"):
            score += 8
            reasons.append("Packer/obfuscation indicators in PE sections")
        if not pe.get("has_authenticode_signature"):
            score += 3
            reasons.append("No Authenticode digital signature")
        if pe.get("has_overlay_data"):
            score += 5
            reasons.append("Overlay data present after last section (possible embedded payload)")

    elf = fmt.get("elf")
    if elf and elf.get("available"):
        if elf.get("suspicious_symbols"):
            score += min(15, len(elf["suspicious_symbols"]) * 3)
            reasons.append(f"Suspicious ELF dynamic symbols: {', '.join(elf['suspicious_symbols'])}")
        if elf.get("is_stripped"):
            score += 3
            reasons.append("ELF binary is stripped (symbol table removed)")

    apk = fmt.get("apk")
    if apk and apk.get("available"):
        n_high_risk = len(apk.get("high_risk_permissions", []))
        if n_high_risk:
            score += min(20, n_high_risk * 3)
            reasons.append(f"{n_high_risk} high-risk Android permission(s) requested")
        if not apk.get("is_signed"):
            score += 5
            reasons.append("APK is not signed")
        if apk.get("files_of_interest"):
            score += 6
            reasons.append("Secondary DEX/SO/JAR payloads bundled inside APK (possible dropper)")

    # --- IOCs -----------------------------------------------------------------
    iocs = report.get("iocs", [])
    c2_candidates = [i for i in iocs if i["ioc_type"] == "c2_candidate"]
    if c2_candidates:
        score += min(20, len(c2_candidates) * 8)
        reasons.append(f"{len(c2_candidates)} candidate C2 indicator(s) extracted from strings")

    score = max(0.0, min(100.0, score))
    verdict = _verdict_from_score(score)

    return {"risk_score": round(score, 1), "verdict": verdict, "reasons": reasons}


def _verdict_from_score(score: float) -> str:
    if score >= 60:
        return "malicious"
    if score >= 25:
        return "suspicious"
    if score > 0:
        return "suspicious"
    return "clean"


def merge_dynamic_score(static_result: dict, sandbox_report: dict | None, network_report: dict | None) -> dict:
    """Blend static score with dynamic (sandbox) and network-forensics signal, once available."""
    score = static_result["risk_score"]
    reasons = list(static_result["reasons"])

    if sandbox_report:
        sb_score = sandbox_report.get("malscore", 0)  # CAPEv2-style 0-10 malscore
        score += min(30, sb_score * 3)
        for sig in sandbox_report.get("signatures", [])[:10]:
            reasons.append(f"Sandbox signature: {sig}")

    if network_report:
        if network_report.get("c2_candidates"):
            score += min(20, len(network_report["c2_candidates"]) * 6)
            reasons.append(f"{len(network_report['c2_candidates'])} network-layer C2 candidate(s) identified")
        if network_report.get("beaconing_detected"):
            score += 10
            reasons.append("Periodic beaconing pattern detected in traffic capture")

    score = max(0.0, min(100.0, score))
    return {"risk_score": round(score, 1), "verdict": _verdict_from_score(score), "reasons": reasons}
