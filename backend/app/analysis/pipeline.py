"""
Static analysis pipeline orchestrator.

Runs every stage in sequence on an uploaded sample and returns a single
structured report. Each stage is defensive — a failure in one parser
(e.g. a corrupt PE) never takes down the whole pipeline.
"""
from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from app.analysis import (
    apk_analysis,
    apk_deep_analysis,
    elf_analysis,
    elf_deep_analysis,
    filetype,
    hashing,
    ioc_extraction,
    macho_analysis,
    macho_deep_analysis,
    ole_analysis,
    pe_analysis,
    pe_deep_analysis,
    risk_scoring,
    script_analysis,
    strings_entropy,
    yara_scanner,
)

logger = logging.getLogger("malinfo.pipeline")


def run_static_analysis(file_path: Path) -> dict:
    """
    Full static-analysis pass. Returns a dict shaped for direct storage in
    Sample.static_report and consumption by the report generator.
    """
    started = dt.datetime.utcnow()

    hashes = hashing.compute_hashes(file_path)
    hashes["ssdeep"] = hashing.compute_ssdeep(file_path)

    ident = filetype.identify_file(file_path)
    entropy = strings_entropy.file_entropy(file_path)
    strings_result = strings_entropy.extract_strings(file_path)
    yara_result = yara_scanner.scan_file(file_path)

    iocs = ioc_extraction.extract_iocs_from_strings(strings_result["sample"])
    c2_candidates = ioc_extraction.flag_likely_c2(iocs)
    iocs.extend(c2_candidates)

    format_specific = _run_format_specific(file_path, ident["target_os"], ident["file_type"])

    report = {
        "hashes": hashes,
        "file_type": ident["file_type"],
        "mime_type": ident["mime_type"],
        "target_os": ident["target_os"],
        "entropy": entropy,
        "entropy_verdict": strings_entropy.entropy_verdict(entropy),
        "strings": {
            "total_extracted": strings_result["total_extracted"],
            "truncated": strings_result["truncated"],
            # Full string dump is large — keep top N in the report, store
            # the rest to disk if you need forensic completeness.
            "sample": strings_result["sample"][:300],
        },
        "yara": yara_result,
        "format_specific": format_specific,
        "iocs": iocs,
        "analysis_duration_sec": round((dt.datetime.utcnow() - started).total_seconds(), 3),
        "analyzed_at": started.isoformat() + "Z",
    }

    scoring = risk_scoring.score_static_report(report)
    report["risk_score"] = scoring["risk_score"]
    report["verdict"] = scoring["verdict"]
    report["risk_reasons"] = scoring["reasons"]

    return report


def _run_format_specific(file_path: Path, target_os: str, file_type: str) -> dict:
    result: dict = {}
    try:
        if target_os == "windows" and "PE" in file_type:
            # Use deep PE analysis for comprehensive results
            result["pe"] = pe_deep_analysis.analyze_pe_deep(file_path)
            # Also keep legacy format for backward compatibility
            result["pe_legacy"] = pe_analysis.analyze_pe(file_path)
        elif target_os == "linux" and "ELF" in file_type:
            result["elf"] = elf_deep_analysis.analyze_elf_deep(file_path)
            result["elf_legacy"] = elf_analysis.analyze_elf(file_path)
        elif target_os == "android":
            result["apk"] = apk_deep_analysis.analyze_apk_deep(file_path)
            result["apk_legacy"] = apk_analysis.analyze_apk(file_path)
        elif target_os == "macos":
            result["macho"] = macho_deep_analysis.analyze_macho_deep(file_path)
            result["macho_legacy"] = macho_analysis.analyze_macho(file_path)
        elif "OLE" in file_type or "Office" in file_type or "PDF" in file_type or "RTF" in file_type:
            result["ole"] = ole_analysis.analyze_ole_document(file_path)
        elif "Script" in file_type or file_path.suffix.lower() in (
            ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".js", ".jse", 
            ".vbs", ".vbe", ".wsf", ".hta", ".py", ".pyw", ".sh", ".bash"
        ):
            result["script"] = script_analysis.analyze_script(file_path)
    except Exception as exc:
        logger.exception("Format-specific analysis failed")
        result["error"] = str(exc)
    return result
