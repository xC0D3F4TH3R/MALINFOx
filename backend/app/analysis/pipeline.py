"""
Static analysis pipeline orchestrator.

Runs every stage in sequence on an uploaded sample and returns a single
structured report. Each stage is defensive — a failure in one parser
(e.g. a corrupt PE) never takes down the whole pipeline.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import TYPE_CHECKING

from app.analysis import (
    apk_analysis,
    apk_deep_analysis,
    crypto_detector,
    elf_analysis,
    elf_deep_analysis,
    filetype,
    hashing,
    ioc_extraction,
    macho_analysis,
    macho_deep_analysis,
    obfuscation_detector,
    ole_analysis,
    pe_analysis,
    pe_deep_analysis,
    risk_scoring,
    script_analysis,
    strings_entropy,
    yara_scanner,
)

if TYPE_CHECKING:
    from pathlib import Path

# NEW: Import new analysis modules
try:
    from app.analysis import archive_analysis
except ImportError:
    archive_analysis = None

try:
    from app.analysis import apple_analysis
except ImportError:
    apple_analysis = None

try:
    from app.analysis import disk_analysis
except ImportError:
    disk_analysis = None

try:
    from app.analysis import firmware_analysis
except ImportError:
    firmware_analysis = None

try:
    from app.analysis import email_analysis
except ImportError:
    email_analysis = None

try:
    from app.analysis import memory_analysis
except ImportError:
    memory_analysis = None

try:
    from app.analysis import java_analysis
except ImportError:
    java_analysis = None

try:
    from app.analysis import font_analysis
except ImportError:
    font_analysis = None

try:
    from app.analysis import image_analysis
except ImportError:
    image_analysis = None

try:
    from app.analysis import config_analysis
except ImportError:
    config_analysis = None

try:
    from app.analysis import database_analysis
except ImportError:
    database_analysis = None

try:
    from app.analysis import log_analysis
except ImportError:
    log_analysis = None

try:
    from app.analysis import crypto_analysis
except ImportError:
    crypto_analysis = None

try:
    from app.analysis import windows_forensics
except ImportError:
    windows_forensics = None

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
        # Existing handlers
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
        
        # NEW: Email - must come before OLE handler since MSG uses OLE format
        elif email_analysis and (
            "Email" in file_type or "EML" in file_type or "MSG" in file_type or
            file_path.suffix.lower() in (".eml", ".msg")
        ):
            result["email"] = email_analysis.analyze_email_file(file_path)
        
        # Documents
        elif "OLE" in file_type or "Office" in file_type or "PDF" in file_type or "RTF" in file_type:
            result["ole"] = ole_analysis.analyze_ole_document(file_path)
        
        # Scripts
        elif "Script" in file_type or file_path.suffix.lower() in (
            ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".js", ".jse",
            ".vbs", ".vbe", ".wsf", ".hta", ".py", ".pyw", ".sh", ".bash"
        ):
            result["script"] = script_analysis.analyze_script(file_path)

        # NEW: Archive handlers
        elif archive_analysis and (
            "ZIP" in file_type or "Archive" in file_type or "JAR" in file_type or
            "WAR" in file_type or "EAR" in file_type or "AAB" in file_type or
            "IPA" in file_type or "VSIX" in file_type or "XPI" in file_type or
            "EPUB" in file_type or "DOCX" in file_type or "XLSX" in file_type or
            "PPTX" in file_type or file_type in ["RAR", "7Z", "TAR", "GZIP", "BZIP2", "XZ", "ZSTD", "LZ4", "LZMA", "CAB", "CHM"] or
            file_path.suffix.lower() in (".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".ipa", ".vsix", ".xpi", ".epub",
                                         ".tar", ".gz", ".bz2", ".xz", ".zst", ".lz4", ".lzma", ".7z", ".rar", ".cab", ".chm",
                                         ".tgz", ".tbz2", ".txz", ".tlz4", ".tlzma")
        ):
            result["archive"] = archive_analysis.analyze_archive(file_path)

        # NEW: Disk images
        elif disk_analysis and (
            "Disk" in file_type or "ISO" in file_type or "VHD" in file_type or
            "VMDK" in file_type or "QCOW" in file_type or "Raw" in file_type or
            file_path.suffix.lower() in (".iso", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".qcow", ".img", ".raw", ".dd", ".dmg")
        ):
            result["disk"] = disk_analysis.analyze_disk_image(file_path)

        # NEW: Firmware - check magic bytes more carefully
        elif firmware_analysis and (
            "Firmware" in file_type or 
            file_path.suffix.lower() in (".fw", ".rom") or
            (file_path.suffix.lower() in (".bin", ".img") and (
                "U-Boot" in file_type or "BOOT" in file_type or 
                "FIT" in file_type or "ANDROID!" in file_type or
                "CHROMEOS" in file_type or "SquashFS" in file_type or
                "JFFS2" in file_type or "YAFFS" in file_type or
                "UBIFS" in file_type or "CRAMFS" in file_type or
                "EROFS" in file_type or "ROMFS" in file_type
            ))
        ):
            result["firmware"] = firmware_analysis.analyze_firmware_image(file_path)

        # NEW: Memory dumps
        elif memory_analysis and (
            "Memory" in file_type or "Dump" in file_type or "Hibernation" in file_type or
            "LIME" in file_type or "WinPMEM" in file_type or "VMware" in file_type or
            "VirtualBox" in file_type or "QEMU" in file_type or
            file_path.suffix.lower() in (".raw", ".mem", ".dmp", ".lime", ".pmem", ".vmsn", ".vmem")
        ):
            result["memory"] = memory_analysis.analyze_memory(file_path)

        # NEW: Java class files
        elif java_analysis and (
            "Java Class" in file_type or file_path.suffix.lower() == ".class"
        ):
            result["java"] = java_analysis.analyze_java(file_path)

        # NEW: Font files
        elif font_analysis and (
            "Font" in file_type or "TTF" in file_type or "OTF" in file_type or
            "WOFF" in file_type or
            file_path.suffix.lower() in (".ttf", ".otf", ".woff", ".woff2", ".ttc")
        ):
            result["font"] = font_analysis.analyze_font_file(file_path)

        # NEW: Image files
        elif image_analysis and (
            "Image" in file_type or "PNG" in file_type or "JPEG" in file_type or
            "JPG" in file_type or "GIF" in file_type or "BMP" in file_type or
            "TIFF" in file_type or "SVG" in file_type or "WEBP" in file_type or
            "JPEG XL" in file_type or
            file_path.suffix.lower() in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".svg", ".webp", ".jxl", ".ico")
        ):
            result["image"] = image_analysis.analyze_image_file(file_path)

        # NEW: Config files
        elif config_analysis and (
            "Config" in file_type or "JSON" in file_type or "YAML" in file_type or
            "XML" in file_type or "INI" in file_type or "TOML" in file_type or
            "Environment" in file_type or
            file_path.suffix.lower() in (".json", ".yaml", ".yml", ".xml", ".ini", ".cfg", ".conf", ".config", ".toml", ".env")
        ):
            result["config"] = config_analysis.analyze_config_file(file_path)

        # NEW: Database files
        elif database_analysis and (
            "Database" in file_type or "SQLite" in file_type or "MDB" in file_type or
            "ACCDB" in file_type or "Access" in file_type or
            file_path.suffix.lower() in (".sqlite", ".db", ".sqlite3", ".mdb", ".accdb")
        ):
            result["database"] = database_analysis.analyze_database_file(file_path)

        # NEW: Log files
        elif log_analysis and (
            "Log" in file_type or "EVTX" in file_type or "Sysmon" in file_type or
            "Zeek" in file_type or "Bro" in file_type or "Suricata" in file_type or
            "Eve" in file_type or
            file_path.suffix.lower() in (".evtx", ".log", ".txt", ".csv", ".tsv", ".eve.json", ".jsonl")
        ):
            result["log"] = log_analysis.analyze_log_file(file_path)

        # NEW: Crypto/Key files
        elif crypto_analysis and (
            "Certificate" in file_type or "Key" in file_type or "PEM" in file_type or
            "DER" in file_type or "PKCS" in file_type or "CSR" in file_type or
            file_path.suffix.lower() in (".pem", ".der", ".crt", ".cer", ".key", ".pfx", ".p12", ".csr", ".p7b", ".p7c", ".crl")
        ):
            result["crypto"] = crypto_analysis.analyze_crypto(file_path)

        # NEW: Windows forensics artifacts
        elif windows_forensics and (
            "LNK" in file_type or "Prefetch" in file_type or "Jump List" in file_type or
            "Amcache" in file_type or "Shimcache" in file_type or "SRUM" in file_type or
            "Registry Hive" in file_type or
            file_path.suffix.lower() in (".lnk", ".pf", ".hve", ".reg", ".dat", ".edb") or
            "automaticdestinations" in file_path.name.lower() or "customdestinations" in file_path.name.lower()
        ):
            result["windows_forensics"] = windows_forensics.analyze_windows_forensics(file_path)

        # NEW: Apple bundles (IPA, .app)
        elif apple_analysis and (
            "IPA" in file_type or "Apple" in file_type or "iOS" in file_type or
            file_path.suffix.lower() in (".ipa", ".app", ".framework", ".dylib")
        ):
            result["apple"] = apple_analysis.analyze_apple(file_path)

        # Generic binary fallback
        else:
            result["binary"] = _analyze_generic_binary(file_path)
    except Exception as exc:
        logger.exception("Format-specific analysis failed")
        result["error"] = str(exc)
    return result


def _analyze_generic_binary(file_path: Path) -> dict:
    """Generic binary analysis for unknown file types."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(8192)

        from app.analysis.strings_entropy import extract_strings, shannon_entropy

        entropy = round(shannon_entropy(data), 3)
        strings_result = extract_strings(file_path)

        return {
            "available": True,
            "format": "Generic Binary",
            "size": file_path.stat().st_size,
            "entropy": entropy,
            "entropy_verdict": strings_entropy.entropy_verdict(entropy),
            "strings": {
                "total_extracted": strings_result["total_extracted"],
                "sample": strings_result["sample"][:100],
            },
            "magic_bytes": data[:16].hex(),
        }
    except Exception as exc:
        return {"error": str(exc), "available": False}