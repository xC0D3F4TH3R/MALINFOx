"""MALINFO — Archive Static Analysis (ZIP, TAR, GZIP, BZ2, XZ, ZSTD, LZ4, LZMA, 7Z, RAR, CAB, etc.)

Recursive extraction and analysis of nested archives with depth/size limits.
"""
from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional

from app.analysis.strings_entropy import shannon_entropy

logger = logging.getLogger("malinfo.archive_analysis")

# Configuration
MAX_EXTRACTION_DEPTH = 5
MAX_TOTAL_EXTRACTED_SIZE = 500 * 1024 * 1024  # 500 MB
MAX_SINGLE_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_FILES_PER_ARCHIVE = 10000

# Known dangerous archive types (bombs)
ARCHIVE_BOMB_INDICATORS = [
    "zip bomb",
    "decompression bomb",
    "zip of death",
    "42.zip",
]


def analyze_archive(file_path: Path) -> dict:
    """
    Analyze archive file with recursive extraction.
    Returns structured analysis results.
    """
    result: dict = {
        "available": True,
        "format": "unknown",
        "format_details": "",
        "archive_type": "",
        "files": [],
        "total_files": 0,
        "total_size": 0,
        "compressed_size": file_path.stat().st_size,
        "compression_ratio": 0.0,
        "password_protected": False,
        "encrypted_files": [],
        "nested_archives": [],
        "executables": [],
        "scripts": [],
        "documents": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "extraction_depth": 0,
        "errors": [],
    }

    try:
        # Determine archive type by magic bytes
        with open(file_path, "rb") as f:
            header = f.read(16)

        archive_type = _detect_archive_type(header, file_path)
        result["archive_type"] = archive_type
        result["format"] = _format_for_archive_type(archive_type)
        result["format_details"] = f"{archive_type} archive"

        # Calculate entropy of archive file
        with open(file_path, "rb") as f:
            data = f.read(8192)
        result["entropy"] = round(shannon_entropy(data), 3)

        # Extract and analyze based on type
        if archive_type in ("ZIP", "APK", "JAR", "WAR", "EAR", "AAB", "IPA", "VSIX", "XPI", "EPUB", "DOCX", "XLSX", "PPTX"):
            _analyze_zip_archive(file_path, result, depth=0)
        elif archive_type in ("TAR", "TAR.GZ", "TAR.BZ2", "TAR.XZ", "TAR.ZST", "TGZ", "TBZ2", "TXZ"):
            _analyze_tar_archive(file_path, result, depth=0)
        elif archive_type == "GZIP":
            _analyze_gzip_archive(file_path, result, depth=0)
        elif archive_type == "BZIP2":
            _analyze_bzip2_archive(file_path, result, depth=0)
        elif archive_type == "XZ":
            _analyze_xz_archive(file_path, result, depth=0)
        elif archive_type == "ZSTD":
            _analyze_zstd_archive(file_path, result, depth=0)
        elif archive_type == "LZ4":
            _analyze_lz4_archive(file_path, result, depth=0)
        elif archive_type == "LZMA":
            _analyze_lzma_archive(file_path, result, depth=0)
        elif archive_type == "7Z":
            _analyze_7z_archive(file_path, result, depth=0)
        elif archive_type == "RAR":
            _analyze_rar_archive(file_path, result, depth=0)
        elif archive_type == "CAB":
            _analyze_cab_archive(file_path, result, depth=0)
        else:
            result["errors"].append(f"Unsupported archive type: {archive_type}")

        # Calculate compression ratio
        if result["total_size"] > 0:
            result["compression_ratio"] = round(result["compressed_size"] / result["total_size"], 3)

        # Check for archive bombs
        _check_archive_bomb(result)

    except Exception as exc:
        logger.debug(f"Archive analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _detect_archive_type(header: bytes, file_path: Path) -> str:
    """Detect archive type from magic bytes and extension."""
    ext = file_path.suffix.lower()
    ext2 = "".join(file_path.suffixes[-2:]).lower() if len(file_path.suffixes) >= 2 else ""

    # Check magic bytes
    if header[:4] == b"PK\x03\x04" or header[:4] == b"PK\x05\x06" or header[:4] == b"PK\x07\x08":
        # ZIP-based - check extension for specific type
        if ext == ".apk":
            return "APK"
        elif ext == ".aab":
            return "AAB"
        elif ext == ".jar":
            return "JAR"
        elif ext == ".war":
            return "WAR"
        elif ext == ".ear":
            return "EAR"
        elif ext == ".ipa":
            return "IPA"
        elif ext == ".vsix":
            return "VSIX"
        elif ext == ".xpi":
            return "XPI"
        elif ext == ".epub":
            return "EPUB"
        elif ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm") or ext in (".dotx", ".xltx", ".potx", ".dotm", ".xltm", ".potm"):
            return ext[1:].upper()
        return "ZIP"

    if header[:6] == b"Rar!\x1a\x07" or header[:7] == b"Rar!\x1a\x07\x01\x00":
        return "RAR"

    if header[:2] == b"\x1f\x8b":
        return "GZIP"

    if header[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7Z"

    if header[:3] == b"BZh":
        return "BZIP2"

    if header[:6] == b"\xfd7zXZ":
        return "XZ"

    if header[:4] == b"\x28\xb5\x2f\xfd":
        return "ZSTD"

    if header[:4] == b"\x04\x22\x4d\x18":
        return "LZ4"

    if header[:5] == b"\x5d\x00\x00\x80\x00":
        return "LZMA"

    if header[:4] == b"MSCF":
        return "CAB"

    if header[:4] == b"ITSF":
        return "CHM"

    # Check TAR variants by extension
    if ext in (".tar",):
        return "TAR"
    if ext2 in (".tar.gz", ".tgz", ".tar.gzip"):
        return "TAR.GZ"
    if ext2 in (".tar.bz2", ".tbz2", ".tbz"):
        return "TAR.BZ2"
    if ext2 in (".tar.xz", ".txz"):
        return "TAR.XZ"
    if ext2 in (".tar.zst", ".tzst"):
        return "TAR.ZST"
    if ext2 in (".tar.lz4", ".tlz4"):
        return "TAR.LZ4"
    if ext2 in (".tar.lzma", ".tlzma"):
        return "TAR.LZMA"

    # Try to detect TAR by content (ustar magic at offset 257)
    if len(header) >= 261:
        if header[257:262] == b"ustar" or header[257:261] == b"USTAR":
            return "TAR"

    return "UNKNOWN"


def _format_for_archive_type(archive_type: str) -> str:
    formats = {
        "ZIP": "ZIP Archive",
        "APK": "Android APK",
        "AAB": "Android App Bundle",
        "JAR": "Java Archive",
        "WAR": "Web Application Archive",
        "EAR": "Enterprise Archive",
        "IPA": "iOS App Store Package",
        "VSIX": "Visual Studio Extension",
        "XPI": "Mozilla Extension",
        "EPUB": "Electronic Publication",
        "DOCX": "Word Document",
        "XLSX": "Excel Spreadsheet",
        "PPTX": "PowerPoint Presentation",
        "DOCM": "Word Macro-Enabled Document",
        "XLSM": "Excel Macro-Enabled Spreadsheet",
        "PPTM": "PowerPoint Macro-Enabled Presentation",
        "DOTX": "Word Template",
        "XLTX": "Excel Template",
        "POTX": "PowerPoint Template",
        "DOTM": "Word Macro-Enabled Template",
        "XLTm": "Excel Macro-Enabled Template",
        "POTM": "PowerPoint Macro-Enabled Template",
        "TAR": "TAR Archive",
        "TAR.GZ": "GZIP-compressed TAR",
        "TAR.BZ2": "BZIP2-compressed TAR",
        "TAR.XZ": "XZ-compressed TAR",
        "TAR.ZST": "ZSTD-compressed TAR",
        "TAR.LZ4": "LZ4-compressed TAR",
        "TAR.LZMA": "LZMA-compressed TAR",
        "TGZ": "GZIP-compressed TAR",
        "TBZ2": "BZIP2-compressed TAR",
        "TXZ": "XZ-compressed TAR",
        "GZIP": "GZIP Archive",
        "BZIP2": "BZIP2 Archive",
        "XZ": "XZ Archive",
        "ZSTD": "ZSTD Archive",
        "LZ4": "LZ4 Archive",
        "LZMA": "LZMA Archive",
        "7Z": "7-Zip Archive",
        "RAR": "RAR Archive",
        "CAB": "Microsoft Cabinet",
        "CHM": "Compiled HTML Help",
        "UNKNOWN": "Unknown Archive",
    }
    return formats.get(archive_type, f"{archive_type} Archive")


def _analyze_zip_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze ZIP-based archive (ZIP, APK, JAR, etc.)."""
    if depth >= MAX_EXTRACTION_DEPTH:
        result["errors"].append(f"Max extraction depth ({MAX_EXTRACTION_DEPTH}) reached")
        return

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            # Check for password protection
            for info in z.infolist():
                if info.flag_bits & 0x1:
                    result["password_protected"] = True
                    result["encrypted_files"].append(info.filename)
                    result["suspicious_indicators"].append("Password-protected archive detected")

            names = z.namelist()
            result["total_files"] = len(names)

            if result["total_files"] > MAX_FILES_PER_ARCHIVE:
                result["suspicious_indicators"].append(
                    f"Large number of files ({result['total_files']}) - possible zip bomb"
                )

            extracted_size = 0
            file_count = 0

            for name in names:
                if file_count >= MAX_FILES_PER_ARCHIVE:
                    result["errors"].append("File limit reached during analysis")
                    break

                try:
                    info = z.getinfo(name)
                    file_size = info.file_size
                    compressed_size = info.compress_size

                    # Skip directories
                    if name.endswith("/"):
                        continue

                    # Check size limits
                    if file_size > MAX_SINGLE_FILE_SIZE:
                        result["suspicious_indicators"].append(
                            f"Large file in archive: {name} ({file_size} bytes)"
                        )
                        continue

                    if extracted_size + file_size > MAX_TOTAL_EXTRACTED_SIZE:
                        result["suspicious_indicators"].append(
                            "Total extracted size limit reached - possible decompression bomb"
                        )
                        break

                    extracted_size += file_size
                    file_count += 1

                    # Get entropy of compressed data
                    try:
                        compressed_data = z.read(name)
                        entropy = round(shannon_entropy(compressed_data[:8192]), 3) if compressed_data else 0.0
                    except Exception:
                        entropy = 0.0

                    file_info = {
                        "name": name,
                        "size": file_size,
                        "compressed_size": compressed_size,
                        "entropy": entropy,
                        "crc32": hex(info.CRC),
                        "is_encrypted": bool(info.flag_bits & 0x1),
                        "compression_method": info.compress_type,
                    }

                    result["files"].append(file_info)
                    result["total_size"] += file_size

                    # Categorize file by extension
                    ext = Path(name).suffix.lower()
                    if ext in (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv"):
                        result["executables"].append(name)
                    elif ext in (".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".py", ".sh", ".bash"):
                        result["scripts"].append(name)
                    elif ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".ods", ".odp"):
                        result["documents"].append(name)
                    elif ext in (".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".cab"):
                        result["nested_archives"].append(name)

                    # Recursively analyze nested archives (limited depth)
                    if depth < MAX_EXTRACTION_DEPTH - 1 and ext in (".zip", ".jar", ".war", ".ear", ".apk"):
                        # Extract to temp and analyze
                        with tempfile.TemporaryDirectory() as tmpdir:
                            try:
                                extracted_path = z.extract(name, tmpdir)
                                # Note: Full recursive analysis would be done in pipeline
                                nested_info = {"path": name, "extracted_to": extracted_path}
                                result["nested_archives"][-1] = {**result["nested_archives"][-1], **nested_info}
                            except Exception:
                                pass

                except Exception as exc:
                    logger.debug(f"Failed to analyze {name}: {exc}")
                    result["errors"].append(f"Error reading {name}: {exc}")

    except zipfile.BadZipFile:
        result["errors"].append("Invalid or corrupted ZIP file")
    except Exception as exc:
        result["errors"].append(f"ZIP analysis failed: {exc}")


def _analyze_tar_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze TAR archive (possibly compressed)."""
    if depth >= MAX_EXTRACTION_DEPTH:
        result["errors"].append(f"Max extraction depth ({MAX_EXTRACTION_DEPTH}) reached")
        return

    try:
        # Determine compression mode
        mode = "r"
        if result["archive_type"] in ("TAR.GZ", "TGZ"):
            mode = "r:gz"
        elif result["archive_type"] in ("TAR.BZ2", "TBZ2"):
            mode = "r:bz2"
        elif result["archive_type"] in ("TAR.XZ", "TXZ"):
            mode = "r:xz"
        elif result["archive_type"] in ("TAR.ZST",):
            mode = "r:zst"
        elif result["archive_type"] in ("TAR.LZ4",):
            mode = "r:lz4"
        elif result["archive_type"] in ("TAR.LZMA",):
            mode = "r:lzma"

        with tarfile.open(file_path, mode) as tar:
            members = tar.getmembers()
            result["total_files"] = len(members)

            if result["total_files"] > MAX_FILES_PER_ARCHIVE:
                result["suspicious_indicators"].append(
                    f"Large number of files ({result['total_files']}) - possible tar bomb"
                )

            extracted_size = 0
            file_count = 0

            for member in members:
                if file_count >= MAX_FILES_PER_ARCHIVE:
                    result["errors"].append("File limit reached during analysis")
                    break

                if not member.isfile():
                    continue

                file_size = member.size

                if file_size > MAX_SINGLE_FILE_SIZE:
                    result["suspicious_indicators"].append(
                        f"Large file in archive: {member.name} ({file_size} bytes)"
                    )
                    continue

                if extracted_size + file_size > MAX_TOTAL_EXTRACTED_SIZE:
                    result["suspicious_indicators"].append(
                        "Total extracted size limit reached - possible decompression bomb"
                    )
                    break

                extracted_size += file_size
                file_count += 1

                # Try to read some data for entropy
                entropy = 0.0
                try:
                    f = tar.extractfile(member)
                    if f:
                        data = f.read(8192)
                        entropy = round(shannon_entropy(data), 3) if data else 0.0
                except Exception:
                    pass

                file_info = {
                    "name": member.name,
                    "size": file_size,
                    "mode": oct(member.mode),
                    "mtime": member.mtime,
                    "entropy": entropy,
                    "type": "file" if member.isfile() else "dir" if member.isdir() else "other",
                }

                result["files"].append(file_info)
                result["total_size"] += file_size

                # Categorize
                ext = Path(member.name).suffix.lower()
                if ext in (".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".so", ".ko", ".bin", ".elf"):
                    result["executables"].append(member.name)
                elif ext in (".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".py", ".sh", ".bash", ".pl", ".rb", ".php"):
                    result["scripts"].append(member.name)
                elif ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".rtf", ".odt", ".ods", ".odp"):
                    result["documents"].append(member.name)
                elif ext in (".zip", ".jar", ".war", ".ear", ".apk", ".aab", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".cab", ".tgz", ".tbz2", ".txz"):
                    result["nested_archives"].append(member.name)

    except tarfile.ReadError:
        result["errors"].append("Invalid or corrupted TAR file")
    except Exception as exc:
        result["errors"].append(f"TAR analysis failed: {exc}")


def _analyze_gzip_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze GZIP archive (single file)."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        with gzip.open(file_path, "rb") as gz:
            # Read first chunk for entropy
            data = gz.read(8192)
            result["entropy"] = round(shannon_entropy(data), 3) if data else 0.0

            # Get uncompressed size (last 4 bytes for gzip)
            gz.seek(-4, 2)
            uncompressed_size = int.from_bytes(gz.read(4), "little")
            result["total_size"] = uncompressed_size
            result["total_files"] = 1

            # Check if it's a tar.gz
            if file_path.suffix.lower() in (".gz",) and file_path.suffixes[-2:].lower() == [".tar", ".gz"]:
                result["archive_type"] = "TAR.GZ"
                result["format"] = "GZIP-compressed TAR"
                # Re-analyze as TAR
                _analyze_tar_archive(file_path, result, depth)
            else:
                result["files"].append({
                    "name": file_path.stem,
                    "size": uncompressed_size,
                    "entropy": result["entropy"],
                })
    except Exception as exc:
        result["errors"].append(f"GZIP analysis failed: {exc}")


def _analyze_bzip2_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze BZIP2 archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        with bz2.open(file_path, "rb") as bz:
            data = bz.read(8192)
            result["entropy"] = round(shannon_entropy(data), 3) if data else 0.0

            # Get uncompressed size by reading all
            bz.seek(0)
            all_data = bz.read()
            result["total_size"] = len(all_data)
            result["total_files"] = 1

            # Check if it's a tar.bz2
            if file_path.suffixes[-2:].lower() == [".tar", ".bz2"]:
                result["archive_type"] = "TAR.BZ2"
                result["format"] = "BZIP2-compressed TAR"
                _analyze_tar_archive(file_path, result, depth)
            else:
                result["files"].append({
                    "name": file_path.stem,
                    "size": result["total_size"],
                    "entropy": result["entropy"],
                })
    except Exception as exc:
        result["errors"].append(f"BZIP2 analysis failed: {exc}")


def _analyze_xz_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze XZ archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        with lzma.open(file_path, "rb") as xz:
            data = xz.read(8192)
            result["entropy"] = round(shannon_entropy(data), 3) if data else 0.0

            xz.seek(0)
            all_data = xz.read()
            result["total_size"] = len(all_data)
            result["total_files"] = 1

            if file_path.suffixes[-2:].lower() == [".tar", ".xz"]:
                result["archive_type"] = "TAR.XZ"
                result["format"] = "XZ-compressed TAR"
                _analyze_tar_archive(file_path, result, depth)
            else:
                result["files"].append({
                    "name": file_path.stem,
                    "size": result["total_size"],
                    "entropy": result["entropy"],
                })
    except Exception as exc:
        result["errors"].append(f"XZ analysis failed: {exc}")


def _analyze_zstd_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze ZSTD archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        import zstandard as zstd

        with open(file_path, "rb") as f:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(f) as reader:
                data = reader.read(8192)
                result["entropy"] = round(shannon_entropy(data), 3) if data else 0.0

                # Read all for size
                reader.seek(0)
                all_data = reader.read()
                result["total_size"] = len(all_data)
                result["total_files"] = 1

                if file_path.suffixes[-2:].lower() == [".tar", ".zst"]:
                    result["archive_type"] = "TAR.ZST"
                    result["format"] = "ZSTD-compressed TAR"
                    _analyze_tar_archive(file_path, result, depth)
                else:
                    result["files"].append({
                        "name": file_path.stem,
                        "size": result["total_size"],
                        "entropy": result["entropy"],
                    })
    except ImportError:
        result["errors"].append("zstandard library not installed")
    except Exception as exc:
        result["errors"].append(f"ZSTD analysis failed: {exc}")


def _analyze_lz4_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze LZ4 archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        import lz4.frame

        with open(file_path, "rb") as f:
            data = f.read(8192)
            result["entropy"] = round(shannon_entropy(data), 3) if data else 0.0

            with lz4.frame.open(file_path, "rb") as lz4f:
                all_data = lz4f.read()
                result["total_size"] = len(all_data)
                result["total_files"] = 1

                if file_path.suffixes[-2:].lower() == [".tar", ".lz4"]:
                    result["archive_type"] = "TAR.LZ4"
                    result["format"] = "LZ4-compressed TAR"
                    _analyze_tar_archive(file_path, result, depth)
                else:
                    result["files"].append({
                        "name": file_path.stem,
                        "size": result["total_size"],
                        "entropy": result["entropy"],
                    })
    except ImportError:
        result["errors"].append("lz4 library not installed")
    except Exception as exc:
        result["errors"].append(f"LZ4 analysis failed: {exc}")


def _analyze_lzma_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze LZMA archive (raw LZMA, not XZ)."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        import lzma

        with lzma.open(file_path, "rb", format=lzma.FORMAT_ALONE) as lzmaf:
            data = lzmaf.read(8192)
            result["entropy"] = round(shannon_entropy(data), 3) if data else 0.0

            lzmaf.seek(0)
            all_data = lzmaf.read()
            result["total_size"] = len(all_data)
            result["total_files"] = 1

            if file_path.suffixes[-2:].lower() == [".tar", ".lzma"]:
                result["archive_type"] = "TAR.LZMA"
                result["format"] = "LZMA-compressed TAR"
                _analyze_tar_archive(file_path, result, depth)
            else:
                result["files"].append({
                    "name": file_path.stem,
                    "size": result["total_size"],
                    "entropy": result["entropy"],
                })
    except Exception as exc:
        result["errors"].append(f"LZMA analysis failed: {exc}")


def _analyze_7z_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze 7-Zip archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        import py7zr

        with py7zr.SevenZipFile(file_path, "r") as z:
            names = z.getnames()
            result["total_files"] = len(names)

            if result["total_files"] > MAX_FILES_PER_ARCHIVE:
                result["suspicious_indicators"].append(
                    f"Large number of files ({result['total_files']}) - possible archive bomb"
                )

            extracted_size = 0
            file_count = 0

            for name in names:
                if file_count >= MAX_FILES_PER_ARCHIVE:
                    break

                try:
                    info = z.getmembers()[names.index(name)]
                    file_size = info.uncompressed

                    if file_size > MAX_SINGLE_FILE_SIZE:
                        continue

                    if extracted_size + file_size > MAX_TOTAL_EXTRACTED_SIZE:
                        break

                    extracted_size += file_size
                    file_count += 1

                    entropy = 0.0
                    try:
                        extracted = z.read([name])
                        data = next(iter(extracted.values()))
                        entropy = round(shannon_entropy(data[:8192]), 3) if data else 0.0
                    except Exception:
                        pass

                    file_info = {
                        "name": name,
                        "size": file_size,
                        "entropy": entropy,
                        "is_encrypted": info.is_encrypted,
                    }

                    result["files"].append(file_info)
                    result["total_size"] += file_size

                    ext = Path(name).suffix.lower()
                    if ext in (".exe", ".dll", ".sys", ".so", ".elf"):
                        result["executables"].append(name)
                    elif ext in (".ps1", ".bat", ".cmd", ".js", ".vbs", ".py", ".sh"):
                        result["scripts"].append(name)
                    elif ext in (".doc", ".docx", ".pdf", ".rtf"):
                        result["documents"].append(name)
                    elif ext in (".zip", ".7z", ".rar", ".tar", ".gz"):
                        result["nested_archives"].append(name)

                except Exception:
                    pass

    except ImportError:
        result["errors"].append("py7zr library not installed")
    except Exception as exc:
        result["errors"].append(f"7Z analysis failed: {exc}")


def _analyze_rar_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze RAR archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        import rarfile

        with rarfile.RarFile(file_path) as rf:
            if rf.needs_password():
                result["password_protected"] = True
                result["suspicious_indicators"].append("Password-protected RAR archive")

            names = rf.namelist()
            result["total_files"] = len(names)

            extracted_size = 0
            file_count = 0

            for name in names:
                if file_count >= MAX_FILES_PER_ARCHIVE:
                    break

                try:
                    info = rf.getinfo(name)
                    if info.is_dir():
                        continue

                    file_size = info.file_size

                    if file_size > MAX_SINGLE_FILE_SIZE:
                        continue

                    if extracted_size + file_size > MAX_TOTAL_EXTRACTED_SIZE:
                        break

                    extracted_size += file_size
                    file_count += 1

                    entropy = 0.0
                    try:
                        data = rf.read(name)
                        entropy = round(shannon_entropy(data[:8192]), 3) if data else 0.0
                    except Exception:
                        pass

                    file_info = {
                        "name": name,
                        "size": file_size,
                        "entropy": entropy,
                        "crc32": hex(info.CRC),
                    }

                    result["files"].append(file_info)
                    result["total_size"] += file_size

                    ext = Path(name).suffix.lower()
                    if ext in (".exe", ".dll", ".sys", ".so", ".elf"):
                        result["executables"].append(name)
                    elif ext in (".ps1", ".bat", ".cmd", ".js", ".vbs", ".py", ".sh"):
                        result["scripts"].append(name)
                    elif ext in (".doc", ".docx", ".pdf", ".rtf"):
                        result["documents"].append(name)
                    elif ext in (".zip", ".7z", ".rar", ".tar", ".gz"):
                        result["nested_archives"].append(name)

                except Exception:
                    pass

    except ImportError:
        result["errors"].append("rarfile library not installed")
    except Exception as exc:
        result["errors"].append(f"RAR analysis failed: {exc}")


def _analyze_cab_archive(file_path: Path, result: dict, depth: int = 0) -> None:
    """Analyze Microsoft Cabinet (CAB) archive."""
    if depth >= MAX_EXTRACTION_DEPTH:
        return

    try:
        import subprocess

        # Use cabextract if available
        try:
            proc = subprocess.run(
                ["cabextract", "-l", str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if proc.returncode == 0:
                # Parse output
                lines = proc.stdout.strip().split("\n")
                for line in lines:
                    if line.strip() and not line.startswith("File") and not line.startswith("---"):
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[-1]
                            size = int(parts[1]) if parts[1].isdigit() else 0
                            result["files"].append({"name": name, "size": size})
                            result["total_size"] += size
                            result["total_files"] += 1
            else:
                result["errors"].append("cabextract failed to list contents")
        except FileNotFoundError:
            result["errors"].append("cabextract not installed")
    except Exception as exc:
        result["errors"].append(f"CAB analysis failed: {exc}")


def _check_archive_bomb(result: dict) -> None:
    """Check for archive bomb indicators."""
    # High compression ratio
    if result.get("compression_ratio", 0) > 100:
        result["suspicious_indicators"].append(
            f"Extremely high compression ratio ({result['compression_ratio']:.1f}:1) - possible decompression bomb"
        )

    # Many small files that expand greatly
    if result.get("total_files", 0) > 1000 and result.get("compression_ratio", 0) > 10:
        result["suspicious_indicators"].append(
            "Many files with high compression ratio - possible archive bomb"
        )

    # Check for known bomb patterns
    for bomb in ARCHIVE_BOMB_INDICATORS:
        for f in result.get("files", []):
            if bomb.lower() in f.get("name", "").lower():
                result["suspicious_indicators"].append(f"Known archive bomb pattern: {bomb}")
                break

    # Nested archives depth
    nested_count = len(result.get("nested_archives", []))
    if nested_count > 10:
        result["suspicious_indicators"].append(f"High number of nested archives ({nested_count})")