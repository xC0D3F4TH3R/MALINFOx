"""
File-type identification.

Uses libmagic when available (most accurate — reads content, not just the
extension), with a pure-Python magic-byte fallback so the pipeline still
works on a host where libmagic isn't installed yet.
"""
from __future__ import annotations

from pathlib import Path

# (signature_bytes, offset, file_type, mime_type, target_os)
_SIGNATURES: list[tuple[bytes, int, str, str, str]] = [
    (b"MZ", 0, "PE (Windows Executable)", "application/x-msdownload", "windows"),
    (b"\x7fELF", 0, "ELF (Linux Executable)", "application/x-elf", "linux"),
    (b"PK\x03\x04", 0, "ZIP-based archive (possibly APK/JAR/DOCX)", "application/zip", "unknown"),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit (macOS/iOS)", "application/x-mach-binary", "macos"),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit (macOS/iOS)", "application/x-mach-binary", "macos"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit reversed (macOS/iOS)", "application/x-mach-binary", "macos"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O Fat Binary / Java class", "application/x-mach-binary", "macos"),
    (b"%PDF", 0, "PDF Document", "application/pdf", "unknown"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MS Office (legacy OLE)", "application/x-ole-storage", "windows"),
    (b"Rar!\x1a\x07", 0, "RAR Archive", "application/x-rar-compressed", "unknown"),
    (b"\x1f\x8b", 0, "GZIP Archive", "application/gzip", "unknown"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip Archive", "application/x-7z-compressed", "unknown"),
    (b"dex\n", 0, "DEX (Android Dalvik bytecode)", "application/x-dex", "android"),
]


def _magic_fallback(header: bytes) -> tuple[str, str, str]:
    for sig, offset, ftype, mime, os_ in _SIGNATURES:
        if header[offset:offset + len(sig)] == sig:
            return ftype, mime, os_
    return "Unknown / raw data", "application/octet-stream", "unknown"


def identify_file(file_path: Path) -> dict:
    with open(file_path, "rb") as f:
        header = f.read(4096)

    file_type, mime_type, target_os = _magic_fallback(header)

    # Prefer libmagic for a richer description when available.
    try:
        import magic  # python-magic

        mime_type = magic.from_file(str(file_path), mime=True) or mime_type
        file_type = magic.from_file(str(file_path)) or file_type
    except Exception:
        pass  # fall back to signature match above

    # APK vs generic ZIP disambiguation: APKs are ZIPs containing
    # AndroidManifest.xml and classes.dex at the root.
    if file_type.startswith("ZIP") or mime_type == "application/zip":
        apk_hint = _looks_like_apk(file_path)
        if apk_hint:
            file_type = "APK (Android Application Package)"
            mime_type = "application/vnd.android.package-archive"
            target_os = "android"
        elif _looks_like_docx_xlsx_pptx(file_path):
            file_type = "Office Open XML document (docx/xlsx/pptx)"
            target_os = "windows"

    return {"file_type": file_type, "mime_type": mime_type, "target_os": target_os}


def _looks_like_apk(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names)
    except Exception:
        return False


def _looks_like_docx_xlsx_pptx(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "[Content_Types].xml" in names
    except Exception:
        return False
