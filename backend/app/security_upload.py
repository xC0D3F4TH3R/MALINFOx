"""
File upload validation and security utilities for MALINFO.
Provides MIME type verification, magic bytes checking, size limits,
and path traversal protection.
"""
from __future__ import annotations

import os
import re
import tempfile
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

import magic

if TYPE_CHECKING:
    from fastapi import UploadFile

# Allowed MIME types for upload
ALLOWED_MIME_TYPES = {
    # Executables
    "application/x-dosexec",      # PE/EXE
    "application/x-executable",   # ELF
    "application/x-mach-binary",  # Mach-O
    "application/vnd.android.package-archive",  # APK
    "application/x-sharedlib",    # Shared libraries

    # Archives
    "application/zip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-tar",
    "application/java-archive",   # JAR

    # Documents
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/rtf",
    "text/plain",

    # Scripts
    "text/x-python",
    "text/x-shellscript",
    "application/x-perl",
    "application/javascript",
    "text/x-php",
    "application/x-httpd-php",

    # Disk images
    "application/x-iso9660-image",
    "application/vnd.vmware.vmdk",
    "application/x-qemu-disk",

    # Memory dumps
    "application/vnd.microsoft.memory-dump",
    "application/x-lime-memory",

    # Logs
    "text/x-log",
    "application/x-evtx",

    # Certificates/Keys
    "application/x-pem-file",
    "application/x-x509-ca-cert",
    "application/pkcs7-mime",
    "application/pkcs12",

    # Images (for steganography analysis)
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/bmp",
    "image/tiff",
    "image/webp",

    # Other
    "application/octet-stream",  # Generic binary
}

# Magic bytes signatures for file type verification
MAGIC_BYTES = {
    # PE/EXE
    b"MZ": "application/x-dosexec",
    # ELF
    b"\x7fELF": "application/x-executable",
    # Mach-O
    b"\xfe\xed\xfa\xce": "application/x-mach-binary",  # 32-bit
    b"\xfe\xed\xfa\xcf": "application/x-mach-binary",  # 64-bit
    b"\xce\xfa\xed\xfe": "application/x-mach-binary",  # Reverse 32-bit
    b"\xcf\xfa\xed\xfe": "application/x-mach-binary",  # Reverse 64-bit
    # ZIP/APK/JAR/DOCX
    b"PK\x03\x04": "application/zip",
    b"PK\x05\x06": "application/zip",  # Empty archive
    b"PK\x07\x08": "application/zip",  # Spanned archive
    # RAR
    b"Rar!\x1a\x07\x00": "application/x-rar-compressed",
    b"Rar!\x1a\x07\x01\x00": "application/x-rar-compressed",
    # 7z
    b"7z\xbc\xaf\x27\x1c": "application/x-7z-compressed",
    # GZIP
    b"\x1f\x8b\x08": "application/gzip",
    # BZIP2
    b"BZh": "application/x-bzip2",
    # XZ
    b"\xfd7zXZ\x00": "application/x-xz",
    # TAR
    # Tar detected by extension or content
    # PDF
    b"%PDF": "application/pdf",
    # PNG
    b"\x89PNG\r\n\x1a\n": "image/png",
    # JPEG
    b"\xff\xd8\xff": "image/jpeg",
    # GIF
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    # BMP
    b"BM": "image/bmp",
    # TIFF
    b"II\x2a\x00": "image/tiff",
    b"MM\x00\x2a": "image/tiff",
    # WebP
    b"RIFF": "image/webp",  # Need to check for "WEBP" at offset 8
    # ISO
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00": "application/x-iso9660-image",
    # Microsoft Compound Document (OLE)
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "application/msword",
    # LZMA
    b"]\x00\x00\x80": "application/x-lzma",
    # Zstandard
    b"\x28\xb5\x2f\xfd": "application/x-zstd",
    # LZ4
    b"\x04\x22\x4d\x18": "application/x-lz4",
}

# File extensions that are ALWAYS blocked
BLOCKED_EXTENSIONS = {
    # Web shells and server-side scripts
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phps",
    ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
    ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
    ".cfm", ".cfml", ".cfc",
    ".pl", ".cgi", ".fcgi",
    ".py", ".pyc", ".pyo", ".pyw",
    ".rb", ".rbw",
    ".sh", ".bash", ".zsh", ".csh", ".ksh",
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1",
    ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
    ".js", ".jse", ".mjs",
    # Config and sensitive files
    ".htaccess", ".htpasswd", ".env", ".git", ".svn",
    ".sql", ".db", ".sqlite", ".sqlite3",
    ".key", ".pem", ".crt", ".cer", ".pfx", ".p12",
    # System files
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".cpl",
    ".msi", ".msp", ".mst",
    ".apk", ".ipa",
    ".app", ".dmg", ".pkg", ".mpkg",
}

# Maximum file sizes by type (in bytes)
MAX_FILE_SIZES = {
    "default": 250 * 1024 * 1024,  # 250 MB
    "application/x-dosexec": 100 * 1024 * 1024,  # 100 MB for PE
    "application/x-executable": 100 * 1024 * 1024,  # 100 MB for ELF
    "application/x-mach-binary": 100 * 1024 * 1024,  # 100 MB for Mach-O
    "application/vnd.android.package-archive": 200 * 1024 * 1024,  # 200 MB for APK
    "application/zip": 500 * 1024 * 1024,  # 500 MB for archives
    "application/x-rar-compressed": 500 * 1024 * 1024,
    "application/x-7z-compressed": 500 * 1024 * 1024,
    "application/pdf": 100 * 1024 * 1024,  # 100 MB for PDF
    "image/png": 50 * 1024 * 1024,
    "image/jpeg": 50 * 1024 * 1024,
}

# Dangerous paths that should never be accessible
DANGEROUS_PATHS = [
    "/etc/", "/var/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
    "/boot/", "/root/", "/home/", "/opt/", "/srv/", "/tmp/", "/dev/",
    "/proc/", "/sys/", "/run/", "/var/log/", "/var/www/",
    "C:\\Windows\\", "C:\\Program Files\\", "C:\\Program Files (x86)\\",
    "C:\\Users\\", "C:\\System Volume Information\\",
]


def detect_mime_type(file_path: Path) -> str:
    """
    Detect MIME type using python-magic (libmagic).
    More reliable than extension-based detection.
    """
    try:
        mime = magic.Magic(mime=True)
        return mime.from_file(str(file_path))
    except Exception:
        return "application/octet-stream"


def detect_mime_from_bytes(data: bytes) -> str:
    """
    Detect MIME type from file header bytes.
    """
    try:
        mime = magic.Magic(mime=True)
        return mime.from_buffer(data)
    except Exception:
        return "application/octet-stream"


def verify_magic_bytes(file_path: Path) -> tuple[str | None, str | None]:
    """
    Verify file type by checking magic bytes.
    Returns (detected_mime, expected_mime) or (None, error) if mismatch.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(8192)

        # Check known magic bytes
        for magic_bytes, mime_type in MAGIC_BYTES.items():
            if header.startswith(magic_bytes):
                return mime_type, None

        # Special case for WebP (RIFF container)
        if header.startswith(b"RIFF") and b"WEBP" in header[8:16]:
            return "image/webp", None

        # Use libmagic as fallback
        detected = detect_mime_from_bytes(header)
        return detected, None

    except Exception as e:
        return None, f"Failed to read file header: {e}"


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent path traversal and injection.
    """
    # Remove any path components
    filename = Path(filename).name

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Remove dangerous characters
    filename = re.sub(r'[<>:\"/\\|?*\x00-\x1f]', "_", filename)

    # Limit length
    if len(filename) > 255:
        name = filename.rsplit(".", 1)[0] if "." in filename else filename
        ext = "." + filename.rsplit(".", 1)[1] if "." in filename else ""
        filename = name[:255 - len(ext)] + ext

    # Prevent hidden files
    if filename.startswith("."):
        filename = "_" + filename[1:]

    # Prevent reserved names (Windows)
    reserved = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4",
                "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2",
                "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}
    name = filename.rsplit(".", 1)[0] if "." in filename else filename
    if name.upper() in reserved:
        filename = "_" + filename

    return filename


def validate_file_extension(filename: str) -> tuple[bool, str | None]:
    """
    Validate file extension against blocked list.
    Returns (is_allowed, error_message).
    """
    ext = Path(filename).suffix.lower()

    if ext in BLOCKED_EXTENSIONS:
        return False, f"File extension '{ext}' is not allowed for security reasons"

    return True, None


def validate_file_size(file_size: int, mime_type: str) -> tuple[bool, str | None]:
    """
    Validate file size against limits.
    Returns (is_allowed, error_message).
    """
    max_size = MAX_FILE_SIZES.get(mime_type, MAX_FILE_SIZES["default"])

    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        return False, f"File size {file_size / (1024 * 1024):.1f} MB exceeds limit of {max_mb:.0f} MB for {mime_type}"

    return True, None


def validate_mime_type(mime_type: str) -> tuple[bool, str | None]:
    """
    Validate MIME type against allowed list.
    Returns (is_allowed, error_message).
    """
    if mime_type not in ALLOWED_MIME_TYPES:
        return False, f"MIME type '{mime_type}' is not allowed"

    return True, None


def check_path_traversal(path: Path, base_dir: Path) -> bool:
    """
    Check if a path attempts to escape the base directory.
    """
    try:
        resolved_path = path.resolve()
        resolved_base = base_dir.resolve()
        return resolved_path.is_relative_to(resolved_base)
    except Exception:
        return False


async def _validate_file_content(temp_path: Path, file_info: dict) -> tuple[bool, str | None]:
    """Validate file content: magic bytes, MIME type, size."""
    # Verify magic bytes
    detected_mime, error = verify_magic_bytes(temp_path)
    if error:
        return False, error
    file_info["detected_mime_type"] = detected_mime

    # Validate detected MIME type
    allowed, error = validate_mime_type(detected_mime)
    if not allowed:
        return False, error

    # Validate size against type-specific limit
    size = file_info["size"]
    allowed, error = validate_file_size(size, detected_mime)
    if not allowed:
        return False, error

    # Verify MIME type matches extension (optional warning)
    safe_filename = file_info["safe_filename"]
    ext = Path(safe_filename).suffix.lower()
    if ext and not _extension_matches_mime(ext, detected_mime):
        file_info["extension_mime_mismatch"] = True

    return True, None


def _handle_validation_error(temp_path: Path, error: str, file_info: dict) -> tuple[bool, str | None, dict]:
    """Clean up temp file and return error."""
    if temp_path.exists():
        temp_path.unlink()
    return False, f"Validation failed: {error}", file_info


async def validate_upload_file(file: UploadFile, upload_dir: Path) -> tuple[bool, str | None, dict]:
    """
    Comprehensive upload file validation.
    Returns (is_valid, error_message, file_info).
    """
    file_info = {
        "original_filename": file.filename,
        "content_type": file.content_type,
        "size": file.size,
    }

    # 1. Check filename
    if not file.filename:
        return False, "No filename provided", file_info

    # Sanitize filename
    safe_filename = sanitize_filename(file.filename)
    file_info["safe_filename"] = safe_filename

    if safe_filename != file.filename:
        file_info["filename_sanitized"] = True

    # 2. Validate extension
    allowed, error = validate_file_extension(safe_filename)
    if not allowed:
        return False, error, file_info

    # 3. Check content-type header (client-provided, not trusted)
    if file.content_type:
        file_info["client_content_type"] = file.content_type

    # 4. Save to temporary location for validation
    temp_dir = Path(tempfile.gettempdir()) / "malinfo_uploads"
    temp_dir.mkdir(parents=True, exist_ok=True)

    temp_path = temp_dir / f"{uuid.uuid4()}_{safe_filename}"

    try:
        # Stream file to temp location
        size = 0
        chunk_size = 8192

        async with temp_path.open("wb") as f:
            while chunk := await file.read(chunk_size):
                size += len(chunk)
                # Check size during upload
                if size > MAX_FILE_SIZES["default"]:
                    return _handle_validation_error(
                        temp_path,
                        f"File exceeds maximum size of {MAX_FILE_SIZES['default'] / (1024*1024):.0f} MB",
                        file_info,
                    )
                f.write(chunk)

        file_info["size"] = size

        # 5. Validate file content
        ok, error = await _validate_file_content(temp_path, file_info)
        if not ok:
            return _handle_validation_error(temp_path, error, file_info)

        file_info["validated"] = True
        file_info["temp_path"] = str(temp_path)

        return True, None, file_info

    except Exception as e:
        return _handle_validation_error(temp_path, str(e), file_info)


def _extension_matches_mime(ext: str, mime_type: str) -> bool:
    """Check if file extension matches detected MIME type."""
    extension_mime_map = {
        ".exe": "application/x-dosexec",
        ".dll": "application/x-dosexec",
        ".so": "application/x-sharedlib",
        ".dylib": "application/x-mach-binary",
        ".apk": "application/vnd.android.package-archive",
        ".ipa": "application/vnd.iphone",
        ".app": "application/x-mach-binary",
        ".pdf": "application/pdf",
        ".zip": "application/zip",
        ".rar": "application/x-rar-compressed",
        ".7z": "application/x-7z-compressed",
        ".gz": "application/gzip",
        ".bz2": "application/x-bzip2",
        ".xz": "application/x-xz",
        ".tar": "application/x-tar",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".bmp": "image/bmp",
        ".tiff": "image/tiff",
        ".tif": "image/tiff",
        ".webp": "image/webp",
        ".iso": "application/x-iso9660-image",
        ".vmdk": "application/vnd.vmware.vmdk",
        ".qcow2": "application/x-qemu-disk",
        ".pem": "application/x-pem-file",
        ".crt": "application/x-x509-ca-cert",
        ".cer": "application/x-x509-ca-cert",
        ".key": "application/x-pem-file",
        ".pfx": "application/pkcs12",
        ".p12": "application/pkcs12",
    }

    expected = extension_mime_map.get(ext)
    if expected:
        return expected == mime_type

    return True  # Unknown extension, allow


def get_safe_destination_path(upload_dir: Path, safe_filename: str) -> Path:
    """
    Get a safe destination path within the upload directory.
    Ensures no path traversal and handles name collisions.
    """
    upload_dir.mkdir(parents=True, exist_ok=True)

    base_path = upload_dir / safe_filename

    if not check_path_traversal(base_path, upload_dir):
        raise ValueError("Path traversal attempt detected")

    counter = 1
    final_path = base_path
    while final_path.exists():
        stem = base_path.stem
        suffix = base_path.suffix
        final_path = upload_dir / f"{stem}_{counter}{suffix}"
        counter += 1

        if counter > 10000:
            raise ValueError("Too many files with same name")

    return final_path