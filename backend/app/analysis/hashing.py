"""Cryptographic and fuzzy hashing for sample identification."""
from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MB


def compute_hashes(file_path: Path) -> dict:
    """Stream the file once, computing MD5 / SHA1 / SHA256 concurrently.
    
    MD5 and SHA1 are used for file identification/fingerprinting, not security.
    usedforsecurity=False suppresses FIPS warnings in Python 3.9+.
    """
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def compute_ssdeep(file_path: Path) -> str | None:
    """
    Fuzzy hash for similarity matching against known malware families.
    Requires the `ssdeep` package (and libfuzzy at the OS level). Degrades
    gracefully to None if unavailable so the pipeline never hard-fails.
    """
    try:
        import ssdeep  # type: ignore
    except ImportError:
        return None

    try:
        return ssdeep.hash_from_file(str(file_path))
    except Exception:
        return None
