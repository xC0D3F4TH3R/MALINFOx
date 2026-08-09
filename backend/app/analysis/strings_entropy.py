"""
Shannon entropy (packing/encryption indicator) and printable-string
extraction (a cheap but genuinely effective first-pass triage technique —
malware authors leave plaintext C2 domains, mutex names, and registry keys
in strings surprisingly often).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")
_WIDE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def file_entropy(file_path: Path) -> float:
    with open(file_path, "rb") as f:
        data = f.read()
    return round(shannon_entropy(data), 3)


def entropy_verdict(entropy: float) -> str:
    """
    Heuristic interpretation. Packed/encrypted/compressed binaries commonly
    sit above ~7.2. This is a *signal*, not proof — legitimate compressed
    formats (installers, media) are also high-entropy.
    """
    if entropy >= 7.5:
        return "very_high_likely_packed_or_encrypted"
    if entropy >= 6.8:
        return "high_possibly_compressed_or_packed"
    if entropy >= 4.0:
        return "normal"
    return "low_likely_text_or_sparse"


def extract_strings(file_path: Path, min_length: int = 5, max_strings: int = 5000) -> dict:
    with open(file_path, "rb") as f:
        data = f.read()

    ascii_hits = [m.group().decode("ascii", errors="ignore") for m in _ASCII_STRING_RE.finditer(data)]
    wide_hits = [
        m.group().decode("utf-16le", errors="ignore") for m in _WIDE_STRING_RE.finditer(data)
    ]

    combined = ascii_hits + wide_hits
    combined = [s for s in combined if len(s) >= min_length]

    return {
        "total_extracted": len(combined),
        "truncated": len(combined) > max_strings,
        "sample": combined[:max_strings],
    }
