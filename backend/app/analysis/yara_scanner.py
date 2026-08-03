"""
YARA rule-based scanning.

Rules live in app/rules/yara/*.yar and are compiled once at startup
(compilation is the expensive part — matching is cheap) and cached.
Add your own organization/CERT rule feeds by dropping more .yar files
in that directory; no code change needed.
"""
from __future__ import annotations

from pathlib import Path

from app.config import settings

_compiled_rules = None


def _load_rules():
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    try:
        import yara
    except ImportError:
        _compiled_rules = False
        return False

    rule_files = {
        p.stem: str(p) for p in Path(settings.YARA_RULES_DIR).glob("*.yar")
    }
    if not rule_files:
        _compiled_rules = False
        return False

    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
    except Exception as exc:
        print(f"[yara_scanner] Failed to compile rules: {exc}")
        _compiled_rules = False

    return _compiled_rules


def scan_file(file_path: Path) -> dict:
    rules = _load_rules()
    if not rules:
        return {"available": False, "matches": [], "note": "yara-python not installed or no rules compiled"}

    try:
        matches = rules.match(str(file_path), timeout=30)
    except Exception as exc:
        return {"available": True, "matches": [], "error": str(exc)}

    out = []
    for m in matches:
        out.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
            "matched_strings": [
                {"identifier": s.identifier, "offset": s.instances[0].offset if s.instances else None}
                for s in m.strings
            ][:20],
        })

    return {"available": True, "matches": out}
