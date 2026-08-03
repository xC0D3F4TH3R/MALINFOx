"""
Android APK static analysis.

Implemented against the standard library (zipfile) plus a lightweight
binary-XML manifest parser rather than pulling in `androguard`, whose
transitive dependency tree is heavy for a pilot deployment. For deeper
DEX-level analysis (decompiled Smali, call-graph analysis) wire in
androguard or jadx in Phase 2 — see backend/app/sandbox/README.md.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

# Dangerous / sensitive Android permissions worth flagging in a report.
_HIGH_RISK_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.CALL_PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
}

# Binary AXML string-pool scan is intentionally simple: we look for
# printable UTF-16 strings inside AndroidManifest.xml rather than fully
# decoding the binary XML format, which is enough to reliably recover
# permission names and package metadata for triage.
_UTF16_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def analyze_apk(file_path: Path) -> dict:
    result: dict = {"available": True, "permissions": [], "high_risk_permissions": [],
                     "package_name": None, "activities_sample": [], "files_of_interest": []}

    try:
        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            result["file_count"] = len(names)
            result["has_dex"] = any(n.endswith(".dex") for n in names)
            result["dex_files"] = [n for n in names if n.endswith(".dex")]
            result["native_libs"] = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            result["is_signed"] = any(n.startswith("META-INF/") and (n.endswith((".RSA", ".DSA", ".EC"))) for n in names)

            # Files that commonly indicate abuse of asset-loading for
            # secondary payload staging (dynamic dex loading, droppers).
            result["files_of_interest"] = [
                n for n in names
                if n.lower().endswith((".dex", ".so", ".jar", ".zip", ".apk"))
                and n not in ("classes.dex",)
            ]

            if "AndroidManifest.xml" in names:
                raw = z.read("AndroidManifest.xml")
                strings_found = [
                    m.group().decode("utf-16le", errors="ignore")
                    for m in _UTF16_STRING_RE.finditer(raw)
                ]
                perms = sorted({s for s in strings_found if s.startswith("android.permission.")})
                result["permissions"] = perms
                result["high_risk_permissions"] = sorted(set(perms) & _HIGH_RISK_PERMISSIONS)

                pkg_candidates = [
                    s for s in strings_found
                    if re.match(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*){2,}$", s)
                    and not s.startswith("android.")
                ]
                if pkg_candidates:
                    result["package_name"] = min(pkg_candidates, key=len)

                result["activities_sample"] = [
                    s for s in strings_found if "Activity" in s or "Service" in s or "Receiver" in s
                ][:50]

    except zipfile.BadZipFile:
        return {"error": "Not a valid ZIP/APK container", "available": False}
    except Exception as exc:
        return {"error": f"Failed to parse APK: {exc}", "available": False}

    return result
