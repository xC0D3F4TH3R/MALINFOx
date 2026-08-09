"""MALINFO — Apple iOS/macOS Analysis (IPA, Mach-O bundles, provisioning profiles)

Analysis for iOS IPA files and macOS app bundles.
"""
from __future__ import annotations

import logging
import plistlib
import zipfile
from typing import TYPE_CHECKING

from app.analysis.macho_deep_analysis import analyze_macho_deep
from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.apple_analysis")


def analyze_apple_bundle(file_path: Path) -> dict:
    """
    Analyze Apple bundle (IPA, .app, .framework, .dylib).
    """
    result: dict = {
        "available": True,
        "format": "unknown",
        "bundle_type": "",
        "info_plist": {},
        "entitlements": {},
        "provisioning_profile": {},
        "code_signature": {},
        "embedded_binaries": [],
        "embedded_frameworks": [],
        "embedded_plugins": [],
        "resources": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
    }

    try:
        # Determine bundle type
        if file_path.suffix.lower() == ".ipa":
            return _analyze_ipa(file_path, result)
        elif file_path.suffix.lower() == ".app":
            return _analyze_app_bundle(file_path, result)
        elif file_path.suffix.lower() in (".framework", ".dylib"):
            return _analyze_macho_binary(file_path, result)
        else:
            result["error"] = f"Unsupported Apple bundle type: {file_path.suffix}"
            result["available"] = False
    except Exception as exc:
        logger.debug(f"Apple bundle analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_ipa(file_path: Path, result: dict) -> dict:
    """Analyze iOS IPA (ZIP-based)."""
    result["format"] = "IPA (iOS App Store Package)"
    result["bundle_type"] = "IPA"

    try:
        with zipfile.ZipFile(file_path, "r") as z:
            names = z.namelist()
            result["files"] = names
            result["total_files"] = len(names)

            # Find the .app bundle
            app_bundles = [n for n in names if n.endswith(".app/")]
            if not app_bundles:
                # Try to find any .app directory
                app_bundles = [n.split("/")[0] + "/" for n in names if ".app/" in n]
                app_bundles = list(set(app_bundles))

            if app_bundles:
                app_path = app_bundles[0]
                result["app_bundle_path"] = app_path
                result["bundle_type"] = "iOS App"

                # Extract and analyze Info.plist
                info_plist_path = app_path + "Info.plist"
                if info_plist_path in names:
                    try:
                        data = z.read(info_plist_path)
                        plist = plistlib.loads(data)
                        result["info_plist"] = _parse_info_plist(plist)
                    except Exception as exc:
                        logger.debug(f"Failed to parse Info.plist: {exc}")
                        result["info_plist"] = {"parse_error": str(exc)}

                # Extract and analyze entitlements
                entitlements_path = app_path + "embedded.mobileprovision"
                if entitlements_path in names:
                    try:
                        data = z.read(entitlements_path)
                        result["provisioning_profile"] = _parse_mobileprovision(data)
                    except Exception as exc:
                        logger.debug(f"Failed to parse mobileprovision: {exc}")

                # Find embedded binaries (executables)
                for name in names:
                    if name.startswith(app_path) and not name.endswith("/"):
                        if name == app_path + "Info.plist":
                            continue
                        if name == app_path + "embedded.mobileprovision":
                            continue

                        # Check if it's a Mach-O binary
                        try:
                            data = z.read(name)
                            if len(data) >= 4:
                                magic = data[:4]
                                if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                            b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                                    result["embedded_binaries"].append({
                                        "path": name,
                                        "size": len(data),
                                        "entropy": round(shannon_entropy(data[:8192]), 3),
                                        "magic": magic.hex(),
                                    })
                        except Exception:
                            pass

                # Find embedded frameworks
                frameworks_dir = app_path + "Frameworks/"
                frameworks = [n for n in names if n.startswith(frameworks_dir) and not n.endswith("/")]
                for fw in frameworks:
                    try:
                        data = z.read(fw)
                        if len(data) >= 4:
                            magic = data[:4]
                            if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                        b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                                result["embedded_frameworks"].append({
                                    "path": fw,
                                    "size": len(data),
                                    "entropy": round(shannon_entropy(data[:8192]), 3),
                                })
                    except Exception:
                        pass

                # Find plugins
                plugins_dir = app_path + "PlugIns/"
                plugins = [n for n in names if n.startswith(plugins_dir) and not n.endswith("/")]
                for pl in plugins:
                    result["embedded_plugins"].append(pl)

                # Resources
                resources = [n for n in names if n.startswith(app_path) and not n.startswith(app_path + "Frameworks/")
                            and not n.startswith(app_path + "PlugIns/") and not n.endswith("/")
                            and n not in [info_plist_path, entitlements_path]]
                result["resources"] = resources[:100]  # Limit

                # Security analysis
                _analyze_ios_security(result)

            else:
                result["errors"] = ["No .app bundle found in IPA"]

    except zipfile.BadZipFile:
        result["errors"] = ["Invalid or corrupted IPA file"]
    except Exception as exc:
        result["errors"] = [f"IPA analysis failed: {exc}"]

    return result


def _analyze_app_bundle(file_path: Path, result: dict) -> dict:
    """Analyze macOS .app bundle (directory)."""
    result["format"] = "macOS App Bundle"
    result["bundle_type"] = "macOS App"

    if not file_path.is_dir():
        result["error"] = "App bundle is not a directory"
        result["available"] = False
        return result

    # Info.plist
    info_plist = file_path / "Contents" / "Info.plist"
    if info_plist.exists():
        try:
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            result["info_plist"] = _parse_info_plist(plist)
        except Exception as exc:
            result["info_plist"] = {"parse_error": str(exc)}

    # Entitlements
    entitlements = file_path / "Contents" / "Resources" / "entitlements.plist"
    if not entitlements.exists():
        entitlements = file_path / "Contents" / "entitlements.plist"
    if entitlements.exists():
        try:
            with open(entitlements, "rb") as f:
                result["entitlements"] = plistlib.load(f)
        except Exception:
            pass

    # Embedded binaries
    macos_dir = file_path / "Contents" / "MacOS"
    if macos_dir.exists():
        for bin_file in macos_dir.iterdir():
            if bin_file.is_file():
                try:
                    data = bin_file.read_bytes()
                    if len(data) >= 4:
                        magic = data[:4]
                        if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
                            result["embedded_binaries"].append({
                                "path": str(bin_file.relative_to(file_path)),
                                "size": len(data),
                                "entropy": round(shannon_entropy(data[:8192]), 3),
                            })
                except Exception:
                    pass

    # Frameworks
    frameworks_dir = file_path / "Contents" / "Frameworks"
    if frameworks_dir.exists():
        for fw in frameworks_dir.rglob("*"):
            if fw.is_file():
                result["embedded_frameworks"].append(str(fw.relative_to(file_path)))

    # Plugins
    plugins_dir = file_path / "Contents" / "PlugIns"
    if plugins_dir.exists():
        for pl in plugins_dir.rglob("*"):
            if pl.is_file():
                result["embedded_plugins"].append(str(pl.relative_to(file_path)))

    # Resources
    resources_dir = file_path / "Contents" / "Resources"
    if resources_dir.exists():
        for res in resources_dir.rglob("*"):
            if res.is_file():
                result["resources"].append(str(res.relative_to(file_path)))

    _analyze_macos_security(result)

    return result


def _analyze_macho_binary(file_path: Path, result: dict) -> dict:
    """Analyze standalone Mach-O binary (.dylib, .framework binary)."""
    result["format"] = "Mach-O Binary"
    result["bundle_type"] = "Mach-O"

    # Use existing deep Mach-O analysis
    try:
        macho_result = analyze_macho_deep(file_path)
        result.update(macho_result)
    except Exception as exc:
        logger.debug(f"Mach-O deep analysis failed: {exc}")
        result["macho_analysis_error"] = str(exc)

    return result


def _parse_info_plist(plist: dict) -> dict:
    """Parse and extract relevant Info.plist fields."""
    keys_of_interest = [
        "CFBundleIdentifier", "CFBundleName", "CFBundleDisplayName",
        "CFBundleVersion", "CFBundleShortVersionString",
        "CFBundleExecutable", "CFBundlePackageType",
        "CFBundleSignature", "CFBundleSupportedPlatforms",
        "MinimumOSVersion", "LSRequiresIPhoneOS",
        "UIRequiredDeviceCapabilities", "UISupportedInterfaceOrientations",
        "NSAppTransportSecurity", "NSAllowsArbitraryLoads",
        "NSExceptionDomains", "ITSAppUsesNonExemptEncryption",
        "UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace",
        "NSCameraUsageDescription", "NSMicrophoneUsageDescription",
        "NSLocationWhenInUseUsageDescription", "NSLocationAlwaysUsageDescription",
        "NSContactsUsageDescription", "NSPhotoLibraryUsageDescription",
        "NSBluetoothPeripheralUsageDescription", "NSCalendarsUsageDescription",
        "NSRemindersUsageDescription", "NSMotionUsageDescription",
        "NSSpeechRecognitionUsageDescription", "NSFaceIDUsageDescription",
        "UIBackgroundModes", "UILaunchStoryboardName",
        "UIMainStoryboardFile", "UISupportedInterfaceOrientations~ipad",
    ]

    parsed = {}
    for key in keys_of_interest:
        if key in plist:
            parsed[key] = plist[key]

    # Also include all keys for completeness
    parsed["_all_keys"] = list(plist.keys())

    return parsed


def _parse_mobileprovision(data: bytes) -> dict:
    """Parse embedded.mobileprovision (CMS signed plist)."""
    try:
        # The mobileprovision is a CMS signed plist
        # Find the plist portion (between <?xml and </plist>)
        xml_start = data.find(b"<?xml")
        xml_end = data.find(b"</plist>")
        if xml_start >= 0 and xml_end >= 0:
            xml_end += len("</plist>")
            plist_data = data[xml_start:xml_end]
            plist = plistlib.loads(plist_data)
            return _parse_provisioning_profile(plist)
    except Exception as exc:
        logger.debug(f"Failed to parse mobileprovision: {exc}")
    return {"parse_error": "Failed to parse provisioning profile"}


def _parse_provisioning_profile(plist: dict) -> dict:
    """Extract relevant fields from provisioning profile."""
    keys = [
        "AppIDName", "ApplicationIdentifierPrefix", "CreationDate",
        "ExpirationDate", "Platform", "DeveloperCertificates",
        "Entitlements", "ProvisionedDevices", "TeamIdentifier",
        "TeamName", "UUID", "Version", "Name",
    ]

    parsed = {}
    for key in keys:
        if key in plist:
            parsed[key] = plist[key]

    # Parse entitlements if present
    if "Entitlements" in plist:
        parsed["Entitlements"] = plist["Entitlements"]

    return parsed


def _analyze_ios_security(result: dict) -> None:
    """Analyze iOS-specific security indicators."""
    info = result.get("info_plist", {})
    entitlements = result.get("provisioning_profile", {}).get("Entitlements", {})

    # Check for debuggable
    if info.get("ITSAppUsesNonExemptEncryption") is False:
        result["suspicious_indicators"].append("App uses non-exempt encryption (may be obfuscated)")

    # Check for arbitrary loads (ATS disabled)
    ats = info.get("NSAppTransportSecurity", {})
    if ats.get("NSAllowsArbitraryLoads") is True:
        result["suspicious_indicators"].append("ATS disabled - allows arbitrary HTTP loads")

    # Check exception domains
    exceptions = ats.get("NSExceptionDomains", {})
    if exceptions:
        result["suspicious_indicators"].append(f"ATS exceptions for domains: {list(exceptions.keys())}")

    # Check entitlements
    if entitlements.get("get-task-allow") is True:
        result["suspicious_indicators"].append("get-task-allow entitlement (debuggable)")

    if entitlements.get("com.apple.security.get-task-allow") is True:
        result["suspicious_indicators"].append("Debug entitlement present")

    # Check for dangerous entitlements
    dangerous_entitlements = [
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.debugger",
    ]
    for ent in dangerous_entitlements:
        if entitlements.get(ent) is True:
            result["suspicious_indicators"].append(f"Dangerous entitlement: {ent}")

    # Check provisioning profile expiry
    exp_date = result.get("provisioning_profile", {}).get("ExpirationDate")
    if exp_date:
        result["provisioning_profile"]["expired"] = _is_expired(exp_date)

    # Check for enterprise distribution
    if result.get("provisioning_profile", {}).get("ProvisionedDevices") is None:
        result["suspicious_indicators"].append("Enterprise distribution profile (no device list)")


def _analyze_macos_security(result: dict) -> None:
    """Analyze macOS-specific security indicators."""
    info = result.get("info_plist", {})
    entitlements = result.get("entitlements", {})

    # Check for hardened runtime
    if entitlements.get("com.apple.security.cs.disable-library-validation") is True:
        result["suspicious_indicators"].append("Library validation disabled")

    if entitlements.get("com.apple.security.cs.allow-unsigned-executable-memory") is True:
        result["suspicious_indicators"].append("Unsigned executable memory allowed")

    if entitlements.get("com.apple.security.cs.allow-dyld-environment-variables") is True:
        result["suspicious_indicators"].append("DYLD environment variables allowed")

    if entitlements.get("com.apple.security.cs.disable-executable-page-protection") is True:
        result["suspicious_indicators"].append("Executable page protection disabled")

    if entitlements.get("com.apple.security.cs.allow-jit") is True:
        result["suspicious_indicators"].append("JIT compilation allowed")

    # Check for sandbox
    if not entitlements.get("com.apple.security.app-sandbox"):
        result["suspicious_indicators"].append("App Sandbox not enabled")


def _is_expired(date_obj) -> bool:
    """Check if date is in the past."""
    from datetime import datetime, timezone
    if isinstance(date_obj, datetime):
        if date_obj.tzinfo is None:
            date_obj = date_obj.replace(tzinfo=timezone.utc)
        return date_obj < datetime.now(timezone.utc)
    return False


def analyze_apple(file_path: Path) -> dict:
    """Main entry point for Apple analysis."""
    return analyze_apple_bundle(file_path)