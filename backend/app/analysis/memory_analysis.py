"""MALINFO — Memory Dump Analysis (Volatility3 integration)

Analysis of memory dumps: raw, WinPMEM, LIME, hibernation, crash dumps.
"""
from __future__ import annotations

import json
import logging
import subprocess
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.memory_analysis")


def analyze_memory_dump(file_path: Path) -> dict:
    """
    Analyze memory dump using Volatility3.
    Supports: Raw, WinPMEM, LIME, Hibernation, Crash dumps, VM snapshots
    """
    result: dict = {
        "available": True,
        "format": "Memory Dump",
        "dump_type": "unknown",
        "os": "unknown",
        "profile": "",
        "kdbg": "",
        "processes": [],
        "network_connections": [],
        "dlls": [],
        "handles": [],
        "malfind": [],
        "hollowfind": [],
        "apihooks": [],
        "ssdt": [],
        "cmdline": [],
        "svcscan": [],
        "driverirp": [],
        "etwtamper": [],
        "ldrmodules": [],
        "pslist": [],
        "pstree": [],
        "files": [],
        "registry": [],
        "timers": [],
        "callbacks": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        # Calculate entropy
        with open(file_path, "rb") as f:
            data = f.read(8192)
        result["entropy"] = round(shannon_entropy(data), 3)

        # Detect dump type
        result["dump_type"] = _detect_dump_type(file_path)

        # Run Volatility3 plugins
        _run_volatility3(file_path, result)

    except Exception as exc:
        logger.debug(f"Memory analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _detect_dump_type(file_path: Path) -> str:
    """Detect memory dump type from header."""
    with open(file_path, "rb") as f:
        header = f.read(4096)

    # Windows crash dump
    if header[:4] == b"PAGE" or header[:4] == b"DUMP":
        return "Windows Crash Dump"

    # Windows hibernation
    if header[:8] == b"HIBR" or header[:4] == b"HIBR":
        return "Windows Hibernation File"

    # LIME (Linux Memory Extractor)
    if b"LIME" in header[:100]:
        return "LIME (Linux)"

    # WinPMEM
    if b"PMEM" in header[:100] or b"winpmem" in header[:100].lower():
        return "WinPMEM"

    # macOS memory dump
    if header[:4] == b"mach" or header[:4] == b"MACH":
        return "macOS Memory Dump"

    # VMware snapshot (.vmsn)
    if header[:4] == b"VMSS":
        return "VMware Snapshot"

    # VirtualBox saved state
    if b"VBOX" in header[:100]:
        return "VirtualBox Saved State"

    # QEMU/KVM dump
    if b"QEMU" in header[:100]:
        return "QEMU/KVM Dump"

    # Raw dump - check for ELF (Linux kernel)
    if header[:4] == b"\x7fELF":
        return "Raw (ELF Kernel)"

    return "Raw/Unknown"


def _run_volatility3(file_path: Path, result: dict) -> None:
    """Run Volatility3 plugins on memory dump."""
    # Determine OS/profile
    dump_type = result.get("dump_type", "").lower()

    if "windows" in dump_type or "crash" in dump_type or "hibernation" in dump_type or "winpmem" in dump_type:
        result["os"] = "windows"
        plugins = [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.dlllist",
            "windows.handles",
            "windows.malfind",
            "windows.hollowfind",
            "windows.cmdline",
            "windows.svcscan",
            "windows.driverirp",
            "windows.etwtamper",
            "windows.ldrmodules",
            "windows.apihooks",
            "windows.ssdt",
            "windows.callbacks",
            "windows.timers",
            "windows.registry.hivelist",
            "windows.registry.printkey",
            "windows.filescan",
            "windows.dumpfiles",
            "windows.memmap",
            "windows.vadinfo",
            "windows.vadwalk",
            "windows.verinfo",
            "windows.getsids",
            "windows.privileges",
            "windows.netstat",
            "windows.netscan",
        ]
    elif "linux" in dump_type or "lime" in dump_type:
        result["os"] = "linux"
        plugins = [
            "linux.info",
            "linux.pslist",
            "linux.pstree",
            "linux.lsmod",
            "linux.netstat",
            "linux.netfilter",
            "linux.mount",
            "linux.arp",
            "linux.route_cache",
            "linux.slab",
            "linux.cred",
            "linux.capabilities",
            "linux.check_creds",
            "linux.check_modules",
            "linux.check_syscall",
            "linux.check_idt",
            "linux.check_kallsyms",
            "linux.enum_files",
            "linux.getcwd",
            "linux.psaux",
            "linux.environ",
            "linux.malfind",
            "linux.truecrypt",
        ]
    elif "macos" in dump_type or "mach" in dump_type:
        result["os"] = "macos"
        plugins = [
            "mac.info",
            "mac.pslist",
            "mac.pstree",
            "mac.netstat",
            "mac.ifconfig",
            "mac.mount",
            "mac.dyld",
            "mac.kexts",
            "mac.malfind",
            "mac.check_syscall",
            "mac.check_kern_structs",
        ]
    else:
        # Try auto-detection with windows.info first
        plugins = ["windows.info", "linux.info", "mac.info"]

    for plugin in plugins:
        _run_volatility_plugin(file_path, plugin, result)


def _run_volatility_plugin(file_path: Path, plugin: str, result: dict) -> None:
    """Run a single Volatility3 plugin."""
    try:
        # Use volatility3 CLI
        proc = subprocess.run(
            ["python", "-m", "volatility3", "-f", str(file_path), plugin, "--output=json"],
            capture_output=True,
            text=True,
            timeout=120
        )

        if proc.returncode == 0:
            try:
                data = json.loads(proc.stdout)
                # Store in result with plugin name as key
                key = plugin.replace(".", "_").replace("-", "_")
                result[key] = data
            except json.JSONDecodeError:
                # Some plugins output text, not JSON
                key = plugin.replace(".", "_").replace("-", "_")
                result[key] = {"raw_output": proc.stdout[:5000]}
        else:
            # Plugin failed - might not be applicable to this OS
            pass

    except FileNotFoundError:
        result["errors"].append("Volatility3 not installed")
    except subprocess.TimeoutExpired:
        result["errors"].append(f"Volatility3 plugin {plugin} timed out")
    except Exception as exc:
        logger.debug(f"Volatility3 plugin {plugin} failed: {exc}")


def _analyze_memory_results(result: dict) -> None:
    """Post-process Volatility3 results for suspicious indicators."""
    # Check malfind for injected code
    malfind = result.get("windows_malfind", {})
    if isinstance(malfind, dict) and "rows" in malfind:
        for row in malfind["rows"]:
            if row.get("Protection") in ("PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"):
                result["suspicious_indicators"].append(
                    f"RWX memory region in PID {row.get('PID')}: {row.get('Protection')}"
                )

    # Check hollowfind for process hollowing
    hollowfind = result.get("windows_hollowfind", {})
    if isinstance(hollowfind, dict) and "rows" in hollowfind:
        for row in hollowfind["rows"]:
            result["suspicious_indicators"].append(
                f"Possible process hollowing: PID {row.get('PID')} ({row.get('Process')})"
            )

    # Check apihooks for API hooking
    apihooks = result.get("windows_apihooks", {})
    if isinstance(apihooks, dict) and "rows" in apihooks:
        for row in apihooks["rows"]:
            if row.get("HookType") in ("Inline", "IAT", "EAT"):
                result["suspicious_indicators"].append(
                    f"API hook detected: {row.get('Function')} in {row.get('Module')} (PID {row.get('PID')})"
                )

    # Check ldrmodules for unlinked/hidden modules
    ldrmodules = result.get("windows_ldrmodules", {})
    if isinstance(ldrmodules, dict) and "rows" in ldrmodules:
        for row in ldrmodules["rows"]:
            if row.get("InLoad") == "False" or row.get("InInit") == "False" or row.get("InMem") == "False":
                result["suspicious_indicators"].append(
                    f"Hidden/unlinked module: {row.get('BaseDllName')} in PID {row.get('PID')}"
                )

    # Check svcscan for suspicious services
    svcscan = result.get("windows_svcscan", {})
    if isinstance(svcscan, dict) and "rows" in svcscan:
        for row in svcscan["rows"]:
            if row.get("BinaryPath") and any(sus in row.get("BinaryPath", "").lower()
                for sus in ["temp", "appdata", "programdata", "windows\\tasks", "recycle"]):
                result["suspicious_indicators"].append(
                    f"Suspicious service path: {row.get('ServiceName')} -> {row.get('BinaryPath')}"
                )

    # Check driverirp for IRP hooks
    driverirp = result.get("windows_driverirp", {})
    if isinstance(driverirp, dict) and "rows" in driverirp:
        for row in driverirp["rows"]:
            if row.get("Hooked") == "True":
                result["suspicious_indicators"].append(
                    f"IRP hook: {row.get('DriverName')} -> {row.get('DeviceName')}"
                )

    # Check callbacks for suspicious callbacks
    callbacks = result.get("windows_callbacks", {})
    if isinstance(callbacks, dict) and "rows" in callbacks:
        for row in callbacks["rows"]:
            if row.get("Module") and "unknown" in row.get("Module", "").lower():
                result["suspicious_indicators"].append(
                    f"Unknown callback module: {row.get('Type')} at {row.get('Address')}"
                )


def analyze_memory(file_path: Path) -> dict:
    """Main entry point."""
    result = analyze_memory_dump(file_path)
    _analyze_memory_results(result)
    return result