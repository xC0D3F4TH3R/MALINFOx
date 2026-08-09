"""MALINFO — Firmware Analysis (Embedded devices, IoT, routers, etc.)

Binwalk integration for firmware extraction and analysis.
"""
from __future__ import annotations

import logging
import subprocess
import tempfile
from typing import TYPE_CHECKING, Optional

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.firmware_analysis")


def analyze_firmware(file_path: Path) -> dict:
    """
    Analyze firmware image using binwalk.
    Supports: Router firmware, IoT device firmware, embedded Linux, RTOS, bare metal
    """
    result: dict = {
        "available": True,
        "format": "Firmware Image",
        "architecture": "unknown",
        "endianness": "unknown",
        "os": "unknown",
        "filesystem": "unknown",
        "compression": "unknown",
        "binwalk_results": [],
        "extracted_files": [],
        "kernel_version": "",
        "bootloader": "",
        "bootloader_version": "",
        "device_tree": [],
        "config_files": [],
        "certificates_keys": [],
        "executables": [],
        "scripts": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        # Calculate entropy
        with open(file_path, "rb") as f:
            data = f.read(8192)
        result["entropy"] = round(shannon_entropy(data), 3)

        # Run binwalk
        _run_binwalk(file_path, result)

        # Analyze extracted files if any
        if result.get("extracted_files"):
            _analyze_extracted_firmware(result)

        # Architecture detection from binwalk results
        _detect_architecture(result)

    except Exception as exc:
        logger.debug(f"Firmware analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _run_binwalk(file_path: Path, result: dict) -> None:
    """Run binwalk and parse output."""
    try:
        # Binwalk signature scan
        proc = subprocess.run(
            ["binwalk", "-B", str(file_path)],
            capture_output=True,
            text=True,
            timeout=120
        )
        if proc.returncode == 0:
            result["binwalk_signatures"] = _parse_binwalk_output(proc.stdout)

        # Binwalk extraction (dry-run to see what would be extracted)
        proc = subprocess.run(
            ["binwalk", "-e", "--dry-run", str(file_path)],
            capture_output=True,
            text=True,
            timeout=120
        )
        if proc.returncode == 0:
            result["binwalk_extraction"] = _parse_binwalk_extraction(proc.stdout)

        # Binwalk entropy analysis
        proc = subprocess.run(
            ["binwalk", "-E", str(file_path)],
            capture_output=True,
            text=True,
            timeout=120
        )
        if proc.returncode == 0:
            result["binwalk_entropy"] = _parse_binwalk_entropy(proc.stdout)

    except FileNotFoundError:
        result["errors"].append("binwalk not installed")
    except subprocess.TimeoutExpired:
        result["errors"].append("binwalk timed out")
    except Exception as exc:
        result["errors"].append(f"binwalk failed: {exc}")


def _parse_binwalk_output(output: str) -> list[dict]:
    """Parse binwalk signature scan output."""
    results = []
    lines = output.strip().split("\n")
    for line in lines:
        line = line.strip()
        if not line or line.startswith(("DECIMAL", "---")):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 3:
            try:
                decimal = int(parts[0])
                hex_offset = parts[1]
                description = parts[2]
                results.append({
                    "offset": decimal,
                    "offset_hex": hex_offset,
                    "description": description,
                })
            except ValueError:
                pass
    return results


def _parse_binwalk_extraction(output: str) -> list[dict]:
    """Parse binwalk extraction dry-run output."""
    results = []
    lines = output.strip().split("\n")
    for line in lines:
        line = line.strip()
        if "extracting" in line.lower() or "inflating" in line.lower():
            parts = line.split()
            if len(parts) >= 2:
                results.append({
                    "action": parts[0],
                    "file": " ".join(parts[1:]),
                })
    return results


def _parse_binwalk_entropy(output: str) -> dict:
    """Parse binwalk entropy analysis output."""
    # Binwalk -E outputs entropy data for plotting
    # We'll just note that entropy analysis was performed
    return {"analyzed": True, "output_lines": len(output.strip().split("\n"))}


def _analyze_extracted_firmware(result: dict) -> None:
    """Analyze files extracted by binwalk."""
    # This would typically be done by extracting to a temp directory
    # and running the analysis pipeline on each file
    # For now, we categorize based on binwalk output
    for item in result.get("binwalk_signatures", []):
        desc = item.get("description", "").lower()

        if "linux kernel" in desc:
            result["os"] = "Linux"
            # Extract kernel version
            import re
            match = re.search(r"linux kernel.*?(\d+\.\d+\.\d+)", desc, re.IGNORECASE)
            if match:
                result["kernel_version"] = match.group(1)

        elif "u-boot" in desc or "uboot" in desc:
            result["bootloader"] = "U-Boot"
            import re
            match = re.search(r"u-?boot.*?(\d{4}\.\d{2})", desc, re.IGNORECASE)
            if match:
                result["bootloader_version"] = match.group(1)

        elif "grub" in desc:
            result["bootloader"] = "GRUB"

        elif "squashfs" in desc:
            result["filesystem"] = "SquashFS"
            result["compression"] = "squashfs"

        elif "jffs2" in desc:
            result["filesystem"] = "JFFS2"

        elif "yaffs" in desc:
            result["filesystem"] = "YAFFS"

        elif "ubifs" in desc:
            result["filesystem"] = "UBIFS"

        elif "cramfs" in desc:
            result["filesystem"] = "CRAMFS"

        elif "romfs" in desc:
            result["filesystem"] = "ROMFS"

        elif "ext2" in desc or "ext3" in desc or "ext4" in desc:
            result["filesystem"] = "ext2/3/4"

        elif "fat" in desc or "vfat" in desc:
            result["filesystem"] = "FAT"

        elif "device tree" in desc or "dtb" in desc:
            result["device_tree"].append(item)

        elif "certificate" in desc or "x.509" in desc or "rsa" in desc or "private key" in desc:
            result["certificates_keys"].append(item)

        elif "executable" in desc or "elf" in desc:
            result["executables"].append(item)

        elif "script" in desc or "shell" in desc:
            result["scripts"].append(item)

        elif "gzip" in desc or "lzma" in desc or "xz" in desc or "lz4" in desc or "zstd" in desc:
            if result["compression"] == "unknown":
                result["compression"] = desc.split()[0]


def _detect_architecture(result: dict) -> None:
    """Detect CPU architecture from binwalk results."""
    arch_keywords = {
        "arm": ["arm", "cortex", "armv7", "armv8", "aarch32", "aarch64", "thumb"],
        "mips": ["mips", "mipsel", "mips64", "mips32"],
        "x86": ["x86", "i386", "i686", "intel 80386", "intel 80486"],
        "x64": ["x86-64", "x86_64", "amd64", "intel 64"],
        "powerpc": ["powerpc", "ppc", "power pc"],
        "riscv": ["riscv", "risc-v"],
        "arc": ["arc", "argonaut"],
        "xtensa": ["xtensa", "tensilica"],
        "superh": ["superh", "sh-", "sh4"],
        "m68k": ["m68k", "68000", "68k"],
    }

    for item in result.get("binwalk_signatures", []):
        desc = item.get("description", "").lower()
        for arch, keywords in arch_keywords.items():
            if any(kw in desc for kw in keywords):
                if result["architecture"] == "unknown":
                    result["architecture"] = arch
                elif result["architecture"] != arch:
                    result["architecture"] = f"{result['architecture']}/{arch}"

    # Check endianness
    for item in result.get("binwalk_signatures", []):
        desc = item.get("description", "").lower()
        if "little endian" in desc or "le " in desc:
            result["endianness"] = "little"
        elif "big endian" in desc or "be " in desc:
            result["endianness"] = "big"


def _analyze_firmware_security(result: dict) -> None:
    """Analyze firmware for security issues."""
    # Check for hardcoded credentials
    for item in result.get("binwalk_signatures", []):
        desc = item.get("description", "").lower()
        if any(kw in desc for kw in ["password", "secret", "key", "credential", "admin:admin", "root:root"]):
            result["suspicious_indicators"].append(f"Possible hardcoded credentials: {item['description']}")

    # Check for debug interfaces
    debug_keywords = ["uart", "jtag", "swd", "debug", "console", "shell", "telnet", "ssh"]
    for item in result.get("binwalk_signatures", []):
        desc = item.get("description", "").lower()
        if any(kw in desc for kw in debug_keywords):
            result["suspicious_indicators"].append(f"Debug interface detected: {item['description']}")

    # Check for outdated components
    if result.get("kernel_version"):
        # Would check against known vulnerable versions
        pass

    # Check for missing security features
    if result.get("filesystem") in ["squashfs", "cramfs", "romfs"]:
        result["suspicious_indicators"].append(f"Read-only filesystem ({result['filesystem']}) - may indicate locked down device")


def analyze_firmware_image(file_path: Path) -> dict:
    """Main entry point."""
    result = analyze_firmware(file_path)
    _analyze_firmware_security(result)
    return result