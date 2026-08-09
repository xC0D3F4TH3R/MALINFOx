"""MALINFO — Disk Image Analysis (ISO, VHD, VHDX, VMDK, QCOW2, IMG)

Read-only analysis of disk images with partition/file system enumeration.
"""
from __future__ import annotations

import logging
import subprocess
from typing import TYPE_CHECKING, Optional

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.disk_analysis")


def analyze_disk_image(file_path: Path) -> dict:
    """
    Analyze disk image file.
    Supports: ISO, VHD, VHDX, VMDK, QCOW2, raw IMG
    """
    result: dict = {
        "available": True,
        "format": "unknown",
        "image_type": "",
        "size_bytes": file_path.stat().st_size,
        "partitions": [],
        "file_systems": [],
        "boot_sector": {},
        "mbr_gpt": {},
        "files": [],
        "total_files": 0,
        "suspicious_indicators": [],
        "entropy": 0.0,
        "mountable": False,
        "errors": [],
    }

    try:
        # Determine image type
        with open(file_path, "rb") as f:
            header = f.read(65536)  # Read more for ISO detection at 32KB+

        image_type = _detect_disk_image_type(header, file_path)
        result["image_type"] = image_type
        result["format"] = _format_for_image_type(image_type)

        # Calculate entropy of first 8KB
        with open(file_path, "rb") as f:
            data = f.read(8192)
        result["entropy"] = round(shannon_entropy(data), 3)

        # Analyze based on type
        if image_type == "ISO":
            _analyze_iso(file_path, result)
        elif image_type in ("VHD", "VHDX"):
            _analyze_vhd(file_path, result)
        elif image_type == "VMDK":
            _analyze_vmdk(file_path, result)
        elif image_type == "QCOW2":
            _analyze_qcow2(file_path, result)
        elif image_type == "RAW":
            _analyze_raw_image(file_path, result)
        else:
            result["errors"].append(f"Unsupported disk image type: {image_type}")

        # Check if mountable (requires root/loop device)
        result["mountable"] = _check_mountable(image_type)

    except Exception as exc:
        logger.debug(f"Disk image analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _detect_disk_image_type(header: bytes, file_path: Path) -> str:
    """Detect disk image type from magic bytes and extension."""
    ext = file_path.suffix.lower()

    # ISO 9660 - check at offset 0x8000 (32KB) for primary volume descriptor
    if len(header) >= 0x8005:
        if header[0x8001:0x8006] == b"CD001":
            return "ISO"

    # VHD - "conectix" at offset 0
    if header[:8] == b"conectix":
        return "VHD"

    # VHDX - "vhdxfile" at offset 0
    if header[:8] == b"vhdxfile":
        return "VHDX"

    # VMDK - "KDMV" at offset 0
    if header[:4] == b"KDMV":
        return "VMDK"

    # QCOW2 - "QFI\xfb" at offset 0
    if header[:4] == b"QFI\xfb":
        return "QCOW2"

    # QCOW v1 - "QFI\xfa" at offset 0
    if header[:4] == b"QFI\xfa":
        return "QCOW"

    # Check extension for raw images
    if ext in (".img", ".raw", ".dd", ".dmg", ".bin"):
        return "RAW"

    return "UNKNOWN"


def _format_for_image_type(image_type: str) -> str:
    formats = {
        "ISO": "ISO 9660 / UDF Disk Image",
        "VHD": "Virtual Hard Disk (VHD)",
        "VHDX": "Virtual Hard Disk v2 (VHDX)",
        "VMDK": "VMware Virtual Disk (VMDK)",
        "QCOW2": "QEMU Copy-on-Write v2 (QCOW2)",
        "QCOW": "QEMU Copy-on-Write v1 (QCOW)",
        "RAW": "Raw Disk Image",
        "UNKNOWN": "Unknown Disk Image",
    }
    return formats.get(image_type, f"{image_type} Disk Image")


def _analyze_iso(file_path: Path, result: dict) -> None:
    """Analyze ISO 9660 / UDF image using isoinfo or libcdio."""
    try:
        # Try using isoinfo (cdrkit)
        proc = subprocess.run(
            ["isoinfo", "-d", "-i", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            _parse_isoinfo(proc.stdout, result)

        # List files
        proc = subprocess.run(
            ["isoinfo", "-f", "-i", str(file_path)],
            capture_output=True,
            text=True,
            timeout=60
        )
        if proc.returncode == 0:
            files = proc.stdout.strip().split("\n")
            result["total_files"] = len(files)
            result["files"] = files[:1000]  # Limit
            _categorize_iso_files(files, result)

    except FileNotFoundError:
        result["errors"].append("isoinfo not installed (install cdrkit)")
    except subprocess.TimeoutExpired:
        result["errors"].append("ISO analysis timed out")
    except Exception as exc:
        result["errors"].append(f"ISO analysis failed: {exc}")


def _parse_isoinfo(output: str, result: dict) -> None:
    """Parse isoinfo -d output."""
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("Volume id:"):
            result["volume_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("System id:"):
            result["system_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Volume set id:"):
            result["volume_set_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Publisher id:"):
            result["publisher_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Data preparer id:"):
            result["data_preparer_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Application id:"):
            result["application_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Copyright file id:"):
            result["copyright_file_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Abstract file id:"):
            result["abstract_file_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Bibliographic file id:"):
            result["bibliographic_file_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("Volume set size:"):
            result["volume_set_size"] = line.split(":", 1)[1].strip()
        elif line.startswith("Volume sequence number:"):
            result["volume_sequence_number"] = line.split(":", 1)[1].strip()
        elif line.startswith("Logical block size:"):
            result["logical_block_size"] = line.split(":", 1)[1].strip()
        elif line.startswith("Volume size:"):
            result["volume_size_blocks"] = line.split(":", 1)[1].strip()
        elif line.startswith("Joliet with UCS level:"):
            result["joliet_level"] = line.split(":", 1)[1].strip()
        elif line.startswith("Rock Ridge signatures version:"):
            result["rock_ridge_version"] = line.split(":", 1)[1].strip()


def _categorize_iso_files(files: list[str], result: dict) -> None:
    """Categorize files found in ISO."""
    executables = []
    scripts = []
    documents = []
    archives = []

    for f in files:
        f_lower = f.lower()
        if f_lower.endswith((".exe", ".dll", ".sys", ".msi", ".cab", ".scr")):
            executables.append(f)
        elif f_lower.endswith((".ps1", ".bat", ".cmd", ".vbs", ".js", ".sh", ".py")):
            scripts.append(f)
        elif f_lower.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt")):
            documents.append(f)
        elif f_lower.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz")):
            archives.append(f)

    result["executables"] = executables[:100]
    result["scripts"] = scripts[:100]
    result["documents"] = documents[:100]
    result["archives"] = archives[:100]

    if executables:
        result["suspicious_indicators"].append(f"ISO contains {len(executables)} Windows executables")
    if scripts:
        result["suspicious_indicators"].append(f"ISO contains {len(scripts)} script files")


def _analyze_vhd(file_path: Path, result: dict) -> None:
    """Analyze VHD/VHDX using qemu-img or vhdx tool."""
    try:
        # Use qemu-img info
        proc = subprocess.run(
            ["qemu-img", "info", "--output=json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            import json
            info = json.loads(proc.stdout)
            result["virtual_size"] = info.get("virtual-size", 0)
            result["actual_size"] = info.get("actual-size", 0)
            result["format"] = info.get("format", "")
            result["cluster_size"] = info.get("cluster-size", 0)
            result["dirty_flag"] = info.get("dirty-flag", False)
            result["backing_file"] = info.get("backing-filename", "")

        # Try to get partition info
        _get_partition_info(file_path, result)

    except FileNotFoundError:
        result["errors"].append("qemu-img not installed")
    except Exception as exc:
        result["errors"].append(f"VHD analysis failed: {exc}")


def _analyze_vmdk(file_path: Path, result: dict) -> None:
    """Analyze VMDK using qemu-img."""
    try:
        proc = subprocess.run(
            ["qemu-img", "info", "--output=json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            import json
            info = json.loads(proc.stdout)
            result["virtual_size"] = info.get("virtual-size", 0)
            result["actual_size"] = info.get("actual-size", 0)
            result["format"] = info.get("format", "")
            result["backing_file"] = info.get("backing-filename", "")

            # VMDK specific - check descriptor
            if file_path.suffix.lower() == ".vmdk":
                with open(file_path, "rb") as f:
                    header = f.read(1024)
                    if b"KDMV" in header:
                        result["descriptor_found"] = True

        _get_partition_info(file_path, result)

    except Exception as exc:
        result["errors"].append(f"VMDK analysis failed: {exc}")


def _analyze_qcow2(file_path: Path, result: dict) -> None:
    """Analyze QCOW2 using qemu-img."""
    try:
        proc = subprocess.run(
            ["qemu-img", "info", "--output=json", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            import json
            info = json.loads(proc.stdout)
            result["virtual_size"] = info.get("virtual-size", 0)
            result["actual_size"] = info.get("actual-size", 0)
            result["format"] = info.get("format", "")
            result["cluster_size"] = info.get("cluster-size", 0)
            result["snapshots"] = info.get("snapshots", [])
            result["backing_file"] = info.get("backing-filename", "")
            result["refcount_bits"] = info.get("refcount-bits", 0)
            result["encryption"] = info.get("encryption", "")
            result["compression_type"] = info.get("compression-type", "")

        _get_partition_info(file_path, result)

    except Exception as exc:
        result["errors"].append(f"QCOW2 analysis failed: {exc}")


def _analyze_raw_image(file_path: Path, result: dict) -> None:
    """Analyze raw disk image - check MBR/GPT and partitions."""
    try:
        with open(file_path, "rb") as f:
            mbr = f.read(512)

        # Check MBR signature
        if mbr[510:512] == b"\x55\xaa":
            result["mbr_gpt"]["has_mbr"] = True
            result["mbr_gpt"]["mbr_signature"] = "0x55AA"
            _parse_mbr(mbr, result)
        else:
            result["mbr_gpt"]["has_mbr"] = False

        # Check GPT (sector 1)
        f.seek(512)
        gpt_header = f.read(512)
        if gpt_header[:8] == b"EFI PART":
            result["mbr_gpt"]["has_gpt"] = True
            _parse_gpt(file_path, gpt_header, result)

        # Try qemu-img for partition info
        _get_partition_info(file_path, result)

    except Exception as exc:
        result["errors"].append(f"Raw image analysis failed: {exc}")


def _parse_mbr(mbr: bytes, result: dict) -> None:
    """Parse MBR partition table."""
    partitions = []
    for i in range(4):
        offset = 446 + i * 16
        part = mbr[offset:offset+16]
        if len(part) == 16:
            status = part[0]
            start_chs = part[1:4]
            part_type = part[4]
            end_chs = part[5:8]
            start_lba = int.from_bytes(part[8:12], "little")
            size_sectors = int.from_bytes(part[12:16], "little")

            if part_type != 0:
                partitions.append({
                    "number": i + 1,
                    "bootable": status == 0x80,
                    "type": hex(part_type),
                    "type_name": _mbr_partition_type_name(part_type),
                    "start_lba": start_lba,
                    "size_sectors": size_sectors,
                    "size_bytes": size_sectors * 512,
                })

    result["partitions"] = partitions


def _mbr_partition_type_name(part_type: int) -> str:
    types = {
        0x01: "FAT12",
        0x04: "FAT16 <32M",
        0x05: "Extended",
        0x06: "FAT16",
        0x07: "NTFS/exFAT",
        0x0B: "FAT32",
        0x0C: "FAT32 LBA",
        0x0E: "FAT16 LBA",
        0x0F: "Extended LBA",
        0x12: "Compaq Diagnostics",
        0x17: "Hidden NTFS",
        0x1B: "Hidden FAT32",
        0x1C: "Hidden FAT32 LBA",
        0x1E: "Hidden FAT16 LBA",
        0x27: "Windows Recovery",
        0x2B: "BSDI fs",
        0x3C: "PartitionMagic Recovery",
        0x42: "LDM (Dynamic Disk)",
        0x82: "Linux Swap",
        0x83: "Linux Filesystem",
        0x84: "Linux Extended",
        0x85: "Linux LVM",
        0x86: "Linux RAID",
        0x8E: "Linux LVM (old)",
        0xA5: "FreeBSD",
        0xA6: "OpenBSD",
        0xA8: "macOS UFS",
        0xA9: "NetBSD",
        0xAB: "macOS Boot",
        0xAF: "macOS HFS+",
        0xEE: "GPT Protective",
        0xEF: "EFI System Partition",
        0xFB: "VMware VMFS",
        0xFC: "VMware Swap",
    }
    return types.get(part_type, f"Unknown (0x{part_type:02x})")


def _parse_gpt(file_path: Path, gpt_header: bytes, result: dict) -> None:
    """Parse GPT partition table."""
    # GPT header fields
    my_lba = int.from_bytes(gpt_header[24:32], "little")
    first_usable_lba = int.from_bytes(gpt_header[40:48], "little")
    last_usable_lba = int.from_bytes(gpt_header[48:56], "little")
    disk_guid = gpt_header[56:72].hex()
    part_entry_start_lba = int.from_bytes(gpt_header[72:80], "little")
    num_part_entries = int.from_bytes(gpt_header[80:84], "little")
    part_entry_size = int.from_bytes(gpt_header[84:88], "little")
    part_entry_crc32 = int.from_bytes(gpt_header[88:92], "little")

    result["mbr_gpt"]["gpt"] = {
        "my_lba": my_lba,
        "first_usable_lba": first_usable_lba,
        "last_usable_lba": last_usable_lba,
        "disk_guid": disk_guid,
        "partition_entry_start_lba": part_entry_start_lba,
        "num_partition_entries": num_part_entries,
        "partition_entry_size": part_entry_size,
        "partition_entry_crc32": hex(part_entry_crc32),
    }

    # Read partition entries
    try:
        with open(file_path, "rb") as f:
            f.seek(part_entry_start_lba * 512)
            for i in range(min(num_part_entries, 128)):  # Limit
                entry = f.read(part_entry_size)
                if len(entry) < 128:
                    break

                part_type_guid = entry[0:16].hex()
                part_guid = entry[16:32].hex()
                first_lba = int.from_bytes(entry[32:40], "little")
                last_lba = int.from_bytes(entry[40:48], "little")
                attrs = int.from_bytes(entry[48:56], "little")
                name_utf16 = entry[56:128]
                name = name_utf16.decode("utf-16le", errors="ignore").rstrip("\x00")

                if first_lba != 0 or last_lba != 0:
                    result["partitions"].append({
                        "number": len(result["partitions"]) + 1,
                        "type_guid": part_type_guid,
                        "type_name": _gpt_type_guid_name(part_type_guid),
                        "partition_guid": part_guid,
                        "first_lba": first_lba,
                        "last_lba": last_lba,
                        "size_bytes": (last_lba - first_lba + 1) * 512,
                        "attributes": hex(attrs),
                        "name": name,
                    })
    except Exception as exc:
        logger.debug(f"Failed to parse GPT entries: {exc}")


def _gpt_type_guid_name(type_guid: str) -> str:
    guids = {
        "c12a7328f81f11d2ba4b00a0c93ec93b": "EFI System Partition",
        "e3c9e3160b5c4db8817df92df00215ae": "Microsoft Reserved",
        "ebd0a0a2b9e5443387c068b6b72699c7": "Microsoft Basic Data",
        "0fc63daf848347728e793d69d8477de4": "Linux Filesystem",
        "0657fd6da4ab434c84e50933c84b4f4f": "Linux Swap",
        "e6d6d379f50744c2a23c238f2a3df928": "Linux LVM",
        "a19d880f05fc4d3ba006743f0f84911e": "Linux RAID",
        "4f68bce3e8cd4db196e7fbcaa6c5a1db": "Linux Root (x86-64)",
        "4fbd7e299d2541b8afd0062c0fcce9b7": "Linux Root (ARM64)",
        "773f91ef66d44929b3a4b04c9867c8d1": "Linux /home",
        "3b8f842520e04f3b907f1a25a76f98e8": "Linux /srv",
        "8da63339000760c0c436083ac8230908": "Linux DM-Crypt",
        "ca7d7ccb63ed42d386a4d1d9e2e8d0b8": "Linux LUKS",
        "5808c8aa7e8f42e085d2e1e90434cfb3": "macOS HFS+",
        "7c3457ef000011aaaa1100306543ecac": "macOS APFS",
        "9d075cb3fa704f9a9d9e0c8b2b1b1b1b": "FreeBSD UFS",
        "a86b8b8b8b8b8b8b8b8b8b8b8b8b8b8b": "FreeBSD ZFS",
    }
    return guids.get(type_guid.lower(), "Unknown")


def _get_partition_info(file_path: Path, result: dict) -> None:
    """Get partition info using sfdisk or fdisk."""
    try:
        # Try sfdisk (Linux)
        proc = subprocess.run(
            ["sfdisk", "-l", "-J", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            import json
            data = json.loads(proc.stdout)
            for pt in data.get("partitiontable", {}).get("partitions", []):
                result["partitions"].append({
                    "number": pt.get("number"),
                    "start": pt.get("start"),
                    "size": pt.get("size"),
                    "type": pt.get("type"),
                    "type_name": pt.get("name", ""),
                    "uuid": pt.get("uuid", ""),
                })
            return
    except Exception:
        pass

    try:
        # Try fdisk
        proc = subprocess.run(
            ["fdisk", "-l", str(file_path)],
            capture_output=True,
            text=True,
            timeout=30
        )
        if proc.returncode == 0:
            result["fdisk_output"] = proc.stdout[:2000]
    except Exception:
        pass


def _check_mountable(image_type: str) -> bool:
    """Check if image type is mountable on current system."""
    mountable_types = ["ISO", "VHD", "VHDX", "RAW"]
    return image_type in mountable_types


def analyze_disk(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_disk_image(file_path)