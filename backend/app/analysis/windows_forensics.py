"""MALINFO — Windows Forensics Artifacts Analysis (LNK, Prefetch, Jump Lists, Shellbags, Amcache, Shimcache, SRUM)

Analysis of Windows forensic artifacts.
"""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.windows_forensics")


def analyze_windows_artifact(file_path: Path) -> dict:
    """
    Analyze Windows forensic artifact.
    Supports: LNK, Prefetch (.pf), Jump Lists, Shellbags, Amcache, Shimcache, SRUM/ESEDB
    """
    result: dict = {
        "available": True,
        "format": "Windows Forensic Artifact",
        "artifact_type": "",
        "details": {},
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read(8192)

        result["entropy"] = round(shannon_entropy(data), 3)

        ext = file_path.suffix.lower()

        if ext == ".lnk":
            result["artifact_type"] = "LNK (Shortcut)"
            _analyze_lnk(file_path, data, result)
        elif ext == ".pf":
            result["artifact_type"] = "Prefetch"
            _analyze_prefetch(file_path, data, result)
        elif "automaticdestinations" in file_path.name.lower() or "customdestinations" in file_path.name.lower():
            result["artifact_type"] = "Jump List"
            _analyze_jump_list(file_path, data, result)
        elif ext in (".hve", ".reg", ".dat") and ("amcache" in file_path.name.lower() or "am_cache" in file_path.name.lower()):
            result["artifact_type"] = "Amcache"
            _analyze_amcache(file_path, data, result)
        elif ext in (".hve", ".reg", ".dat") and ("shimcache" in file_path.name.lower() or "appcompat" in file_path.name.lower()):
            result["artifact_type"] = "Shimcache"
            _analyze_shimcache(file_path, data, result)
        elif ext == ".edb" or "srum" in file_path.name.lower():
            result["artifact_type"] = "SRUM/ESEDB"
            _analyze_srum(file_path, data, result)
        # Try to detect by content
        elif data[:4] == b"SCCC":
            result["artifact_type"] = "Prefetch"
            _analyze_prefetch(file_path, data, result)
        elif data[:4] == b"LNK\x00" or data[4:8] == b"\x01\x14\x02\x00":
            result["artifact_type"] = "LNK (Shortcut)"
            _analyze_lnk(file_path, data, result)
        elif data[:4] == b"regf":
            result["artifact_type"] = "Registry Hive"
            _analyze_registry_hive(file_path, data, result)
        else:
            result["errors"].append("Unknown Windows artifact type")

    except Exception as exc:
        logger.debug(f"Windows forensics analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_lnk(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze LNK (Shell Link) file."""
    try:
        # Read full file for parsing
        with open(file_path, "rb") as f:
            data = f.read()

        # LNK header
        if len(data) < 0x4C:
            result["errors"].append("LNK file too small")
            return

        # Shell Link Header (76 bytes)
        clsid = data[0:16]
        if clsid != b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46":
            result["errors"].append("Invalid LNK CLSID")
            return

        link_flags = struct.unpack("<I", data[16:20])[0]
        file_attrs = struct.unpack("<I", data[20:24])[0]
        creation_time = struct.unpack("<Q", data[24:32])[0]
        access_time = struct.unpack("<Q", data[32:40])[0]
        write_time = struct.unpack("<Q", data[40:48])[0]
        file_size = struct.unpack("<I", data[48:52])[0]
        icon_index = struct.unpack("<I", data[52:56])[0]
        show_cmd = struct.unpack("<I", data[56:60])[0]
        hotkey = struct.unpack("<H", data[60:62])[0]
        reserved = data[62:76]

        result["details"]["link_flags"] = _parse_lnk_flags(link_flags)
        result["details"]["file_attributes"] = file_attrs
        result["details"]["creation_time"] = _filetime_to_iso(creation_time)
        result["details"]["access_time"] = _filetime_to_iso(access_time)
        result["details"]["write_time"] = _filetime_to_iso(write_time)
        result["details"]["file_size"] = file_size
        result["details"]["icon_index"] = icon_index
        result["details"]["show_command"] = show_cmd

        # Parse link target ID list
        offset = 76
        idlist_size = struct.unpack("<H", data[offset:offset+2])[0]
        offset += 2 + idlist_size

        # LinkInfo
        if offset + 4 <= len(data):
            linkinfo_size = struct.unpack("<I", data[offset:offset+4])[0]
            if linkinfo_size > 0:
                linkinfo = data[offset:offset+linkinfo_size]
                _parse_lnk_linkinfo(linkinfo, result)

        # String data
        _parse_lnk_strings(data[offset+linkinfo_size:], result)

    except Exception as exc:
        result["errors"].append(f"LNK parsing failed: {exc}")


def _parse_lnk_flags(flags: int) -> list[str]:
    flag_names = {
        0x00000001: "HasLinkTargetIDList",
        0x00000002: "HasLinkInfo",
        0x00000004: "HasName",
        0x00000008: "HasRelativePath",
        0x00000010: "HasWorkingDir",
        0x00000020: "HasArguments",
        0x00000040: "HasIconLocation",
        0x00000080: "IsUnicode",
        0x00000100: "ForceNoLinkInfo",
        0x00000200: "HasExpString",
        0x00000400: "RunInSeparateProcess",
        0x00000800: "Unused",
        0x00001000: "HasDarwinID",
        0x00002000: "RunAsUser",
        0x00004000: "HasExpIcon",
        0x00008000: "NoPidlAlias",
        0x00010000: "RunWithShimLayer",
        0x00020000: "ForceNoLinkTrack",
        0x00040000: "EnableTargetMetadata",
        0x00080000: "DisableLinkPathTracking",
        0x00100000: "DisableKnownFolderTracking",
        0x00200000: "DisableKnownFolderAlias",
        0x00400000: "AllowLinkToLink",
        0x00800000: "UnaliasOnSave",
        0x01000000: "PreferEnvironmentPath",
        0x02000000: "KeepLocalIDListForUNCTarget",
    }
    return [v for k, v in flag_names.items() if flags & k]


def _parse_lnk_linkinfo(data: bytes, result: dict) -> None:
    """Parse LNK LinkInfo structure."""
    try:
        if len(data) < 24:
            return

        header_size = struct.unpack("<I", data[0:4])[0]
        linkinfo_flags = struct.unpack("<I", data[4:8])[0]
        volume_id_offset = struct.unpack("<I", data[8:12])[0]
        local_base_path_offset = struct.unpack("<I", data[12:16])[0]
        network_base_path_offset = struct.unpack("<I", data[16:20])[0]
        common_path_suffix_offset = struct.unpack("<I", data[20:24])[0]

        result["details"]["linkinfo"] = {
            "header_size": header_size,
            "flags": linkinfo_flags,
            "volume_id_offset": volume_id_offset,
            "local_base_path_offset": local_base_path_offset,
            "network_base_path_offset": network_base_path_offset,
            "common_path_suffix_offset": common_path_suffix_offset,
        }

        # Parse volume ID
        if volume_id_offset > 0 and volume_id_offset < len(data):
            vol_data = data[volume_id_offset:]
            if len(vol_data) >= 16:
                vol_type = struct.unpack("<I", vol_data[0:4])[0]
                vol_serial = struct.unpack("<I", vol_data[4:8])[0]
                vol_label_offset = struct.unpack("<I", vol_data[8:12])[0]
                vol_label_len = struct.unpack("<I", vol_data[12:16])[0]
                result["details"]["volume_id"] = {
                    "type": vol_type,
                    "serial": hex(vol_serial),
                    "label_offset": vol_label_offset,
                }

        # Parse local base path
        if local_base_path_offset > 0 and local_base_path_offset < len(data):
            path_data = data[local_base_path_offset:]
            # Try to decode as string
            try:
                if b"\x00\x00" in path_data:
                    path_str = path_data[:path_data.index(b"\x00\x00")].decode("utf-16le", errors="ignore")
                else:
                    path_str = path_data.decode("utf-8", errors="ignore")
                result["details"]["local_base_path"] = path_str.rstrip("\x00")
            except Exception:
                pass

    except Exception as exc:
        logger.debug(f"LinkInfo parsing failed: {exc}")


def _parse_lnk_strings(data: bytes, result: dict) -> None:
    """Parse LNK string data (name, relative path, working dir, arguments, icon)."""
    try:
        strings = {}
        offset = 0
        string_types = [
            "name", "relative_path", "working_dir", "arguments", "icon_location"
        ]

        for s_type in string_types:
            if offset >= len(data):
                break
            # String length (including null terminator)
            if offset + 2 > len(data):
                break
            str_len = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2
            if str_len > 0:
                if offset + str_len * 2 <= len(data):
                    str_data = data[offset:offset+str_len*2]
                    try:
                        strings[s_type] = str_data.decode("utf-16le", errors="ignore").rstrip("\x00")
                    except Exception:
                        strings[s_type] = str_data.decode("utf-8", errors="ignore").rstrip("\x00")
                    offset += str_len * 2

        result["details"]["strings"] = strings

        # Check for suspicious strings
        for key, value in strings.items():
            if value:
                v_lower = value.lower()
                if any(sus in v_lower for sus in ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "download", "http:", "ftp:", "\\temp\\", "\\appdata\\"]):
                    result["suspicious_indicators"].append(f"Suspicious {key}: {value[:200]}")

    except Exception as exc:
        logger.debug(f"LNK string parsing failed: {exc}")


def _analyze_prefetch(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze Windows Prefetch (.pf) file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 148:
            result["errors"].append("Prefetch file too small")
            return

        # Prefetch header (v17/v23/v26/v30)
        version = struct.unpack("<I", data[0:4])[0]
        magic = data[4:8]
        if magic != b"SCCC":
            result["errors"].append("Invalid prefetch magic")
            return

        result["details"]["version"] = version
        result["details"]["magic"] = magic.decode()

        # File name (offset 0x10, 60 bytes)
        name_bytes = data[0x10:0x4C]
        name = name_bytes.decode("utf-16le", errors="ignore").rstrip("\x00")
        result["details"]["executable_name"] = name

        # Prefetch hash (offset 0x4C)
        pf_hash = struct.unpack("<I", data[0x4C:0x50])[0]
        result["details"]["prefetch_hash"] = hex(pf_hash)

        # Run count (offset 0x90 or 0x98 depending on version)
        run_count_offset = 0x90 if version >= 26 else 0x98
        run_count = struct.unpack("<I", data[run_count_offset:run_count_offset+4])[0]
        result["details"]["run_count"] = run_count

        # Last run times (offset 0x80 - 8 FILETIMEs)
        last_run_offset = 0x80
        last_runs = []
        for i in range(8):
            if last_run_offset + 8 <= len(data):
                ft = struct.unpack("<Q", data[last_run_offset:last_run_offset+8])[0]
                if ft > 0:
                    last_runs.append(_filetime_to_iso(ft))
                last_run_offset += 8
        result["details"]["last_run_times"] = last_runs

        # Volume info
        vol_offset = 0x6C
        vol_count = struct.unpack("<I", data[vol_offset:vol_offset+4])[0]
        volumes = []
        vol_offset += 4
        for i in range(vol_count):
            if vol_offset + 40 <= len(data):
                vol_serial = struct.unpack("<I", data[vol_offset:vol_offset+4])[0]
                vol_creation = struct.unpack("<Q", data[vol_offset+4:vol_offset+12])[0]
                vol_offset += 40
                volumes.append({
                    "serial": hex(vol_serial),
                    "creation_time": _filetime_to_iso(vol_creation),
                })
        result["details"]["volumes"] = volumes

        # File references (filenames referenced by the executable)
        # This is complex - simplified
        result["details"]["note"] = "Full file reference parsing requires specialized library"

    except Exception as exc:
        result["errors"].append(f"Prefetch parsing failed: {exc}")


def _analyze_jump_list(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze Jump List (automaticDestinations-ms / customDestinations-ms)."""
    try:
        # Jump Lists are OLE Compound Files
        result["details"]["note"] = "Jump List is OLE Compound File - requires olefile for full parsing"

        # Check for DestList stream
        if b"DestList" in header:
            result["details"]["has_destlist"] = True

    except Exception as exc:
        result["errors"].append(f"Jump List parsing failed: {exc}")


def _analyze_amcache(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze Amcache.hve registry hive."""
    try:
        result["details"]["note"] = "Amcache is a registry hive - requires python-registry or similar for parsing"
        result["details"]["hive_signature"] = header[:4].hex()

    except Exception as exc:
        result["errors"].append(f"Amcache parsing failed: {exc}")


def _analyze_shimcache(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze Shimcache (AppCompatCache)."""
    try:
        result["details"]["note"] = "Shimcache is stored in registry - requires registry parsing"
        result["details"]["hive_signature"] = header[:4].hex()

    except Exception as exc:
        result["errors"].append(f"Shimcache parsing failed: {exc}")


def _analyze_srum(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze SRUM/ESEDB."""
    try:
        result["details"]["note"] = "SRUM is an ESE database - requires libesedb or similar for parsing"
        if header[:4] == b"\x00\x00\x00\x00":
            result["details"]["possible_esedb"] = True

    except Exception as exc:
        result["errors"].append(f"SRUM parsing failed: {exc}")


def _analyze_registry_hive(file_path: Path, header: bytes, result: dict) -> None:
    """Analyze generic registry hive."""
    try:
        if header[:4] == b"regf":
            result["details"]["hive_type"] = "Windows Registry Hive"
            result["details"]["primary_sequence"] = struct.unpack("<I", header[4:8])[0]
            result["details"]["secondary_sequence"] = struct.unpack("<I", header[8:12])[0]
            result["details"]["last_written"] = struct.unpack("<Q", header[12:20])[0]
            result["details"]["major_version"] = struct.unpack("<I", header[20:24])[0]
            result["details"]["minor_version"] = struct.unpack("<I", header[24:28])[0]
            result["details"]["file_type"] = struct.unpack("<I", header[28:32])[0]
            result["details"]["root_key_offset"] = struct.unpack("<I", header[32:36])[0]
        else:
            result["errors"].append("Invalid registry hive signature")

    except Exception as exc:
        result["errors"].append(f"Registry hive parsing failed: {exc}")


def _filetime_to_iso(filetime: int) -> str:
    """Convert Windows FILETIME to ISO 8601 string."""
    if filetime == 0:
        return ""
    try:
        # FILETIME is 100-nanosecond intervals since Jan 1, 1601 UTC
        # Unix epoch is Jan 1, 1970 UTC
        # Difference is 11644473600 seconds
        EPOCH_DIFF = 116444736000000000  # in 100ns units
        unix_time = (filetime - EPOCH_DIFF) // 10000000
        from datetime import datetime, timezone
        return datetime.fromtimestamp(unix_time, tz=timezone.utc).isoformat()
    except Exception:
        return str(filetime)


def analyze_windows_forensics(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_windows_artifact(file_path)