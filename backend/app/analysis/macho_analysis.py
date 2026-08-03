"""
macOS / iOS Mach-O static analysis via `macholib`.

Dynamic detonation is out of scope for iOS entirely (see sandbox/README.md)
and requires Apple Silicon hardware for macOS — this module covers the
*static* side only, which is fully achievable cross-platform.
"""
from __future__ import annotations

from pathlib import Path


def analyze_macho(file_path: Path) -> dict:
    try:
        from macholib.MachO import MachO
    except ImportError:
        return {"error": "macholib not installed", "available": False}

    try:
        m = MachO(str(file_path))
    except Exception as exc:
        return {"error": f"Failed to parse Mach-O: {exc}", "available": False}

    result: dict = {"available": True, "architectures": [], "load_commands_sample": [], "is_fat_binary": len(m.headers) > 1}

    for header in m.headers:
        arch = {
            "cpu_type": header.header.cputype,
            "cpu_subtype": header.header.cpusubtype,
            "file_type": header.header.filetype,
            "load_command_count": header.header.ncmds,
        }
        result["architectures"].append(arch)

        cmd_names = []
        for cmd in header.commands[:50]:
            try:
                cmd_names.append(cmd[0].get_cmd_name())
            except Exception:
                continue
        result["load_commands_sample"].extend(cmd_names)

    return result
