"""Linux ELF static analysis via `pyelftools`."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_SUSPICIOUS_SYMBOLS = {
    "ptrace", "execve", "socket", "connect", "fork", "setuid", "system",
    "dlopen", "mprotect", "LD_PRELOAD", "prctl",
}


def analyze_elf(file_path: Path) -> dict:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools not installed", "available": False}

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            result: dict = {
                "available": True,
                "ei_class": elf.elfclass,  # 32 or 64
                "e_type": elf.header["e_type"],
                "e_machine": elf.header["e_machine"],
                "entry_point": hex(elf.header["e_entry"]),
                "is_stripped": True,
                "sections": [],
                "dynamic_symbols_sample": [],
                "suspicious_symbols": [],
                "interpreter": None,
            }

            symtab_present = False
            for section in elf.iter_sections():
                result["sections"].append({
                    "name": section.name,
                    "size": section["sh_size"],
                })
                if section.name in (".symtab", ".debug_info"):
                    symtab_present = True
                if section.name == ".interp":
                    try:
                        result["interpreter"] = section.data().rstrip(b"\x00").decode(errors="ignore")
                    except Exception:
                        pass

            result["is_stripped"] = not symtab_present

            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym is not None:
                names = [sym.name for sym in dynsym.iter_symbols() if sym.name]
                result["dynamic_symbols_sample"] = names[:200]
                result["suspicious_symbols"] = sorted(
                    {n for n in names if n in _SUSPICIOUS_SYMBOLS}
                )

            return result
    except Exception as exc:
        return {"error": f"Failed to parse ELF: {exc}", "available": False}
