"""
MALINFO — Deep Linux ELF Static Analysis.

Comprehensive ELF analysis for professional malware analysis and reverse engineering.
Includes: Dynamic segment hardening flags (BIND_NOW, RELRO), DT_NEEDED/RPATH/RUNPATH,
version definitions/requirements (gnu.version), .note.gnu.build-id, .note.ABI-tag,
interpreter path, symbol visibility, init/fini arrays, GO/Rust binary detection.
"""
from __future__ import annotations

import logging
from pathlib import Path

from app.analysis.strings_entropy import shannon_entropy

logger = logging.getLogger("malinfo.elf_deep")

_SUSPICIOUS_SYMBOLS = {
    "ptrace", "execve", "socket", "connect", "fork", "setuid", "system",
    "dlopen", "dlsym", "mprotect", "LD_PRELOAD", "prctl", "process_vm_readv", "process_vm_writev", "memfd_create", "userfaultfd",
    "pivot_root", "chroot", "setns", "unshare", "clone", "vfork",
    "accept", "bind", "listen", "sendto", "recvfrom", "sendmsg", "recvmsg",
    "inet_ntop", "inet_pton", "getaddrinfo", "gethostbyname",
    "crypt", "encrypt", "decrypt", "MD5_Init", "SHA1_Init", "SHA256_Init",
    "AES_set_encrypt_key", "AES_encrypt", "RC4", "ChaCha20",
    "RSA_public_encrypt", "RSA_private_decrypt", "EVP_EncryptInit",
    "EVP_DecryptInit", "EVP_CipherInit",
}

# Hardening flags from DT_FLAGS_1
_DT_FLAGS_1 = {
    0x00000001: "NOW",           # Lazy binding disabled
    0x00000002: "GLOBAL",        # Global symbols visible
    0x00000004: "GROUP",         # Object is a group
    0x00000008: "NODELETE",      # Don't unload on dlclose
    0x00000010: "NOOPEN",        # Can't be dlopen'd
    0x00000020: "ORIGIN",        # $ORIGIN processing required
    0x00000040: "INTERPOSE",     # Symbol table interposes
    0x00000080: "NODEFLIB",      # Ignore default library search path
    0x00000100: "FILTER",        # Filter on dependencies
    0x00000200: "PIE",           # Position Independent Executable
    0x00000400: "NOW",           # Same as NOW (alias)
    0x00000800: "RELRO",         # RELRO (partial)
    0x00001000: "BIND_NOW",      # Bind now (full RELRO)
}

def analyze_elf_deep(file_path: Path) -> dict:
    """
    Comprehensive ELF analysis.
    """
    try:
        from elftools.elf.dynamic import DynamicSection
        from elftools.elf.elffile import ELFFile
        from elftools.elf.gnuversions import (
            GNUVerDefSection,
            GNUVerNeedSection,
            GNUVerSymSection,
        )
        from elftools.elf.relocation import RelocationSection
        from elftools.elf.sections import NoteSection, SymbolTableSection
    except ImportError:
        return {"error": "pyelftools not installed", "available": False}

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            
            result: dict = {
                "available": True,
                "ei_class": elf.elfclass,  # 32 or 64
                "ei_data": "LSB" if elf.little_endian else "MSB",
                "e_type": elf.header["e_type"],
                "e_type_str": _etype_to_str(elf.header["e_type"]),
                "e_machine": elf.header["e_machine"],
                "e_machine_str": _emachine_to_str(elf.header["e_machine"]),
                "entry_point": hex(elf.header["e_entry"]),
                "program_header_count": elf.header["e_phnum"],
                "section_header_count": elf.header["e_shnum"],
                "flags": elf.header["e_flags"],
                "is_stripped": True,
                "sections": [],
                "segments": [],
                "dynamic_symbols_sample": [],
                "suspicious_symbols": [],
                "interpreter": None,
                "needed_libraries": [],
                "rpath": None,
                "runpath": None,
                "hardening": {},
                "build_id": None,
                "abi_tag": None,
                "version_info": {},
                "init_fini_arrays": [],
                "go_info": None,
                "rust_info": None,
                "symbol_visibility": {},
                "relocations": [],
                "notes": [],
            }

            # ─── Sections ───
            symtab_present = False
            for section in elf.iter_sections():
                sec_info = {
                    "name": section.name,
                    "type": section["sh_type"],
                    "type_str": _sh_type_to_str(section["sh_type"]),
                    "flags": section["sh_flags"],
                    "flags_str": _sh_flags_to_str(section["sh_flags"]),
                    "address": hex(section["sh_addr"]),
                    "offset": section["sh_offset"],
                    "size": section["sh_size"],
                    "link": section["sh_link"],
                    "info": section["sh_info"],
                    "alignment": section["sh_addralign"],
                    "entropy": 0.0,
                }
                
                # Calculate entropy for loadable sections
                if section["sh_type"] == 1:  # SHT_PROGBITS
                    data = section.data()
                    if data:
                        sec_info["entropy"] = round(shannon_entropy(data), 3)
                
                result["sections"].append(sec_info)
                
                if section.name in (".symtab", ".debug_info"):
                    symtab_present = True
                
                if section.name == ".interp":
                    try:
                        result["interpreter"] = section.data().rstrip(b"\x00").decode(errors="ignore")
                    except Exception:
                        pass

            result["is_stripped"] = not symtab_present

            # ─── Program Headers (Segments) ───
            for segment in elf.iter_segments():
                seg_info = {
                    "type": segment["p_type"],
                    "type_str": _ptype_to_str(segment["p_type"]),
                    "flags": segment["p_flags"],
                    "flags_str": _pflags_to_str(segment["p_flags"]),
                    "offset": hex(segment["p_offset"]),
                    "vaddr": hex(segment["p_vaddr"]),
                    "paddr": hex(segment["p_paddr"]),
                    "filesz": segment["p_filesz"],
                    "memsz": segment["p_memsz"],
                    "alignment": segment["p_align"],
                }
                result["segments"].append(seg_info)
                
                # PT_INTERP
                if segment["p_type"] == 3:  # PT_INTERP
                    try:
                        data = segment.data()
                        if data:
                            result["interpreter"] = data.rstrip(b"\x00").decode(errors="ignore")
                    except Exception:
                        pass

            # ─── Dynamic Section ───
            dyn_section = elf.get_section_by_name(".dynamic")
            if dyn_section and isinstance(dyn_section, DynamicSection):
                dyn_info = _parse_dynamic_section(dyn_section, elf)
                result.update(dyn_info)

            # ─── Dynamic Symbols ───
            dynsym = elf.get_section_by_name(".dynsym")
            if dynsym and isinstance(dynsym, SymbolTableSection):
                names = [sym.name for sym in dynsym.iter_symbols() if sym.name]
                result["dynamic_symbols_sample"] = names[:500]
                result["suspicious_symbols"] = sorted(
                    {n for n in names if n in _SUSPICIOUS_SYMBOLS}
                )
                
                # Symbol visibility
                vis_counts = {"DEFAULT": 0, "HIDDEN": 0, "INTERNAL": 0, "PROTECTED": 0}
                for sym in dynsym.iter_symbols():
                    if sym.name:
                        vis = sym["st_other"] & 0x3
                        if vis == 0:
                            vis_counts["DEFAULT"] += 1
                        elif vis == 1:
                            vis_counts["HIDDEN"] += 1
                        elif vis == 2:
                            vis_counts["INTERNAL"] += 1
                        elif vis == 3:
                            vis_counts["PROTECTED"] += 1
                result["symbol_visibility"] = vis_counts

            # ─── Version Info (gnu.version, gnu.version_d, gnu.version_r) ───
            result["version_info"] = _parse_version_sections(elf)

            # ─── Notes (.note.gnu.build-id, .note.ABI-tag, etc.) ───
            result["notes"] = _parse_notes(elf)
            for note in result["notes"]:
                if note["name"] == "GNU" and note["type"] == 3:  # NT_GNU_BUILD_ID
                    result["build_id"] = note["desc"].hex()
                elif note["name"] == "GNU" and note["type"] == 1:  # NT_GNU_ABI_TAG
                    result["abi_tag"] = _parse_abi_tag(note["desc"])

            # ─── Init/Fini Arrays ───
            result["init_fini_arrays"] = _parse_init_fini_arrays(elf)

            # ─── Relocations ───
            result["relocations"] = _parse_relocations(elf)

            # ─── Go Binary Detection ───
            result["go_info"] = _detect_go_binary(elf)

            # ─── Rust Binary Detection ───
            result["rust_info"] = _detect_rust_binary(elf)

    except Exception as exc:
        logger.exception("ELF deep analysis failed")
        return {"error": f"Failed to parse ELF: {exc}", "available": False}

    return result


def _parse_dynamic_section(dyn_section, elf) -> dict:
    """Parse .dynamic section for DT_* entries."""
    result = {
        "needed_libraries": [],
        "rpath": None,
        "runpath": None,
        "hardening": {},
        "init_array": None,
        "fini_array": None,
        "init_array_sz": 0,
        "fini_array_sz": 0,
        "plt_got": None,
        "plt_rel": None,
        "plt_rel_sz": 0,
        "flags_1": 0,
    }
    
    for tag in dyn_section.iter_tags():
        tag_name = tag.entry.d_tag
        val = tag.entry.d_val
        
        if tag_name == "DT_NEEDED":
            result["needed_libraries"].append(tag.needed.decode(errors="ignore"))
        elif tag_name == "DT_RPATH":
            result["rpath"] = tag.needed.decode(errors="ignore") if tag.needed else None
        elif tag_name == "DT_RUNPATH":
            result["runpath"] = tag.needed.decode(errors="ignore") if tag.needed else None
        elif tag_name == "DT_FLAGS_1":
            result["hardening"]["flags_1"] = val
            result["hardening"]["flags_1_decoded"] = _decode_dt_flags_1(val)
        elif tag_name == "DT_FLAGS":
            result["hardening"]["flags"] = val
            result["hardening"]["flags_decoded"] = _decode_dt_flags(val)
        elif tag_name == "DT_BIND_NOW":
            result["hardening"]["bind_now"] = True
        elif tag_name == "DT_INIT_ARRAY":
            result["init_array"] = hex(val)
        elif tag_name == "DT_FINI_ARRAY":
            result["fini_array"] = hex(val)
        elif tag_name == "DT_INIT_ARRAYSZ":
            result["init_array_sz"] = val
        elif tag_name == "DT_FINI_ARRAYSZ":
            result["fini_array_sz"] = val
        elif tag_name == "DT_PLTGOT":
            result["plt_got"] = hex(val)
        elif tag_name == "DT_JMPREL":
            result["plt_rel"] = hex(val)
        elif tag_name == "DT_PLTRELSZ":
            result["plt_rel_sz"] = val
        elif tag_name == "DT_REL" or tag_name == "DT_RELA":
            result.setdefault("relocations_dyn", []).append({
                "type": tag_name,
                "address": hex(val),
                "size": tag.entry.d_val if hasattr(tag.entry, "d_val") else 0,
            })
    
    return result


def _decode_dt_flags_1(val: int) -> list[str]:
    """Decode DT_FLAGS_1 value."""
    flags = []
    for bit, name in _DT_FLAGS_1.items():
        if val & bit:
            flags.append(name)
    return flags


def _decode_dt_flags(val: int) -> list[str]:
    """Decode DT_FLAGS value."""
    flags = []
    flag_map = {
        0x00000001: "ORIGIN",
        0x00000002: "SYMBOLIC",
        0x00000004: "TEXTREL",
        0x00000008: "BIND_NOW",
        0x00000010: "STATIC_TLS",
    }
    for bit, name in flag_map.items():
        if val & bit:
            flags.append(name)
    return flags


def _parse_version_sections(elf) -> dict:
    """Parse GNU version sections."""
    result = {
        "versym": [],
        "verdef": [],
        "verneed": [],
    }
    
    # .gnu.version (Versym)
    versym = elf.get_section_by_name(".gnu.version")
    if versym and isinstance(versym, GNUVerSymSection):
        for i, entry in enumerate(versym.iter_symbols()):
            result["versym"].append({
                "index": i,
                "version": entry["ndx"],
                "hidden": bool(entry["ndx"] & 0x8000),
            })
    
    # .gnu.version_d (Verdef) - version definitions
    verdef = elf.get_section_by_name(".gnu.version_d")
    if verdef and isinstance(verdef, GNUVerDefSection):
        for vdef in verdef.iter_versions():
            result["verdef"].append({
                "version": vdef["vd_version"],
                "flags": vdef["vd_flags"],
                "flags_str": "BASE" if vdef["vd_flags"] == 1 else "NONE",
                "name": vdef.name,
                "hash": vdef["vd_hash"],
                "aux": [
                    {"name": aux.name, "hash": aux["vda_hash"]}
                    for aux in vdef.iter_aux()
                ],
            })
    
    # .gnu.version_r (Verneed) - version requirements
    verneed = elf.get_section_by_name(".gnu.version_r")
    if verneed and isinstance(verneed, GNUVerNeedSection):
        for vneed in verneed.iter_versions():
            result["verneed"].append({
                "version": vneed["vn_version"],
                "file": vneed.name,
                "cnt": vneed["vn_cnt"],
                "aux": [
                    {"name": aux.name, "hash": aux["vna_hash"], "flags": aux["vna_flags"]}
                    for aux in vneed.iter_aux()
                ],
            })
    
    return result


def _parse_notes(elf) -> list[dict]:
    """Parse all NOTE sections."""
    notes = []
    for section in elf.iter_sections():
        if isinstance(section, NoteSection):
            for note in section.iter_notes():
                notes.append({
                    "name": note["n_name"],
                    "type": note["n_type"],
                    "desc": note["n_desc"],
                    "section": section.name,
                })
    return notes


def _parse_abi_tag(desc: bytes) -> dict:
    """Parse NT_GNU_ABI_TAG descriptor."""
    if len(desc) >= 12:
        import struct
        os = struct.unpack("<I", desc[:4])[0]
        major = struct.unpack("<I", desc[4:8])[0]
        minor = struct.unpack("<I", desc[8:12])[0]
        os_str = {0: "Linux", 1: "Hurd", 2: "Solaris", 3: "FreeBSD", 4: "NetBSD", 5: "OpenBSD"}.get(os, f"Unknown({os})")
        return {"os": os_str, "major": major, "minor": minor}
    return {}


def _parse_init_fini_arrays(elf) -> list[dict]:
    """Parse .init_array and .fini_array sections."""
    arrays = []
    for section in elf.iter_sections():
        if section.name in (".init_array", ".fini_array", ".preinit_array"):
            data = section.data()
            if data:
                import struct
                ptr_size = 8 if elf.elfclass == 64 else 4
                fmt = "<Q" if ptr_size == 8 else "<I"
                entries = []
                for i in range(0, len(data), ptr_size):
                    if i + ptr_size <= len(data):
                        addr = struct.unpack(fmt, data[i:i+ptr_size])[0]
                        if addr != 0:
                            entries.append(hex(addr))
                arrays.append({
                    "section": section.name,
                    "count": len(entries),
                    "entries": entries[:50],  # Limit output
                })
    return arrays


def _parse_relocations(elf) -> list[dict]:
    """Parse relocation sections."""
    relocs = []
    for section in elf.iter_sections():
        if isinstance(section, RelocationSection):
            reloc_info = {
                "section": section.name,
                "type": "RELA" if section["sh_type"] == 4 else "REL",  # SHT_RELA = 4
                "count": section.num_relocations(),
                "entries": [],
            }
            for rel in section.iter_relocations():
                if len(reloc_info["entries"]) >= 100:  # Limit
                    break
                sym = rel.get_symbol()
                reloc_info["entries"].append({
                    "offset": hex(rel["r_offset"]),
                    "type": rel["r_info_type"],
                    "symbol": sym.name if sym else None,
                    "addend": rel.get("r_addend", None),
                })
            relocs.append(reloc_info)
    return relocs


def _detect_go_binary(elf) -> dict | None:
    """Detect Go binary and extract build info."""
    # Go binaries have specific symbols and sections
    go_indicators = [
        "runtime.buildVersion",
        "runtime.modInfo",
        "runtime.sched",
        "runtime.mheap",
        "runtime.gcenable",
    ]
    
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        names = {sym.name for sym in dynsym.iter_symbols() if sym.name}
        if any(ind in names for ind in go_indicators):
            # Try to extract Go version from .go.buildinfo or runtime.buildVersion
            go_info = {"detected": True, "version": None, "module_path": None, "dependencies": []}
            
            # Check for .go.buildinfo section (Go 1.18+)
            for section in elf.iter_sections():
                if section.name == ".go.buildinfo":
                    data = section.data()
                    if data:
                        # Parse Go build info (simplified)
                        text = data.decode("utf-8", errors="ignore")
                        for line in text.split("\n"):
                            if line.startswith("go version "):
                                go_info["version"] = line[len("go version "):].strip()
                            elif line.startswith("mod "):
                                go_info["module_path"] = line[len("mod "):].strip()
                            elif line.startswith("dep "):
                                go_info["dependencies"].append(line[len("dep "):].strip())
                    break
            
            return go_info
    return None


def _detect_rust_binary(elf) -> dict | None:
    """Detect Rust binary and extract metadata."""
    # Rust binaries have specific symbols
    rust_indicators = [
        "rust_begin_unwind",
        "rust_eh_personality",
        "std::rt::lang_start",
        "__rust_probestack",
    ]
    
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        names = {sym.name for sym in dynsym.iter_symbols() if sym.name}
        if any(ind in names for ind in rust_indicators):
            rust_info = {"detected": True, "version": None, "crate_name": None, "edition": None}
            
            # Try to find .comment section with rustc version
            for section in elf.iter_sections():
                if section.name == ".comment":
                    data = section.data()
                    if data:
                        text = data.decode("utf-8", errors="ignore")
                        if "rustc" in text:
                            rust_info["version"] = text.strip()
                    break
            
            return rust_info
    return None


def _etype_to_str(etype: int) -> str:
    types = {
        0: "ET_NONE",
        1: "ET_REL",
        2: "ET_EXEC",
        3: "ET_DYN",
        4: "ET_CORE",
    }
    return types.get(etype, f"UNKNOWN({etype})")


def _emachine_to_str(emachine: int) -> str:
    machines = {
        3: "EM_386 (x86)",
        8: "EM_MIPS",
        20: "EM_PPC",
        21: "EM_PPC64",
        40: "EM_ARM",
        62: "EM_X86_64",
        183: "EM_AARCH64",
        243: "EM_RISCV",
    }
    return machines.get(emachine, f"UNKNOWN({emachine})")


def _sh_type_to_str(sh_type: int) -> str:
    types = {
        0: "SHT_NULL",
        1: "SHT_PROGBITS",
        2: "SHT_SYMTAB",
        3: "SHT_STRTAB",
        4: "SHT_RELA",
        5: "SHT_HASH",
        6: "SHT_DYNAMIC",
        7: "SHT_NOTE",
        8: "SHT_NOBITS",
        9: "SHT_REL",
        10: "SHT_SHLIB",
        11: "SHT_DYNSYM",
        14: "SHT_INIT_ARRAY",
        15: "SHT_FINI_ARRAY",
        16: "SHT_PREINIT_ARRAY",
        17: "SHT_GROUP",
        18: "SHT_SYMTAB_SHNDX",
        0x60000000: "SHT_GNU_ATTRIBUTES",
        0x6ffffffe: "SHT_GNU_VERDEF",
        0x6fffffff: "SHT_GNU_VERNEED",
        0x6fffffff: "SHT_GNU_VERSYM",
    }
    return types.get(sh_type, f"SHT_UNKNOWN({sh_type})")


def _sh_flags_to_str(sh_flags: int) -> list[str]:
    flags = []
    flag_map = {
        0x1: "WRITE",
        0x2: "ALLOC",
        0x4: "EXECINSTR",
        0x10: "MERGE",
        0x20: "STRINGS",
        0x40: "INFO_LINK",
        0x80: "LINK_ORDER",
        0x100: "OS_NONCONFORMING",
        0x200: "GROUP",
        0x400: "TLS",
        0x800: "COMPRESSED",
        0x1000: "MASKOS",
        0x2000: "MASKPROC",
        0x4000: "ORDERED",
        0x8000: "EXCLUDE",
    }
    for bit, name in flag_map.items():
        if sh_flags & bit:
            flags.append(name)
    return flags


def _ptype_to_str(ptype: int) -> str:
    types = {
        0: "PT_NULL",
        1: "PT_LOAD",
        2: "PT_DYNAMIC",
        3: "PT_INTERP",
        4: "PT_NOTE",
        5: "PT_SHLIB",
        6: "PT_PHDR",
        7: "PT_TLS",
        0x60000000: "PT_GNU_EH_FRAME",
        0x60000001: "PT_GNU_STACK",
        0x60000002: "PT_GNU_RELRO",
    }
    return types.get(ptype, f"PT_UNKNOWN({ptype})")


def _pflags_to_str(pflags: int) -> list[str]:
    flags = []
    if pflags & 0x4: flags.append("R")
    if pflags & 0x2: flags.append("W")
    if pflags & 0x1: flags.append("X")
    return flags


# ──────────────────────────────────────────────────────────────────────────────
# Backward Compatibility
# ──────────────────────────────────────────────────────────────────────────────

def analyze_elf(file_path: Path) -> dict:
    """Backward compatible wrapper returning original format."""
    deep = analyze_elf_deep(file_path)
    if not deep.get("available"):
        return deep
    
    return {
        "available": True,
        "ei_class": deep.get("ei_class"),
        "e_type": deep.get("e_type"),
        "e_machine": deep.get("e_machine"),
        "entry_point": deep.get("entry_point"),
        "is_stripped": deep.get("is_stripped"),
        "sections": [{"name": s["name"], "size": s["size"]} for s in deep.get("sections", [])],
        "dynamic_symbols_sample": deep.get("dynamic_symbols_sample", []),
        "suspicious_symbols": deep.get("suspicious_symbols", []),
        "interpreter": deep.get("interpreter"),
    }