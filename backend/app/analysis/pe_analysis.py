"""Windows PE (Portable Executable) static analysis via `pefile`."""
from __future__ import annotations

from pathlib import Path

from app.analysis.strings_entropy import shannon_entropy

# Import commonly abused Windows APIs — their presence isn't proof of malice,
# but a cluster of these together is a well-established heuristic signal.
_SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "SetWindowsHookEx", "GetAsyncKeyState", "InternetOpenA", "InternetOpenW",
    "URLDownloadToFileA", "WinExec", "ShellExecuteA", "CryptEncrypt",
    "RegSetValueExA", "RegCreateKeyExA", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "AdjustTokenPrivileges", "OpenProcess",
    "ReadProcessMemory", "GetProcAddress", "LoadLibraryA",
}

_KNOWN_PACKER_SECTIONS = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack", ".petite",
    ".themida", ".vmp0", ".vmp1", "pec1", "pec2",
}


def analyze_pe(file_path: Path) -> dict:
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed", "available": False}

    try:
        pe = pefile.PE(str(file_path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ])
    except Exception as exc:
        return {"error": f"Failed to parse PE: {exc}", "available": False}

    result: dict = {"available": True}

    # --- Header metadata -----------------------------------------------------
    result["machine"] = hex(pe.FILE_HEADER.Machine)
    result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    result["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    result["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
    result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result["image_base"] = hex(pe.OPTIONAL_HEADER.ImageBase)

    # --- Sections + per-section entropy (packer detection) --------------------
    sections = []
    suspicious_sections = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        data = section.get_data()
        entropy = round(shannon_entropy(data), 3) if data else 0.0
        sections.append({
            "name": name,
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "entropy": entropy,
        })
        if name in _KNOWN_PACKER_SECTIONS:
            suspicious_sections.append(f"Known packer section name: {name}")
        if entropy >= 7.5:
            suspicious_sections.append(f"Section '{name}' entropy {entropy} — likely packed/encrypted")
    result["sections"] = sections
    result["packer_indicators"] = suspicious_sections

    # --- Imports ---------------------------------------------------------------
    imports = []
    hit_suspicious = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore") if entry.dll else "?"
            for imp in entry.imports:
                fname = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                imports.append(f"{dll}!{fname}")
                if fname in _SUSPICIOUS_IMPORTS:
                    hit_suspicious.append(f"{dll}!{fname}")
    result["import_count"] = len(imports)
    result["imports_sample"] = imports[:200]
    result["suspicious_api_calls"] = sorted(set(hit_suspicious))

    # --- Exports (relevant for DLLs, e.g. proxy DLL hijacking) -----------------
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode(errors="ignore"))
    result["exports"] = exports[:100]

    # --- Digital signature presence (does NOT validate trust chain here) -------
    result["has_authenticode_signature"] = _has_signature(pe)

    # --- Overlay data (data appended after the last section — common for
    #     self-extracting droppers / embedded payloads) --------------------------
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        result["has_overlay_data"] = overlay_offset is not None
        if overlay_offset is not None:
            result["overlay_size_bytes"] = len(pe.__data__) - overlay_offset
    except Exception:
        result["has_overlay_data"] = False

    pe.close()
    return result


def _has_signature(pe) -> bool:
    try:
        # IMAGE_DIRECTORY_ENTRY_SECURITY == index 4
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        return entry.Size > 0
    except Exception:
        return False
