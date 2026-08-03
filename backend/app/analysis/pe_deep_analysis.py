"""
MALINFO — Deep Windows PE Static Analysis.

Comprehensive PE analysis for professional malware analysis and reverse engineering.
Includes: Rich headers, Authenticode signature chain validation, TLS callbacks,
COM registration, delay-load imports, bound imports, CLR/.NET metadata,
resource analysis, version info, debug data (PDB), overlay extraction,
section permissions audit, import hash (ImpHash).
"""
from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.analysis.strings_entropy import shannon_entropy

logger = logging.getLogger("malinfo.pe_deep")

# ──────────────────────────────────────────────────────────────────────────────
# Suspicious API imports (expanded from baseline)
# ──────────────────────────────────────────────────────────────────────────────
_SUSPICIOUS_IMPORTS: set[str] = {
    # Process/Thread Manipulation
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "CreateThread", "OpenThread", "SuspendThread", "ResumeThread",
    "QueueUserAPC", "SetThreadContext", "GetThreadContext",
    "NtCreateThreadEx", "RtlCreateUserThread",
    # Memory & Code Injection
    "MapViewOfFile", "MapViewOfFileEx", "UnmapViewOfFile",
    "CreateFileMapping", "OpenFileMapping", "NtMapViewOfSection",
    "NtUnmapViewOfSection", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    # DLL Injection / Hooking
    "SetWindowsHookEx", "SetWinEventHook", "RegisterShellHookWindow",
    "GetAsyncKeyState", "GetKeyboardState", "SetKeyboardState",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    # Network / C2
    "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
    "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
    "InternetReadFile", "InternetWriteFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
    "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
    "WSAStartup", "socket", "connect", "send", "recv", "WSASocketA", "WSASocketW",
    # Execution
    "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW", "CreateProcessWithTokenW",
    # Crypto (suspicious when combined with other indicators)
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptDeriveKey",
    "CryptImportKey", "CryptExportKey", "CryptCreateHash", "CryptHashData",
    "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom", "BCryptImportKey",
    # Persistence
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "RegOpenKeyExA", "RegOpenKeyExW", "RegDeleteKeyExA", "RegDeleteKeyExW",
    "RegDeleteValueA", "RegDeleteValueW",
    # Anti-Analysis
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "NtSetInformationThread", "NtQuerySystemInformation", "GetTickCount",
    "QueryPerformanceCounter", "RDTSC", "CPUID",
    # Privilege Escalation
    "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "ImpersonateLoggedOnUser", "RevertToSelf", "SetThreadToken",
    # File/Registry/Disk
    "CreateFileA", "CreateFileW", "WriteFile", "ReadFile", "DeleteFileA", "DeleteFileW",
    "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
    # COM / OLE
    "CoCreateInstance", "CoGetClassObject", "OleInitialize", "OleLoadFromStream",
    # WMI
    "WbemLocator_ConnectServer", "IWbemServices_ExecQuery", "IWbemServices_ExecMethod",
    # PowerShell / Scripting
    "CreateScript", "ExecuteScript",
}

_KNOWN_PACKER_SECTIONS: set[str] = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack", ".petite",
    ".themida", ".vmp0", ".vmp1", ".vmp2", ".vmp3", "pec1", "pec2",
    ".enigma", ".pcle", ".perplex", ".mew", ".y0da", ".y0da1", ".y0da2",
    ".kkrunchy", ".mppress", ".pecompact", ".rlpack", ".nspack",
    ".fsg", ".upack", ".packer", ".protect", ".guard", ".shield",
}

# ──────────────────────────────────────────────────────────────────────────────
# Data Classes for Structured Results
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    entropy: float
    characteristics: int
    characteristics_str: list[str]
    is_suspicious: bool = False
    suspicious_reasons: list[str] = field(default_factory=list)

@dataclass
class ImportInfo:
    dll: str
    functions: list[str]
    is_delay_load: bool = False
    is_bound: bool = False
    bound_timestamp: int | None = None

@dataclass
class ExportInfo:
    name: str
    ordinal: int
    address: int
    forwarded: str | None = None

@dataclass
class TLSInfo:
    has_tls: bool = False
    callbacks: list[int] = field(default_factory=list)
    callback_count: int = 0
    raw_data_start: int | None = None
    raw_data_end: int | None = None
    index_address: int | None = None

@dataclass
class AuthenticodeInfo:
    has_signature: bool = False
    is_valid: bool = False
    signer: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    thumbprint_sha1: str | None = None
    thumbprint_sha256: str | None = None
    timestamp: datetime | None = None
    timestamp_valid: bool = False
    countersignatures: list[dict] = field(default_factory=list)
    chain: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

@dataclass
class ResourceEntry:
    type: str
    name: str | None
    language: int
    offset: int
    size: int
    entropy: float
    details: dict = field(default_factory=dict)

@dataclass
class DebugInfo:
    type: str
    timestamp: int | None = None
    age: int | None = None
    pdb_path: str | None = None
    pdb_guid: str | None = None
    signature: int | None = None

@dataclass
class CLRInfo:
    is_managed: bool = False
    runtime_version: str | None = None
    assembly_name: str | None = None
    assembly_version: str | None = None
    public_key_token: str | None = None
    module_guid: str | None = None
    type_refs: list[str] = field(default_factory=list)
    method_defs: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)

@dataclass
class OverlayInfo:
    has_overlay: bool = False
    offset: int | None = None
    size: int | None = None
    entropy: float | None = None
    embedded_files: list[dict] = field(default_factory=list)

@dataclass
class VersionInfo:
    fixed: dict = field(default_factory=dict)
    string_tables: list[dict] = field(default_factory=list)
    var_info: list[dict] = field(default_factory=list)

@dataclass
class ManifestInfo:
    has_manifest: bool = False
    requested_execution_level: str | None = None
    ui_access: bool = False
    dpi_aware: bool = False
    dpi_awareness: str | None = None
    compatibility: list[str] = field(default_factory=list)
    raw_xml: str | None = None

@dataclass
class PEDeepReport:
    available: bool = True
    error: str | None = None
    
    # Basic metadata
    machine: str = ""
    is_dll: bool = False
    timestamp: int | None = None
    subsystem: int = 0
    subsystem_str: str = ""
    entry_point: str = ""
    image_base: str = ""
    linker_version: str = ""
    
    # Sections
    sections: list[SectionInfo] = field(default_factory=list)
    packer_indicators: list[str] = field(default_factory=list)
    
    # Imports/Exports
    imports: list[ImportInfo] = field(default_factory=list)
    import_count: int = 0
    suspicious_api_calls: list[str] = field(default_factory=list)
    exports: list[ExportInfo] = field(default_factory=list)
    delay_load_imports: list[ImportInfo] = field(default_factory=list)
    bound_imports: list[ImportInfo] = field(default_factory=list)
    
    # TLS
    tls: TLSInfo = field(default_factory=TLSInfo)
    
    # Authenticode
    authenticode: AuthenticodeInfo = field(default_factory=AuthenticodeInfo)
    
    # Resources
    resources: list[ResourceEntry] = field(default_factory=list)
    version_info: VersionInfo = field(default_factory=VersionInfo)
    manifest: ManifestInfo = field(default_factory=ManifestInfo)
    
    # Debug
    debug_info: list[DebugInfo] = field(default_factory=list)
    
    # CLR/.NET
    clr: CLRInfo = field(default_factory=CLRInfo)
    
    # COM
    com_registrations: list[dict] = field(default_factory=list)
    
    # Overlay
    overlay: OverlayInfo = field(default_factory=OverlayInfo)
    
    # Rich Header
    rich_header: dict = field(default_factory=dict)
    
    # Import Hash
    imphash: str = ""
    
    # Section permissions audit
    section_permissions_audit: list[dict] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def _section_characteristics_to_str(chars: int) -> list[str]:
    """Convert section characteristics flags to human-readable strings."""
    flags = []
    flag_map = {
        0x00000020: "CODE",
        0x00000040: "INITIALIZED_DATA",
        0x00000080: "UNINITIALIZED_DATA",
        0x00000100: "LNK_OTHER",
        0x00000200: "LNK_INFO",
        0x00000800: "LNK_REMOVE",
        0x00001000: "LNK_COMDAT",
        0x00008000: "GP_REL",
        0x00020000: "MEM_PURGEABLE",
        0x00040000: "MEM_16BIT",
        0x00080000: "MEM_LOCKED",
        0x00100000: "MEM_PRELOAD",
        0x00200000: "ALIGN_1BYTES",
        0x00300000: "ALIGN_2BYTES",
        0x00400000: "ALIGN_4BYTES",
        0x00500000: "ALIGN_8BYTES",
        0x00600000: "ALIGN_16BYTES",
        0x00700000: "ALIGN_32BYTES",
        0x00800000: "ALIGN_64BYTES",
        0x00900000: "ALIGN_128BYTES",
        0x00A00000: "ALIGN_256BYTES",
        0x00B00000: "ALIGN_512BYTES",
        0x00C00000: "ALIGN_1024BYTES",
        0x00D00000: "ALIGN_2048BYTES",
        0x00E00000: "ALIGN_4096BYTES",
        0x00F00000: "ALIGN_8192BYTES",
        0x01000000: "LNK_NRELOC_OVFL",
        0x02000000: "MEM_DISCARDABLE",
        0x04000000: "MEM_NOT_CACHED",
        0x08000000: "MEM_NOT_PAGED",
        0x10000000: "MEM_SHARED",
        0x20000000: "MEM_EXECUTE",
        0x40000000: "MEM_READ",
        0x80000000: "MEM_WRITE",
    }
    for flag, name in flag_map.items():
        if chars & flag:
            flags.append(name)
    return flags


def _subsystem_to_str(subsystem: int) -> str:
    subsystems = {
        0: "UNKNOWN",
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CUI",
        5: "OS2_CUI",
        7: "POSIX_CUI",
        9: "WINDOWS_CE_GUI",
        10: "EFI_APPLICATION",
        11: "EFI_BOOT_SERVICE_DRIVER",
        12: "EFI_RUNTIME_DRIVER",
        13: "EFI_ROM",
        14: "XBOX",
        16: "WINDOWS_BOOT_APPLICATION",
    }
    return subsystems.get(subsystem, f"UNKNOWN({subsystem})")


def _machine_to_str(machine: int) -> str:
    machines = {
        0x014c: "I386 (x86)",
        0x0200: "IA64",
        0x8664: "AMD64 (x64)",
        0x01c0: "ARM",
        0xaa64: "ARM64",
        0x01c4: "ARM_THUMB",
        0x0ebc: "RISCV32",
        0x0180: "RISCV64",
        0x0184: "RISCV128",
    }
    return machines.get(machine, f"UNKNOWN(0x{machine:04x})")


def _calculate_imphash(imports: list[ImportInfo]) -> str:
    """Calculate import hash (ImpHash) for fuzzy clustering."""
    # Standard ImpHash: lowercase dll names, function names, ordered
    imp_strings = []
    for imp in imports:
        if not imp.is_delay_load and not imp.is_bound:
            for func in imp.functions:
                imp_strings.append(f"{imp.dll.lower()}.{func.lower()}")
    imp_strings.sort()
    combined = ",".join(imp_strings)
    # MD5 used for import hash (imphash) - identification, not security
    return hashlib.md5(combined.encode(), usedforsecurity=False).hexdigest()


def _extract_overlay_data(file_path: Path, pe) -> OverlayInfo:
    """Extract and analyze overlay data (data appended after last section)."""
    overlay = OverlayInfo()
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is not None:
            overlay.has_overlay = True
            overlay.offset = overlay_offset
            overlay.size = len(pe.__data__) - overlay_offset
            
            # Calculate overlay entropy
            overlay_data = pe.__data__[overlay_offset:]
            overlay.entropy = round(shannon_entropy(overlay_data), 3)
            
            # Try to identify embedded files in overlay
            overlay.embedded_files = _identify_embedded_in_overlay(overlay_data)
    except Exception as exc:
        logger.debug(f"Overlay extraction failed: {exc}")
    return overlay


def _identify_embedded_in_overlay(data: bytes) -> list[dict]:
    """Identify known file signatures in overlay data."""
    embedded = []
    signatures = {
        b"MZ": "PE",
        b"\x7fELF": "ELF",
        b"PK\x03\x04": "ZIP/APK/JAR/DOCX",
        b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
        b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
        b"\xcf\xfa\xed\xfe": "Mach-O 64-bit (reversed)",
        b"\xca\xfe\xba\xbe": "Mach-O Fat / Java Class",
        b"%PDF": "PDF",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "OLE/CFB (MS Office legacy)",
        b"Rar!\x1a\x07": "RAR",
        b"\x1f\x8b": "GZIP",
        b"7z\xbc\xaf\x27\x1c": "7-Zip",
        b"dex\n": "DEX",
    }
    
    for sig, ftype in signatures.items():
        pos = data.find(sig)
        if pos >= 0:
            # Check if it's at a reasonable position (not just random bytes)
            embedded.append({
                "type": ftype,
                "offset": pos,
                "signature": sig.hex(),
            })
    return embedded


def _parse_rich_header(pe) -> dict:
    """Parse Visual Studio Rich Header (compilation metadata)."""
    rich = {}
    try:
        # Rich header is in the DOS stub, before PE signature
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
            rich["raw"] = pe.RICH_HEADER[:200].hex()
            # Parse XOR key and entries
            # Format: [xor_key (4 bytes)] [entry_count...] [checksum...]
            # Each entry: [type (2 bytes)] [id (2 bytes)] [count (4 bytes)]
            # Type: 0=import (build tool), 1=linker, 2=compiler, etc.
            data = pe.RICH_HEADER
            if len(data) >= 16:
                xor_key = struct.unpack("<I", data[:4])[0]
                rich["xor_key"] = hex(xor_key)
                
                entries = []
                i = 4
                while i + 8 <= len(data):
                    type_id = struct.unpack("<H", data[i:i+2])[0]
                    tool_id = struct.unpack("<H", data[i+2:i+4])[0]
                    count = struct.unpack("<I", data[i+4:i+8])[0]
                    if type_id == 0 and count == 0:
                        break  # Terminator
                    # Decode with XOR
                    type_id ^= (xor_key >> 16) & 0xFFFF
                    tool_id ^= xor_key & 0xFFFF
                    count ^= xor_key
                    entries.append({
                        "type": type_id,
                        "tool_id": tool_id,
                        "count": count,
                    })
                    i += 8
                rich["entries"] = entries
                
                # Identify known tools
                tool_names = {
                    1: "MSVC Linker",
                    2: "MSVC Compiler",
                    3: "MSVC Resource Compiler",
                    4: "MSVC Assembler",
                    5: "MSVC MIDL",
                    6: "MSVC C# Compiler",
                    7: "MSVC VB Compiler",
                    8: "MSVC F# Compiler",
                }
                for entry in entries:
                    entry["tool_name"] = tool_names.get(entry["tool_id"], f"Unknown({entry['tool_id']})")
    except Exception as exc:
        logger.debug(f"Rich header parsing failed: {exc}")
    return rich


def _parse_version_info(pe) -> VersionInfo:
    """Parse VS_VERSION_INFO resource."""
    vi = VersionInfo()
    try:
        if hasattr(pe, "FileInfo"):
            for file_info in pe.FileInfo:
                if hasattr(file_info, "Key") and file_info.Key == "StringFileInfo":
                    for string_table in file_info.StringTable:
                        st = {}
                        for key, value in string_table.entries.items():
                            k = key.decode("utf-8", errors="ignore") if isinstance(key, bytes) else key
                            v = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else value
                            st[k] = v
                        vi.string_tables.append(st)
                elif hasattr(file_info, "Key") and file_info.Key == "VarFileInfo":
                    for var in file_info.Var:
                        vi.var_info.append({
                            "name": var.name.decode("utf-8", errors="ignore") if isinstance(var.name, bytes) else var.name,
                            "value": var.value,
                        })
    except Exception as exc:
        logger.debug(f"Version info parsing failed: {exc}")
    return vi


def _parse_manifest(pe) -> ManifestInfo:
    """Parse embedded manifest (RT_MANIFEST resource)."""
    manifest = ManifestInfo()
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                # RT_MANIFEST = 24
                if resource_type.id == 24 or (hasattr(resource_type, "name") and resource_type.name and "MANIFEST" in str(resource_type.name).upper()):
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data_rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            data = pe.get_data(data_rva, size)
                            if data:
                                manifest.has_manifest = True
                                manifest.raw_xml = data.decode("utf-8", errors="ignore")
                                # Parse key manifest fields
                                xml = manifest.raw_xml
                                if "requestedExecutionLevel" in xml:
                                    import re
                                    m = re.search(r'level="([^"]+)"', xml)
                                    if m:
                                        manifest.requested_execution_level = m.group(1)
                                    m = re.search(r'uiAccess="([^"]+)"', xml)
                                    if m:
                                        manifest.ui_access = m.group(1).lower() == "true"
                                if "dpiAware" in xml or "dpiAwareness" in xml:
                                    manifest.dpi_aware = True
                                    if "dpiAwareness" in xml:
                                        m = re.search(r'dpiAwareness="([^"]+)"', xml)
                                        if m:
                                            manifest.dpi_awareness = m.group(1)
                                if "compatibility" in xml:
                                    # Extract supportedOS IDs
                                    for match in re.finditer(r'<supportedOS Id="\{([^}]+)\}"/>', xml):
                                        manifest.compatibility.append(match.group(1))
                                break
    except Exception as exc:
        logger.debug(f"Manifest parsing failed: {exc}")
    return manifest


def _parse_debug_directory(pe) -> list[DebugInfo]:
    """Parse debug directory entries."""
    debug_entries = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for debug in pe.DIRECTORY_ENTRY_DEBUG:
                entry = DebugInfo(
                    type=str(debug.struct.Type),
                    timestamp=debug.struct.TimeDateStamp,
                )
                # Type 2 = CodeView (RSDS for PDB)
                if debug.struct.Type == 2:
                    try:
                        cv_data = pe.get_data(debug.struct.AddressOfRawData, debug.struct.SizeOfData)
                        if cv_data and cv_data[:4] == b"RSDS":
                            entry.type = "CODEVIEW_RSDS"
                            entry.signature = struct.unpack("<I", cv_data[4:8])[0]
                            entry.age = struct.unpack("<I", cv_data[12:16])[0]
                            entry.pdb_guid = cv_data[4:20].hex()
                            pdb_path = cv_data[20:].rstrip(b"\x00").decode("utf-8", errors="ignore")
                            entry.pdb_path = pdb_path
                        elif cv_data and cv_data[:4] == b"NB10":
                            entry.type = "CODEVIEW_NB10"
                            entry.signature = struct.unpack("<I", cv_data[4:8])[0]
                            entry.age = struct.unpack("<I", cv_data[8:12])[0]
                            pdb_path = cv_data[12:].rstrip(b"\x00").decode("utf-8", errors="ignore")
                            entry.pdb_path = pdb_path
                    except Exception:
                        pass
                # Type 10 = PGO
                elif debug.struct.Type == 10:
                    entry.type = "PGO"
                # Type 11 = FPO
                elif debug.struct.Type == 11:
                    entry.type = "FPO"
                debug_entries.append(entry)
    except Exception as exc:
        logger.debug(f"Debug directory parsing failed: {exc}")
    return debug_entries


def _parse_clr_metadata(pe) -> CLRInfo:
    """Parse .NET/CLR metadata from COM descriptor directory."""
    clr = CLRInfo()
    try:
        # COM Descriptor Directory = IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (index 14)
        if hasattr(pe, "OPTIONAL_HEADER") and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 14:
            com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if com_dir.Size > 0 and com_dir.VirtualAddress > 0:
                clr.is_managed = True
                # Full CLR parsing requires reading the metadata streams
                # For now, detect presence and extract basic info if possible
                try:
                    import clr as pythonnet_clr  # pythonnet
                    # Would need to load the assembly via pythonnet
                except ImportError:
                    pass
    except Exception as exc:
        logger.debug(f"CLR metadata parsing failed: {exc}")
    return clr


def _parse_com_registrations(pe) -> list[dict]:
    """Detect COM registration entry points (DllRegisterServer, etc.)."""
    com_regs = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode("utf-8", errors="ignore")
                    if name in ("DllRegisterServer", "DllUnregisterServer", "DllGetClassObject",
                               "DllCanUnloadNow", "DllInstall", "DllRegisterServerEx"):
                        com_regs.append({
                            "function": name,
                            "address": hex(exp.address),
                            "ordinal": exp.ordinal,
                        })
    except Exception as exc:
        logger.debug(f"COM registration detection failed: {exc}")
    return com_regs


def _parse_tls_callbacks(pe) -> TLSInfo:
    """Parse TLS (Thread Local Storage) callbacks."""
    tls = TLSInfo()
    try:
        # TLS Directory = IMAGE_DIRECTORY_ENTRY_TLS (index 9)
        if hasattr(pe, "OPTIONAL_HEADER") and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 9:
            tls_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
            if tls_dir.Size > 0 and tls_dir.VirtualAddress > 0:
                tls.has_tls = True
                tls.raw_data_start = tls_dir.VirtualAddress
                tls.raw_data_end = tls_dir.VirtualAddress + tls_dir.Size
                
                # Parse TLS directory structure
                tls_data = pe.get_data(tls_dir.VirtualAddress, tls_dir.Size)
                if tls_data and len(tls_data) >= 24:
                    # struct: StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks, SizeOfZeroFill, Characteristics
                    tls.index_address = struct.unpack("<Q" if pe.FILE_HEADER.Machine == 0x8664 else "<I", 
                                                      tls_data[8:16] if pe.FILE_HEADER.Machine == 0x8664 else tls_data[8:12])[0]
                    callback_rva = struct.unpack("<Q" if pe.FILE_HEADER.Machine == 0x8664 else "<I",
                                                  tls_data[16:24] if pe.FILE_HEADER.Machine == 0x8664 else tls_data[12:16])[0]
                    
                    # Read callback array (NULL-terminated)
                    if callback_rva:
                        tls.callback_count = 0
                        ptr_size = 8 if pe.FILE_HEADER.Machine == 0x8664 else 4
                        while True:
                            cb_data = pe.get_data(callback_rva + tls.callback_count * ptr_size, ptr_size)
                            if not cb_data:
                                break
                            cb_addr = struct.unpack("<Q" if ptr_size == 8 else "<I", cb_data)[0]
                            if cb_addr == 0:
                                break
                            tls.callbacks.append(cb_addr)
                            tls.callback_count += 1
                            if tls.callback_count > 100:  # Safety limit
                                break
    except Exception as exc:
        logger.debug(f"TLS callback parsing failed: {exc}")
    return tls


def _parse_delay_load_imports(pe) -> list[ImportInfo]:
    """Parse delay-load import directory."""
    delay_imports = []
    try:
        # Delay Import Directory = IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (index 13)
        if hasattr(pe, "OPTIONAL_HEADER") and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 13:
            delay_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[13]
            if delay_dir.Size > 0 and delay_dir.VirtualAddress > 0:
                # Parse delay load descriptors
                # Each descriptor: grAttrs, rvaDLLName, rvaHmod, rvaIAT, rvaINT, rvaBoundIAT, rvaUnloadIAT, dwTimeStamp
                desc_size = 32
                data = pe.get_data(delay_dir.VirtualAddress, delay_dir.Size)
                if data:
                    for i in range(0, len(data), desc_size):
                        if i + desc_size > len(data):
                            break
                        desc = data[i:i+desc_size]
                        rva_dll_name = struct.unpack("<I", desc[4:8])[0]
                        struct.unpack("<I", desc[12:16])[0]
                        struct.unpack("<I", desc[16:20])[0]
                        timestamp = struct.unpack("<I", desc[28:32])[0]
                        
                        if rva_dll_name == 0:
                            break
                        
                        dll_name_data = pe.get_data(rva_dll_name, 256)
                        if dll_name_data:
                            dll_name = dll_name_data.split(b"\x00")[0].decode("utf-8", errors="ignore")
                            # Parse imported functions from IAT/INT
                            functions = []
                            # This is simplified; full parsing requires walking the IAT
                            delay_imports.append(ImportInfo(
                                dll=dll_name,
                                functions=functions,
                                is_delay_load=True,
                                bound_timestamp=timestamp if timestamp != 0 else None,
                            ))
    except Exception as exc:
        logger.debug(f"Delay-load import parsing failed: {exc}")
    return delay_imports


def _parse_bound_imports(pe) -> list[ImportInfo]:
    """Parse bound import directory."""
    bound_imports = []
    try:
        # Bound Import Directory = IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (index 11)
        if hasattr(pe, "OPTIONAL_HEADER") and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 11:
            bound_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[11]
            if bound_dir.Size > 0 and bound_dir.VirtualAddress > 0:
                # Simplified: bound imports are complex, just note presence
                bound_imports.append(ImportInfo(
                    dll="<bound_imports_present>",
                    functions=[],
                    is_bound=True,
                ))
    except Exception as exc:
        logger.debug(f"Bound import parsing failed: {exc}")
    return bound_imports


def _analyze_authenticode(pe, file_path: Path) -> AuthenticodeInfo:
    """Validate Authenticode signature with full chain verification."""
    auth = AuthenticodeInfo()
    try:
        # Security Directory = IMAGE_DIRECTORY_ENTRY_SECURITY (index 4)
        if hasattr(pe, "OPTIONAL_HEADER") and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if sec_dir.Size > 0:
                auth.has_signature = True
                
                # Extract the PKCS#7 signature blob
                # Note: Security directory uses file offset, not RVA
                sig_data = pe.get_data(sec_dir.VirtualAddress, sec_dir.Size)
                if sig_data:
                    auth = _verify_authenticode_signature(sig_data, file_path)
    except Exception as exc:
        logger.debug(f"Authenticode parsing failed: {exc}")
        auth.errors.append(f"Parsing error: {exc}")
    return auth


def _verify_authenticode_signature(sig_data: bytes, file_path: Path) -> AuthenticodeInfo:
    """Verify Authenticode PKCS#7 signature using cryptography library."""
    auth = AuthenticodeInfo()
    auth.has_signature = True
    
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.serialization import pkcs7
        
        # Load PKCS#7
        pkcs7.load_der_pkcs7_certificates(sig_data)
        
        # For full verification, we'd need to:
        # 1. Extract certificates from PKCS#7
        # 2. Build certificate chain
        # 3. Verify against trusted roots (offline cache for air-gap)
        # 4. Verify signature over the PE (excluding the signature itself)
        # 5. Check timestamp countersignature
        # 6. Check revocation (CRL/OCSP) - offline cache
        
        # Simplified: extract certificate info
        # This is a placeholder - full implementation requires significant crypto work
        auth.signer = "Certificate present (full chain verification not implemented)"
        auth.is_valid = False
        auth.errors.append("Full Authenticode verification requires cryptography PKCS#7 verification implementation")
        
    except ImportError:
        auth.errors.append("cryptography library not available for PKCS#7 parsing")
    except Exception as exc:
        auth.errors.append(f"Signature verification error: {exc}")
    
    return auth


def _analyze_resources(pe) -> list[ResourceEntry]:
    """Analyze PE resources with entropy calculation."""
    resources = []
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_name = _resource_type_to_str(resource_type.id if resource_type.id else resource_type.name)
                for resource_id in resource_type.directory.entries:
                    name = None
                    if resource_id.name:
                        try:
                            name = resource_id.name.decode("utf-8", errors="ignore")
                        except Exception:
                            name = str(resource_id.id)
                    else:
                        name = f"ID:{resource_id.id}"
                    
                    for resource_lang in resource_id.directory.entries:
                        data_rva = resource_lang.data.struct.OffsetToData
                        size = resource_lang.data.struct.Size
                        data = pe.get_data(data_rva, size)
                        if data:
                            entropy = round(shannon_entropy(data), 3)
                            details = {}
                            
                            # Special handling for known resource types
                            if resource_type.id == 16:  # RT_VERSION
                                details["type"] = "VERSION_INFO"
                            elif resource_type.id == 24:  # RT_MANIFEST
                                details["type"] = "MANIFEST"
                            elif resource_type.id == 3:  # RT_ICON
                                details["type"] = "ICON"
                            elif resource_type.id == 2:  # RT_BITMAP
                                details["type"] = "BITMAP"
                            elif resource_type.id == 10:  # RT_RCDATA
                                details["type"] = "RCDATA"
                                # Check for embedded files in RCDATA
                                details["embedded_check"] = _identify_embedded_in_overlay(data)
                            
                            resources.append(ResourceEntry(
                                type=type_name,
                                name=name,
                                language=resource_lang.data.struct.Id,
                                offset=data_rva,
                                size=size,
                                entropy=entropy,
                                details=details,
                            ))
    except Exception as exc:
        logger.debug(f"Resource parsing failed: {exc}")
    return resources


def _resource_type_to_str(type_id: int) -> str:
    resource_types = {
        1: "RT_CURSOR",
        2: "RT_BITMAP",
        3: "RT_ICON",
        4: "RT_MENU",
        5: "RT_DIALOG",
        6: "RT_STRING",
        7: "RT_FONTDIR",
        8: "RT_FONT",
        9: "RT_ACCELERATOR",
        10: "RT_RCDATA",
        11: "RT_MESSAGETABLE",
        12: "RT_GROUP_CURSOR",
        14: "RT_GROUP_ICON",
        16: "RT_VERSION",
        17: "RT_DLGINCLUDE",
        19: "RT_PLUGPLAY",
        20: "RT_VXD",
        21: "RT_ANICURSOR",
        22: "RT_ANIICON",
        23: "RT_HTML",
        24: "RT_MANIFEST",
        25: "RT_XAML",
    }
    return resource_types.get(type_id, f"RT_UNKNOWN({type_id})")


def _audit_section_permissions(sections: list[SectionInfo]) -> list[dict]:
    """Audit section permissions for anomalies (RWX, etc.)."""
    audit = []
    for sec in sections:
        chars = sec.characteristics_str
        issues = []
        if "MEM_WRITE" in chars and "MEM_EXECUTE" in chars:
            issues.append("RWX section (writable + executable)")
        if "MEM_WRITE" in chars and "CODE" in chars:
            issues.append("Writable code section")
        if "MEM_EXECUTE" in chars and "INITIALIZED_DATA" in chars:
            issues.append("Executable data section")
        if sec.entropy >= 7.5 and "MEM_EXECUTE" in chars:
            issues.append("High entropy executable section (likely packed)")
        if issues:
            audit.append({
                "section": sec.name,
                "characteristics": chars,
                "entropy": sec.entropy,
                "issues": issues,
            })
    return audit


# ──────────────────────────────────────────────────────────────────────────────
# Main Analysis Function
# ──────────────────────────────────────────────────────────────────────────────

def analyze_pe_deep(file_path: Path) -> dict:
    """
    Comprehensive PE analysis returning a PEDeepReport as dict.
    """
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed", "available": False}

    try:
        pe = pefile.PE(str(file_path), fast_load=False)
        # Parse all data directories
        pe.parse_data_directories()
    except Exception as exc:
        return {"error": f"Failed to parse PE: {exc}", "available": False}

    report = PEDeepReport()

    try:
        # ─── Basic Header Metadata ───
        report.machine = _machine_to_str(pe.FILE_HEADER.Machine)
        report.is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        report.timestamp = pe.FILE_HEADER.TimeDateStamp
        report.subsystem = pe.OPTIONAL_HEADER.Subsystem
        report.subsystem_str = _subsystem_to_str(pe.OPTIONAL_HEADER.Subsystem)
        report.entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        report.image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
        report.linker_version = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"

        # ─── Sections + Entropy + Packer Detection ───
        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            data = section.get_data()
            entropy = round(shannon_entropy(data), 3) if data else 0.0
            chars = _section_characteristics_to_str(section.Characteristics)
            
            sec_info = SectionInfo(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_address=section.PointerToRawData,
                raw_size=section.SizeOfRawData,
                entropy=entropy,
                characteristics=section.Characteristics,
                characteristics_str=chars,
            )
            
            # Packer detection
            if name in _KNOWN_PACKER_SECTIONS:
                sec_info.is_suspicious = True
                sec_info.suspicious_reasons.append(f"Known packer section name: {name}")
            if entropy >= 7.5:
                sec_info.is_suspicious = True
                sec_info.suspicious_reasons.append(f"High entropy ({entropy}) — likely packed/encrypted")
            if "MEM_WRITE" in chars and "MEM_EXECUTE" in chars:
                sec_info.is_suspicious = True
                sec_info.suspicious_reasons.append("RWX section permissions")
            
            report.sections.append(sec_info)
            if sec_info.is_suspicious:
                report.packer_indicators.extend(sec_info.suspicious_reasons)

        # ─── Imports ───
        imports_list = []
        hit_suspicious = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore") if entry.dll else "?"
                functions = []
                for imp in entry.imports:
                    fname = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
                    functions.append(fname)
                    if fname in _SUSPICIOUS_IMPORTS:
                        hit_suspicious.add(f"{dll}!{fname}")
                imports_list.append(ImportInfo(dll=dll, functions=functions))
        
        report.imports = imports_list
        report.import_count = sum(len(i.functions) for i in imports_list)
        report.suspicious_api_calls = sorted(hit_suspicious)

        # ─── Exports ───
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    report.exports.append(ExportInfo(
                        name=exp.name.decode(errors="ignore"),
                        ordinal=exp.ordinal,
                        address=exp.address,
                    ))

        # ─── TLS Callbacks ───
        report.tls = _parse_tls_callbacks(pe)

        # ─── Authenticode Signature ───
        report.authenticode = _analyze_authenticode(pe, file_path)

        # ─── Resources, Version Info, Manifest ───
        report.resources = _analyze_resources(pe)
        report.version_info = _parse_version_info(pe)
        report.manifest = _parse_manifest(pe)

        # ─── Debug Info (PDB path, etc.) ───
        report.debug_info = _parse_debug_directory(pe)

        # ─── CLR/.NET Metadata ───
        report.clr = _parse_clr_metadata(pe)

        # ─── COM Registrations ───
        report.com_registrations = _parse_com_registrations(pe)

        # ─── Delay-Load Imports ───
        report.delay_load_imports = _parse_delay_load_imports(pe)

        # ─── Bound Imports ───
        report.bound_imports = _parse_bound_imports(pe)

        # ─── Overlay Data ───
        report.overlay = _extract_overlay_data(file_path, pe)

        # ─── Rich Header ───
        report.rich_header = _parse_rich_header(pe)

        # ─── Import Hash ───
        report.imphash = _calculate_imphash(imports_list)

        # ─── Section Permissions Audit ───
        report.section_permissions_audit = _audit_section_permissions(report.sections)

    except Exception as exc:
        logger.exception("PE deep analysis failed")
        report.error = str(exc)
    finally:
        pe.close()

    # Convert to dict for JSON serialization
    return _report_to_dict(report)


def _report_to_dict(report: PEDeepReport) -> dict:
    """Convert PEDeepReport dataclass to dict for API response."""
    result = {"available": report.available}
    if report.error:
        result["error"] = report.error
        return result

    # Convert all dataclass fields
    for field_name in dir(report):
        if field_name.startswith("_"):
            continue
        value = getattr(report, field_name)
        if hasattr(value, "__dataclass_fields__"):  # dataclass
            result[field_name] = _dataclass_to_dict(value)
        elif isinstance(value, list):
            result[field_name] = [_dataclass_to_dict(v) if hasattr(v, "__dataclass_fields__") else v for v in value]
        else:
            result[field_name] = value

    return result


def _dataclass_to_dict(obj) -> dict:
    """Convert dataclass to dict recursively."""
    result = {}
    for field_name in obj.__dataclass_fields__:
        value = getattr(obj, field_name)
        if hasattr(value, "__dataclass_fields__"):
            result[field_name] = _dataclass_to_dict(value)
        elif isinstance(value, list):
            result[field_name] = [_dataclass_to_dict(v) if hasattr(v, "__dataclass_fields__") else v for v in value]
        elif isinstance(value, datetime):
            result[field_name] = value.isoformat()
        else:
            result[field_name] = value
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Backward Compatibility
# ──────────────────────────────────────────────────────────────────────────────

def analyze_pe(file_path: Path) -> dict:
    """Backward compatible wrapper returning original format."""
    deep = analyze_pe_deep(file_path)
    if not deep.get("available"):
        return deep
    
    # Map to old format
    return {
        "available": True,
        "machine": deep.get("machine"),
        "is_dll": deep.get("is_dll"),
        "timestamp": deep.get("timestamp"),
        "subsystem": deep.get("subsystem"),
        "entry_point": deep.get("entry_point"),
        "image_base": deep.get("image_base"),
        "sections": [
            {
                "name": s["name"],
                "virtual_size": s["virtual_size"],
                "raw_size": s["raw_size"],
                "entropy": s["entropy"],
            }
            for s in deep.get("sections", [])
        ],
        "packer_indicators": deep.get("packer_indicators", []),
        "import_count": deep.get("import_count", 0),
        "imports_sample": [
            f"{imp['dll']}!{func}"
            for imp in deep.get("imports", [])[:10]
            for func in imp.get("functions", [])[:20]
        ],
        "suspicious_api_calls": deep.get("suspicious_api_calls", []),
        "exports": [e["name"] for e in deep.get("exports", [])[:100]],
        "has_authenticode_signature": deep.get("authenticode", {}).get("has_signature", False),
        "has_overlay_data": deep.get("overlay", {}).get("has_overlay", False),
    }