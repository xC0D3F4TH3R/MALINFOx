"""
MALINFO — Obfuscation & Anti-Analysis Detection.

Detection of code obfuscation techniques, packers, virtual machine protectors,
anti-debugging, anti-VM, sandbox evasion, and other anti-analysis measures.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.obfuscation_detector")

# ──────────────────────────────────────────────────────────────────────────────
# Known Packer/Protector Signatures
# ──────────────────────────────────────────────────────────────────────────────

_PACKER_SIGNATURES = {
    # Commercial Packers
    "UPX": {
        "sections": ["UPX0", "UPX1", "UPX2"],
        "strings": ["UPX!", "UPX0", "UPX1", "UPX2"],
        "imports": [],
        "description": "UPX Packer",
    },
    "ASPack": {
        "sections": [".aspack", ".adata"],
        "strings": ["ASPack", "aPLib"],
        "imports": [],
        "description": "ASPack",
    },
    "PECompact": {
        "sections": [".pec1", ".pec2"],
        "strings": ["PECompact", "PECOMPACT"],
        "imports": [],
        "description": "PECompact",
    },
    "Themida": {
        "sections": [".themida", ".themida_", "Themida"],
        "strings": ["Themida", "Oreans", "WinLicense"],
        "imports": [],
        "description": "Themida / WinLicense",
    },
    "VMProtect": {
        "sections": [".vmp0", ".vmp1", ".vmp2", ".vmp3", "VMP0", "VMP1"],
        "strings": ["VMProtect", "VMP", "Virtual Machine Protect"],
        "imports": [],
        "description": "VMProtect",
    },
    "Enigma Protector": {
        "sections": [".enigma", ".enigma_", "Enigma"],
        "strings": ["Enigma Protector", "Enigma", "EP_"],
        "imports": [],
        "description": "Enigma Protector",
    },
    "CodeVirtualizer": {
        "sections": [".cv", ".cv_", "CodeVirtualizer"],
        "strings": ["CodeVirtualizer", "Oreans"],
        "imports": [],
        "description": "CodeVirtualizer",
    },
    "Obsidium": {
        "sections": [".obsidium", "Obsidium"],
        "strings": ["Obsidium"],
        "imports": [],
        "description": "Obsidium",
    },
    "Armadillo": {
        "sections": [".armadillo", "Armadillo"],
        "strings": ["Armadillo", "Silicon Realms"],
        "imports": [],
        "description": "Armadillo",
    },
    "Mpress": {
        "sections": [".mpress", "Mpress"],
        "strings": ["Mpress", "Matcode"],
        "imports": [],
        "description": "MPRESS",
    },
    "NSPack": {
        "sections": [".nspack", ".nsp0", ".nsp1"],
        "strings": ["NSPack"],
        "imports": [],
        "description": "NSPack",
    },
    "RLPack": {
        "sections": [".rlpack", "RLPack"],
        "strings": ["RLPack"],
        "imports": [],
        "description": "RLPack",
    },
    "FSG": {
        "sections": [".fsg", "FSG"],
        "strings": ["FSG", "Fast Small Good"],
        "imports": [],
        "description": "FSG",
    },
    "Petite": {
        "sections": [".petite", "Petite"],
        "strings": ["Petite"],
        "imports": [],
        "description": "Petite",
    },
    "Yoda's Crypter": {
        "sections": [".y0da", ".y0da1", ".y0da2"],
        "strings": ["Yoda", "Y0DA"],
        "imports": [],
        "description": "Yoda's Crypter",
    },
    "KKrunchy": {
        "sections": [".kkrunchy", "KKrunchy"],
        "strings": ["KKrunchy"],
        "imports": [],
        "description": "KKrunchy",
    },
    "PELock": {
        "sections": [".pelock", "PELock"],
        "strings": ["PELock"],
        "imports": [],
        "description": "PELock",
    },
    "EXECryptor": {
        "sections": [".execryptor", "EXECryptor"],
        "strings": ["EXECryptor", "StrongBit"],
        "imports": [],
        "description": "EXECryptor",
    },
    "PESpin": {
        "sections": [".pespin", "PESpin"],
        "strings": ["PESpin"],
        "imports": [],
        "description": "PESpin",
    },
    "Upack": {
        "sections": [".upack", "Upack"],
        "strings": ["Upack"],
        "imports": [],
        "description": "Upack",
    },
    # Crypters/Loaders
    "RunPE": {
        "sections": [],
        "strings": ["RunPE", "Run PE", "CreateProcess", "WriteProcessMemory", "NtUnmapViewOfSection"],
        "imports": ["CreateProcessA", "CreateProcessW", "WriteProcessMemory", "NtUnmapViewOfSection", "VirtualAllocEx", "GetThreadContext", "SetThreadContext", "ResumeThread"],
        "description": "RunPE (Process Hollowing)",
    },
    "Process Hollowing": {
        "sections": [],
        "strings": ["NtUnmapViewOfSection", "WriteProcessMemory", "CreateProcess", "ZwUnmapViewOfSection"],
        "imports": ["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "WriteProcessMemory", "CreateProcessA", "CreateProcessW"],
        "description": "Process Hollowing Technique",
    },
    "Reflective Loader": {
        "sections": [],
        "strings": ["ReflectiveLoader", "ReflectiveDLLInjection"],
        "imports": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect"],
        "description": "Reflective DLL Injection",
    },
    "Donut": {
        "sections": [],
        "strings": ["Donut", "CLR", "ExecuteAssembly", "AppDomain"],
        "imports": ["CorBindToRuntime", "CLRCreateInstance", "ICLRRuntimeHost"],
        "description": "Donut (Shellcode/.NET loader)",
    },
}

# ──────────────────────────────────────────────────────────────────────────────
# Anti-Analysis Patterns
# ──────────────────────────────────────────────────────────────────────────────

_ANTI_DEBUG_PATTERNS = [
    # Windows API
    ("IsDebuggerPresent", "kernel32.IsDebuggerPresent", "Direct debugger detection"),
    ("CheckRemoteDebuggerPresent", "kernel32.CheckRemoteDebuggerPresent", "Remote debugger detection"),
    ("NtQueryInformationProcess", "ntdll.NtQueryInformationProcess", "Process info query (ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle)"),
    ("NtSetInformationThread", "ntdll.NtSetInformationThread", "Thread hiding (ThreadHideFromDebugger)"),
    ("OutputDebugString", "kernel32.OutputDebugString", "Debug string trick (error if debugger attached)"),
    ("CloseHandle", "kernel32.CloseHandle", "Invalid handle exception (debugger detects)"),
    ("BlockInput", "user32.BlockInput", "Input blocking detection"),
    ("GetTickCount", "kernel32.GetTickCount", "Timing check"),
    ("GetTickCount64", "kernel32.GetTickCount64", "Timing check (64-bit)"),
    ("QueryPerformanceCounter", "kernel32.QueryPerformanceCounter", "High-resolution timing"),
    ("QueryPerformanceFrequency", "kernel32.QueryPerformanceFrequency", "Timing frequency"),
    ("RDTSC", "CPU Instruction", "Time Stamp Counter (timing)"),
    ("CPUID", "CPU Instruction", "CPUID (hypervisor detection)"),
    ("SIDT", "CPU Instruction", "Store IDT (VM detection)"),
    ("SGDT", "CPU Instruction", "Store GDT (VM detection)"),
    ("STR", "CPU Instruction", "Store Task Register (VM detection)"),
    ("SLDT", "CPU Instruction", "Store LDT (VM detection)"),
    ("SMSW", "CPU Instruction", "Store Machine Status Word (VM detection)"),
    ("IN", "CPU Instruction", "IN instruction (VM port access)"),
    ("VMWare Backdoor", "I/O Port", "VMware backdoor port (0x5658)"),
    ("VBox Detection", "Registry/Files", "VirtualBox artifacts detection"),
    ("Hyper-V Detection", "CPUID/Hypercall", "Hyper-V hypervisor detection"),
    ("Parallels Detection", "Files/Registry", "Parallels artifacts"),
    ("QEMU Detection", "CPUID/Devices", "QEMU/KVM artifacts"),
    ("Xen Detection", "CPUID/Hypercall", "Xen hypervisor detection"),
    ("Sandboxie", "SbieDll.dll", "Sandboxie detection"),
    ("Cuckoo", "cuckoo", "Cuckoo Sandbox artifacts"),
    ("Joe Sandbox", "joesandbox", "Joe Sandbox artifacts"),
    ("Hybrid Analysis", "hybrid-analysis", "Hybrid Analysis artifacts"),
    ("Any.Run", "any.run", "Any.Run artifacts"),
    ("CAPE", "cape", "CAPE Sandbox artifacts"),
    ("VirusTotal", "virustotal", "VirusTotal artifacts"),
    ("Debugger Detection", "BeingDebugged", "PEB.BeingDebugged flag"),
    ("NtGlobalFlag", "NtGlobalFlag", "PEB.NtGlobalFlag heap flags"),
    ("Heap Flags", "HeapFlags", "Process heap flags"),
    ("Heap Tail", "HeapTail", "Heap tail checking"),
    ("Debug Object", "DebugObjectHandle", "Debug object handle"),
    ("Hardware Breakpoints", "DR0-DR7", "Hardware debug registers"),
    ("Software Breakpoints", "INT3/0xCC", "Software breakpoint (0xCC)"),
    ("Memory Breakpoints", "PAGE_GUARD", "Memory breakpoint (guard pages)"),
    ("Exception Handling", "VEH/SEH", "Vectored/Structured Exception Handling abuse"),
    ("UnhandledExceptionFilter", "kernel32.UnhandledExceptionFilter", "Exception filter manipulation"),
    ("SetUnhandledExceptionFilter", "kernel32.SetUnhandledExceptionFilter", "Set exception filter"),
    ("AddVectoredExceptionHandler", "kernel32.AddVectoredExceptionHandler", "VEH registration"),
    ("AddVectoredContinueHandler", "kernel32.AddVectoredContinueHandler", "VEH continue handler"),
    ("RaiseException", "kernel32.RaiseException", "Manual exception raising"),
    ("DebugBreak", "kernel32.DebugBreak", "Debug break"),
    ("DbgBreakPoint", "ntdll.DbgBreakPoint", "Kernel debug break"),
    ("DbgUiRemoteBreakin", "ntdll.DbgUiRemoteBreakin", "Remote debug break-in"),
    ("ZwContinue", "ntdll.ZwContinue", "Continue after exception"),
    ("ZwSetContextThread", "ntdll.ZwSetContextThread", "Set thread context (anti-debug)"),
    ("ZwGetContextThread", "ntdll.ZwGetContextThread", "Get thread context"),
    ("ZwCreateThreadEx", "ntdll.ZwCreateThreadEx", "Thread creation"),
    ("RtlCreateUserThread", "ntdll.RtlCreateUserThread", "User thread creation"),
    ("LdrLoadDll", "ntdll.LdrLoadDll", "DLL loading"),
    ("LdrGetProcedureAddress", "ntdll.LdrGetProcedureAddress", "Get proc address"),
    ("LdrRegisterDllNotification", "ntdll.LdrRegisterDllNotification", "DLL notification callback"),
    ("EtwEventWrite", "ntdll.EtwEventWrite", "ETW event writing (tampering)"),
    ("EtwEventRegister", "ntdll.EtwEventRegister", "ETW registration"),
    ("NtTraceEvent", "ntdll.NtTraceEvent", "Trace event"),
    ("WerRegisterRuntimeExceptionModule", "wer.dll", "Windows Error Reporting"),
    ("WerRegisterMemoryBlock", "wer.dll", "WER memory block"),
]

_ANTI_VM_PATTERNS = [
    # Registry
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "VMware/VirtualBox disk enum"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "VirtualBox Guest Additions"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", "VirtualBox Mouse"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxService", "VirtualBox Service"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VBoxSF", "VirtualBox Shared Folders"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VMTools", "VMware Tools"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\VMMEMCTL", "VMware Memory Control"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "VMware HGFS"),
    ("HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmmouse", "VMware Mouse"),
    ("HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "VMware SCSI"),
    ("HKLM\\HARDWARE\\Description\\System\\BIOS\\SystemManufacturer", "BIOS Manufacturer (VMware, VirtualBox, QEMU)"),
    ("HKLM\\HARDWARE\\Description\\System\\BIOS\\SystemProductName", "BIOS Product Name (VirtualBox, VMware, etc.)"),
    ("HKLM\\HARDWARE\\Description\\System\\BIOS\\VideoBiosVersion", "Video BIOS Version"),
    # Files
    ("C:\\Windows\\System32\\drivers\\VBoxGuest.sys", "VirtualBox Guest driver"),
    ("C:\\Windows\\System32\\drivers\\VBoxMouse.sys", "VirtualBox Mouse driver"),
    ("C:\\Windows\\System32\\drivers\\VBoxSF.sys", "VirtualBox Shared Folders driver"),
    ("C:\\Windows\\System32\\drivers\\VMTools.sys", "VMware Tools driver"),
    ("C:\\Windows\\System32\\drivers\\vmhgfs.sys", "VMware HGFS driver"),
    ("C:\\Windows\\System32\\drivers\\vmmouse.sys", "VMware Mouse driver"),
    ("C:\\Windows\\System32\\drivers\\vmxnet.sys", "VMware VMXNET driver"),
    ("C:\\Windows\\System32\\drivers\\vmx_svga.sys", "VMware SVGA driver"),
    ("C:\\Windows\\System32\\vboxdisp.dll", "VirtualBox Display DLL"),
    ("C:\\Windows\\System32\\vboxhook.dll", "VirtualBox Hook DLL"),
    ("C:\\Windows\\System32\\vboxmrxnp.dll", "VirtualBox MRxNP DLL"),
    ("C:\\Windows\\System32\\vboxogl.dll", "VirtualBox OpenGL DLL"),
    ("C:\\Windows\\System32\\vboxoglarrayspu.dll", "VirtualBox OpenGL Arrays SPU"),
    ("C:\\Windows\\System32\\vboxoglcrutil.dll", "VirtualBox OpenGL CR Util"),
    ("C:\\Windows\\System32\\vboxoglerrorspu.dll", "VirtualBox OpenGL Errors SPU"),
    ("C:\\Windows\\System32\\vboxoglfeedbackspu.dll", "VirtualBox OpenGL Feedback SPU"),
    ("C:\\Windows\\System32\\vboxoglpackspu.dll", "VirtualBox OpenGL Pack SPU"),
    ("C:\\Windows\\System32\\vboxoglpassthroughspu.dll", "VirtualBox OpenGL Passthrough SPU"),
    ("C:\\Windows\\System32\\vboxservice.exe", "VirtualBox Service"),
    ("C:\\Windows\\System32\\vboxtray.exe", "VirtualBox Tray"),
    ("C:\\Windows\\System32\\vmtoolsd.exe", "VMware Tools Daemon"),
    ("C:\\Windows\\System32\\vmacthlp.exe", "VMware Activation Helper"),
    ("C:\\Windows\\System32\\vmwareuser.exe", "VMware User Process"),
    ("C:\\Windows\\System32\\vmwaretray.exe", "VMware Tray"),
    # MAC Addresses (OUI)
    ("00:05:69", "VMware OUI"),
    ("00:0C:29", "VMware OUI"),
    ("00:1C:14", "VMware OUI"),
    ("00:50:56", "VMware OUI"),
    ("08:00:27", "VirtualBox OUI (PCnet)"),
    ("0A:00:27", "VirtualBox OUI (Intel PRO/1000)"),
    ("00:16:3E", "Xen/QEMU/KVM OUI"),
    ("00:1C:42", "Parallels OUI"),
    ("00:03:FF", "Microsoft Hyper-V OUI"),
    ("00:15:5D", "Microsoft Hyper-V OUI"),
    # CPUID
    ("CPUID Leaf 0x40000000", "Hypervisor CPUID leaf"),
    ("HyperV", "Microsoft Hyper-V signature"),
    ("VMwareVMware", "VMware signature"),
    ("XenVMMXenVMM", "Xen signature"),
    ("KVMKVMKVM", "KVM signature"),
    ("prl hyperv", "Parallels signature"),
    ("VBoxVBoxVBox", "VirtualBox signature"),
    # Devices
    ("\\\\.\\VBoxGuest", "VirtualBox Guest Device"),
    ("\\\\.\\VBoxMiniRdrDN", "VirtualBox Mini Redirector"),
    ("\\\\.\\VMwareTool", "VMware Tool Device"),
    ("\\\\.\\HGFS", "VMware HGFS Device"),
    ("\\\\.\\VMCI", "VMware VMCI Device"),
]

_SANDBOX_EVASION_PATTERNS = [
    # Timing/Delay
    ("Sleep", "Extended sleep (sandbox timeout evasion)"),
    ("SleepEx", "Alertable sleep"),
    ("NtDelayExecution", "Kernel delay execution"),
    ("GetTickCount", "Sandbox time acceleration detection"),
    ("QueryPerformanceCounter", "High-res timing check"),
    ("RDTSC", "CPU cycle counting"),
    # User Interaction
    ("GetCursorPos", "Mouse position check"),
    ("GetAsyncKeyState", "Keyboard state check"),
    ("GetKeyState", "Key state check"),
    ("GetLastInputInfo", "Last input time (idle detection)"),
    ("GetForegroundWindow", "Foreground window check"),
    ("GetActiveWindow", "Active window check"),
    ("SetForegroundWindow", "Foreground window manipulation"),
    ("ShowWindow", "Window show/hide"),
    ("IsWindowVisible", "Window visibility"),
    ("GetMessage", "Message loop check"),
    ("PeekMessage", "Message peek"),
    ("WaitMessage", "Wait for message"),
    # Environment
    ("GetUserName", "Username check (sandbox usernames: malware, sample, test, analyst)"),
    ("GetComputerName", "Computer name check"),
    ("GetWindowsDirectory", "Windows directory"),
    ("GetSystemDirectory", "System directory"),
    ("GetTempPath", "Temp path"),
    ("ExpandEnvironmentStrings", "Environment variable expansion"),
    ("GetVolumeInformation", "Volume serial number (sandbox: fixed values)"),
    ("GetDiskFreeSpace", "Disk space check (small disks)"),
    ("GetSystemMetrics", "System metrics (SM_CLEANBOOT, SM_REMOTESESSION)"),
    ("GetSystemInfo", "System info (processor count, memory)"),
    ("GlobalMemoryStatusEx", "Memory status (low RAM in sandboxes)"),
    ("GetNativeSystemInfo", "Native system info"),
    ("IsWow64Process", "WoW64 check"),
    ("GetProcessHeap", "Process heap"),
    ("HeapWalk", "Heap walking"),
    ("Toolhelp32Snapshot", "Process/module snapshot"),
    ("Process32First", "Process enumeration"),
    ("Process32Next", "Process enumeration"),
    ("Module32First", "Module enumeration"),
    ("Module32Next", "Module enumeration"),
    ("EnumWindows", "Window enumeration"),
    ("EnumProcesses", "Process enumeration (PSAPI)"),
    ("EnumProcessModules", "Module enumeration (PSAPI)"),
    ("GetModuleFileNameEx", "Module path (PSAPI)"),
    ("GetModuleInformation", "Module info (PSAPI)"),
    ("WNetGetConnection", "Network connection"),
    ("WNetOpenEnum", "Network enumeration"),
    ("WNetEnumResource", "Network resource enumeration"),
    ("GetAdaptersInfo", "Network adapter info"),
    ("GetAdaptersAddresses", "Network adapter addresses (IPHLPAPI)"),
    ("GetIfTable", "Interface table (IPHLPAPI)"),
    ("GetIpAddrTable", "IP address table (IPHLPAPI)"),
    ("GetBestRoute", "Best route (IPHLPAPI)"),
    ("GetTcpTable", "TCP table (IPHLPAPI)"),
    ("GetUdpTable", "UDP table (IPHLPAPI)"),
    ("GetExtendedTcpTable", "Extended TCP table (IPHLPAPI)"),
    ("GetExtendedUdpTable", "Extended UDP table (IPHLPAPI)"),
    ("GetPerAdapterInfo", "Per-adapter info (IPHLPAPI)"),
    ("GetDnsSettings", "DNS settings"),
    ("DnsQuery", "DNS query"),
    ("InternetOpen", "WinINet session"),
    ("InternetConnect", "WinINet connection"),
    ("HttpOpenRequest", "WinINet HTTP request"),
    ("HttpSendRequest", "WinINet HTTP send"),
    ("InternetReadFile", "WinINet read"),
    ("InternetWriteFile", "WinINet write"),
    ("WinHttpOpen", "WinHTTP session"),
    ("WinHttpConnect", "WinHTTP connect"),
    ("WinHttpOpenRequest", "WinHTTP request"),
    ("WinHttpSendRequest", "WinHTTP send"),
    ("WinHttpReceiveResponse", "WinHTTP receive"),
    ("WinHttpReadData", "WinHTTP read"),
    ("WinHttpWriteData", "WinHTTP write"),
    ("URLDownloadToFile", "URL download"),
    ("URLDownloadToCacheFile", "URL download to cache"),
    ("WinInet", "WinINet usage"),
    ("WinHttp", "WinHTTP usage"),
    # File/Registry artifacts
    ("CreateFile", "File creation check"),
    ("CreateFileW", "File creation (Unicode)"),
    ("CreateFileA", "File creation (ANSI)"),
    ("ReadFile", "File read"),
    ("WriteFile", "File write"),
    ("DeleteFile", "File deletion"),
    ("MoveFile", "File move"),
    ("CopyFile", "File copy"),
    ("GetFileAttributes", "File attributes"),
    ("GetFileAttributesW", "File attributes (Unicode)"),
    ("GetFileAttributesA", "File attributes (ANSI)"),
    ("SetFileAttributes", "Set file attributes"),
    ("FindFirstFile", "File search"),
    ("FindFirstFileW", "File search (Unicode)"),
    ("FindFirstFileA", "File search (ANSI)"),
    ("FindNextFile", "File search next"),
    ("FindNextFileW", "File search next (Unicode)"),
    ("FindNextFileA", "File search next (ANSI)"),
    ("FindClose", "File search close"),
    ("RegOpenKey", "Registry open"),
    ("RegOpenKeyEx", "Registry open extended"),
    ("RegOpenKeyExW", "Registry open extended (Unicode)"),
    ("RegOpenKeyExA", "Registry open extended (ANSI)"),
    ("RegQueryValue", "Registry query"),
    ("RegQueryValueEx", "Registry query extended"),
    ("RegQueryValueExW", "Registry query extended (Unicode)"),
    ("RegQueryValueExA", "Registry query extended (ANSI)"),
    ("RegSetValue", "Registry set"),
    ("RegSetValueEx", "Registry set extended"),
    ("RegSetValueExW", "Registry set extended (Unicode)"),
    ("RegSetValueExA", "Registry set extended (ANSI)"),
    ("RegCreateKey", "Registry create"),
    ("RegCreateKeyEx", "Registry create extended"),
    ("RegCreateKeyExW", "Registry create extended (Unicode)"),
    ("RegCreateKeyExA", "Registry create extended (ANSI)"),
    ("RegDeleteKey", "Registry delete"),
    ("RegDeleteKeyEx", "Registry delete extended"),
    ("RegDeleteKeyExW", "Registry delete extended (Unicode)"),
    ("RegDeleteKeyExA", "Registry delete extended (ANSI)"),
    ("RegDeleteValue", "Registry delete value"),
    ("RegEnumKey", "Registry enum key"),
    ("RegEnumKeyEx", "Registry enum key extended"),
    ("RegEnumKeyExW", "Registry enum key extended (Unicode)"),
    ("RegEnumKeyExA", "Registry enum key extended (ANSI)"),
    ("RegEnumValue", "Registry enum value"),
    ("RegEnumValueW", "Registry enum value (Unicode)"),
    ("RegEnumValueA", "Registry enum value (ANSI)"),
    ("RegCloseKey", "Registry close"),
    ("RegFlushKey", "Registry flush"),
    # Process/Thread
    ("CreateProcess", "Process creation"),
    ("CreateProcessW", "Process creation (Unicode)"),
    ("CreateProcessA", "Process creation (ANSI)"),
    ("CreateRemoteThread", "Remote thread creation"),
    ("CreateThread", "Thread creation"),
    ("OpenProcess", "Process open"),
    ("OpenThread", "Thread open"),
    ("TerminateProcess", "Process termination"),
    ("TerminateThread", "Thread termination"),
    ("SuspendThread", "Thread suspension"),
    ("ResumeThread", "Thread resumption"),
    ("QueueUserAPC", "User APC queue"),
    ("SetThreadContext", "Thread context set"),
    ("GetThreadContext", "Thread context get"),
    ("VirtualAlloc", "Virtual memory allocation"),
    ("VirtualAllocEx", "Virtual memory allocation (remote)"),
    ("VirtualFree", "Virtual memory free"),
    ("VirtualFreeEx", "Virtual memory free (remote)"),
    ("VirtualProtect", "Virtual memory protect"),
    ("VirtualProtectEx", "Virtual memory protect (remote)"),
    ("VirtualQuery", "Virtual memory query"),
    ("VirtualQueryEx", "Virtual memory query (remote)"),
    ("ReadProcessMemory", "Process memory read"),
    ("WriteProcessMemory", "Process memory write"),
    ("NtReadVirtualMemory", "Kernel read virtual memory"),
    ("NtWriteVirtualMemory", "Kernel write virtual memory"),
    ("NtAllocateVirtualMemory", "Kernel allocate virtual memory"),
    ("NtFreeVirtualMemory", "Kernel free virtual memory"),
    ("NtProtectVirtualMemory", "Kernel protect virtual memory"),
    ("NtQueryVirtualMemory", "Kernel query virtual memory"),
    ("NtCreateSection", "Kernel create section"),
    ("NtMapViewOfSection", "Kernel map view of section"),
    ("NtUnmapViewOfSection", "Kernel unmap view of section"),
    ("NtCreateThreadEx", "Kernel create thread"),
    ("RtlCreateUserThread", "User thread creation"),
    ("LdrLoadDll", "Load DLL"),
    ("LdrGetProcedureAddress", "Get procedure address"),
    ("LdrRegisterDllNotification", "DLL notification"),
    ("NtQuerySystemInformation", "System information query"),
    ("NtQueryInformationProcess", "Process information query"),
    ("NtQueryInformationThread", "Thread information query"),
    ("NtSetInformationProcess", "Process information set"),
    ("NtSetInformationThread", "Thread information set"),
    ("NtCreateFile", "Kernel create file"),
    ("NtOpenFile", "Kernel open file"),
    ("NtReadFile", "Kernel read file"),
    ("NtWriteFile", "Kernel write file"),
    ("NtDeleteFile", "Kernel delete file"),
    ("NtCreateKey", "Kernel create registry key"),
    ("NtOpenKey", "Kernel open registry key"),
    ("NtQueryValueKey", "Kernel query registry value"),
    ("NtSetValueKey", "Kernel set registry value"),
    ("NtDeleteKey", "Kernel delete registry key"),
    ("NtEnumerateKey", "Kernel enumerate registry key"),
    ("NtEnumerateValueKey", "Kernel enumerate registry value"),
    ("NtClose", "Kernel close handle"),
    ("NtWaitForSingleObject", "Kernel wait single object"),
    ("NtWaitForMultipleObjects", "Kernel wait multiple objects"),
    ("NtSignalAndWaitForSingleObject", "Kernel signal and wait"),
    ("NtDelayExecution", "Kernel delay execution"),
    ("NtYieldExecution", "Kernel yield execution"),
    ("NtTestAlert", "Kernel test alert"),
    ("NtContinue", "Kernel continue"),
    ("NtRaiseException", "Kernel raise exception"),
    ("NtRaiseHardError", "Kernel raise hard error"),
    ("NtGetContextThread", "Kernel get thread context"),
    ("NtSetContextThread", "Kernel set thread context"),
    ("NtCreateEvent", "Kernel create event"),
    ("NtOpenEvent", "Kernel open event"),
    ("NtSetEvent", "Kernel set event"),
    ("NtResetEvent", "Kernel reset event"),
    ("NtPulseEvent", "Kernel pulse event"),
    ("NtQueryEvent", "Kernel query event"),
    ("NtCreateMutant", "Kernel create mutant"),
    ("NtOpenMutant", "Kernel open mutant"),
    ("NtReleaseMutant", "Kernel release mutant"),
    ("NtQueryMutant", "Kernel query mutant"),
    ("NtCreateSemaphore", "Kernel create semaphore"),
    ("NtOpenSemaphore", "Kernel open semaphore"),
    ("NtReleaseSemaphore", "Kernel release semaphore"),
    ("NtQuerySemaphore", "Kernel query semaphore"),
    ("NtCreateTimer", "Kernel create timer"),
    ("NtOpenTimer", "Kernel open timer"),
    ("NtSetTimer", "Kernel set timer"),
    ("NtCancelTimer", "Kernel cancel timer"),
    ("NtQueryTimer", "Kernel query timer"),
]

# ──────────────────────────────────────────────────────────────────────────────

def detect_obfuscation(file_path: Path, pe_info: dict | None = None, elf_info: dict | None = None, macho_info: dict | None = None) -> dict:
    """
    Detect obfuscation, packing, anti-analysis, and anti-VM techniques.
    """
    result: dict = {
        "available": True,
        "packers_detected": [],
        "anti_debug": [],
        "anti_vm": [],
        "sandbox_evasion": [],
        "obfuscation_techniques": [],
        "control_flow_obfuscation": [],
        "api_hashing": [],
        "string_encryption": [],
        "vm_protectors": [],
        "custom_protectors": [],
        "confidence": "low",
        "overall_risk": 0,
    }

    try:
        data = file_path.read_bytes()
        text = data.decode("utf-8", errors="ignore").lower()
        
        # ─── Packer Detection ───
        result["packers_detected"] = _detect_packers(data, text, pe_info, elf_info, macho_info)
        
        # ─── Anti-Debug ───
        result["anti_debug"] = _detect_anti_debug(data, text, pe_info)
        
        # ─── Anti-VM ───
        result["anti_vm"] = _detect_anti_vm(data, text, pe_info)
        
        # ─── Sandbox Evasion ───
        result["sandbox_evasion"] = _detect_sandbox_evasion(data, text, pe_info)
        
        # ─── Obfuscation Techniques ───
        result["obfuscation_techniques"] = _detect_obfuscation_techniques(data, text, pe_info)
        
        # ─── Control Flow Obfuscation ───
        result["control_flow_obfuscation"] = _detect_control_flow_obfuscation(data, text, pe_info)
        
        # ─── API Hashing ───
        result["api_hashing"] = _detect_api_hashing(data, text, pe_info)
        
        # ─── String Encryption ───
        result["string_encryption"] = _detect_string_encryption(data, text, pe_info)
        
        # ─── VM Protectors ───
        result["vm_protectors"] = _detect_vm_protectors(data, text, pe_info)
        
        # ─── Custom Protectors ───
        result["custom_protectors"] = _detect_custom_protectors(data, text, pe_info)
        
        # ─── Calculate Overall Risk ───
        result["overall_risk"] = _calculate_obfuscation_risk(result)
        result["confidence"] = _calculate_confidence(result)
        
    except Exception as exc:
        logger.exception("Obfuscation detection failed")
        return {"error": f"Failed to detect obfuscation: {exc}", "available": False}

    return result


def _detect_packers(data: bytes, text: str, pe_info: dict, elf_info: dict, macho_info: dict) -> list[dict]:
    """Detect known packers/protectors."""
    detected = []
    
    for packer_name, signatures in _PACKER_SIGNATURES.items():
        matches = []
        confidence = 0
        
        # Check section names
        for section in signatures.get("sections", []):
            if pe_info and "sections" in pe_info:
                for sec in pe_info["sections"]:
                    if section.lower() in sec.get("name", "").lower():
                        matches.append(f"Section name: {section}")
                        confidence += 30
            if elf_info and "sections" in elf_info:
                for sec in elf_info["sections"]:
                    if section.lower() in sec.get("name", "").lower():
                        matches.append(f"ELF Section name: {section}")
                        confidence += 30
            if macho_info and "sections" in macho_info:
                for sec in macho_info["sections"]:
                    if section.lower() in sec.get("name", "").lower():
                        matches.append(f"Mach-O Section name: {section}")
                        confidence += 30
        
        # Check strings
        for string in signatures.get("strings", []):
            if string.lower() in text:
                matches.append(f"String: {string}")
                confidence += 20
        
        # Check imports
        for imp in signatures.get("imports", []):
            if pe_info and "imports" in pe_info:
                for pimp in pe_info["imports"]:
                    if imp.lower() in str(pimp).lower():
                        matches.append(f"Import: {imp}")
                        confidence += 25
        
        if matches:
            detected.append({
                "packer": packer_name,
                "description": signatures.get("description", ""),
                "matches": matches,
                "confidence": min(confidence, 100),
            })
    
    return sorted(detected, key=lambda x: x["confidence"], reverse=True)


def _detect_anti_debug(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect anti-debugging techniques."""
    detected = []
    
    for api, description, details in _ANTI_DEBUG_PATTERNS:
        found = False
        context = ""
        
        # Check in imports
        if pe_info and "imports" in pe_info:
            for imp in pe_info["imports"]:
                if api.lower() in str(imp).lower():
                    found = True
                    context = f"Import: {imp}"
                    break
        
        # Check in strings
        if not found and api.lower() in text:
            found = True
            # Find context
            idx = text.find(api.lower())
            context = text[max(0, idx-100):idx+100]
        
        # Check in assembly (would need disassembly)
        # For now, just check strings/imports
        
        if found:
            detected.append({
                "api": api,
                "description": description,
                "details": details,
                "context": context[:200],
            })
    
    return detected


def _detect_anti_vm(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect anti-VM/sandbox techniques."""
    detected = []
    
    for indicator, description in _ANTI_VM_PATTERNS:
        found = False
        context = ""
        
        if indicator.lower() in text:
            found = True
            idx = text.find(indicator.lower())
            context = text[max(0, idx-100):idx+100]
        
        if found:
            detected.append({
                "indicator": indicator,
                "description": description,
                "context": context[:200],
            })
    
    return detected


def _detect_sandbox_evasion(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect sandbox evasion techniques."""
    detected = []
    
    for api, description in _SANDBOX_EVASION_PATTERNS:
        found = False
        context = ""
        
        # Check in imports
        if pe_info and "imports" in pe_info:
            for imp in pe_info["imports"]:
                if api.lower() in str(imp).lower():
                    found = True
                    context = f"Import: {imp}"
                    break
        
        # Check in strings
        if not found and api.lower() in text:
            found = True
            idx = text.find(api.lower())
            context = text[max(0, idx-100):idx+100]
        
        if found:
            detected.append({
                "api": api,
                "description": description,
                "context": context[:200],
            })
    
    return detected


def _detect_obfuscation_techniques(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect general obfuscation techniques."""
    techniques = []
    
    # High entropy sections (packing/encryption)
    if pe_info and "sections" in pe_info:
        for sec in pe_info["sections"]:
            if sec.get("entropy", 0) >= 7.5:
                techniques.append({
                    "technique": "High Entropy Section",
                    "section": sec.get("name", "unknown"),
                    "entropy": sec.get("entropy", 0),
                    "description": "Section has very high entropy, likely packed or encrypted",
                })
    
    # Overlay data
    if pe_info and pe_info.get("overlay", {}).get("has_overlay"):
        techniques.append({
            "technique": "Overlay Data",
            "size": pe_info["overlay"].get("size", 0),
            "entropy": pe_info["overlay"].get("entropy", 0),
            "description": "Data appended after last section (possible embedded payload)",
        })
    
    # Suspicious section permissions
    if pe_info and "section_permissions_audit" in pe_info:
        for audit in pe_info["section_permissions_audit"]:
            techniques.append({
                "technique": "Suspicious Section Permissions",
                "section": audit.get("section", "unknown"),
                "issues": audit.get("issues", []),
                "description": "Section has anomalous permissions (RWX, writable code, etc.)",
            })
    
    # Rich header anomalies
    if pe_info and "rich_header" in pe_info:
        rich = pe_info["rich_header"]
        if rich.get("entries"):
            # Check for unusual tool IDs
            for entry in rich["entries"]:
                if entry.get("tool_name", "").startswith("Unknown"):
                    techniques.append({
                        "technique": "Unknown Rich Header Tool",
                        "tool_id": entry.get("tool_id"),
                        "count": entry.get("count"),
                        "description": "Rich header contains unknown build tool ID",
                    })
    
    # TLS callbacks (can be used for anti-debug)
    if pe_info and "tls" in pe_info:
        tls = pe_info["tls"]
        if tls.get("has_tls") and tls.get("callback_count", 0) > 0:
            techniques.append({
                "technique": "TLS Callbacks",
                "count": tls.get("callback_count", 0),
                "callbacks": tls.get("callbacks", []),
                "description": "Thread Local Storage callbacks (can execute before entry point)",
            })
    
    # Delay-load imports (can hide imports)
    if pe_info and "delay_load_imports" in pe_info:
        if pe_info["delay_load_imports"]:
            techniques.append({
                "technique": "Delay-Load Imports",
                "count": len(pe_info["delay_load_imports"]),
                "description": "Imports loaded at runtime (can hide static analysis)",
            })
    
    # Bound imports (timestamp validation)
    if pe_info and "bound_imports" in pe_info and pe_info["bound_imports"]:
        techniques.append({
            "technique": "Bound Imports",
            "description": "Imports bound to specific DLL versions (anti-tamper)",
        })
    
    # .NET specific
    if pe_info and "clr" in pe_info and pe_info["clr"].get("is_managed"):
        techniques.append({
            "technique": ".NET Managed Code",
            "description": "Managed assembly (requires .NET decompilation for full analysis)",
        })
    
    return techniques


def _detect_control_flow_obfuscation(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect control flow obfuscation (CFG flattening, opaque predicates, etc.)."""
    cf_obf = []
    
    # These would require disassembly/control flow analysis
    # For now, we detect indicators in strings/imports
    
    cf_indicators = [
        ("opaque predicate", "Opaque Predicate"),
        ("control flow flattening", "Control Flow Flattening"),
        ("cfg flattening", "CFG Flattening"),
        ("dispatcher loop", "Dispatcher Loop"),
        ("overlapping instructions", "Overlapping Instructions"),
        ("instruction substitution", "Instruction Substitution"),
        ("junk code", "Junk Code Insertion"),
        ("dead code", "Dead Code Insertion"),
        ("code transposition", "Code Transposition"),
        ("register swapping", "Register Swapping"),
        ("instruction reordering", "Instruction Reordering"),
        ("basic block splitting", "Basic Block Splitting"),
        ("loop unwinding", "Loop Unwinding"),
        ("loop inversion", "Loop Inversion"),
        ("function inlining", "Function Inlining"),
        ("function outlining", "Function Outlining"),
        ("tail call optimization", "Tail Call Optimization"),
        ("indirect jumps", "Indirect Jumps/Call"),
        ("computed gotos", "Computed Gotos"),
        ("switch dispatch", "Switch Dispatch"),
    ]
    
    for keyword, name in cf_indicators:
        if keyword in text:
            cf_obf.append({
                "technique": name,
                "indicator": keyword,
                "context": text[max(0, text.find(keyword)-50):text.find(keyword)+100],
            })
    
    return cf_obf


def _detect_api_hashing(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect API hashing (dynamic API resolution)."""
    api_hash = []
    
    # Common API hash algorithms
    hash_algos = [
        ("djb2", "DJB2 Hash"),
        ("fnv", "FNV Hash"),
        ("fnv1a", "FNV-1a Hash"),
        ("crc32", "CRC32 Hash"),
        ("ror", "ROR Hash (Rotate Right)"),
        ("rol", "ROL Hash (Rotate Left)"),
        ("crc32c", "CRC32C (Castagnoli)"),
        ("murmur", "MurmurHash"),
        ("xxhash", "xxHash"),
        ("siphash", "SipHash"),
        ("custom hash", "Custom Hash Function"),
        ("api hash", "API Hashing"),
        ("hash api", "API Hash"),
        ("resolve api", "Dynamic API Resolution"),
        ("getprocaddress", "GetProcAddress Usage"),
        ("loadlibrary", "LoadLibrary Usage"),
        ("lldrloaddll", "LdrLoadDll Usage"),
        ("lldrgetprocedureaddress", "LdrGetProcedureAddress Usage"),
    ]
    
    for keyword, name in hash_algos:
        if keyword in text:
            api_hash.append({
                "algorithm": name,
                "indicator": keyword,
                "context": text[max(0, text.find(keyword)-50):text.find(keyword)+100],
            })
    
    # Also check for common hash constants in data
    # DJB2: 5381
    if struct.pack("<I", 5381) in data:
        api_hash.append({
            "algorithm": "DJB2 Hash",
            "indicator": "Constant 5381 found in binary",
            "context": "DJB2 initial hash value",
        })
    
    # FNV offset basis
    if struct.pack("<I", 0x811C9DC5) in data or struct.pack("<Q", 0xCBF29CE484222325) in data:
        api_hash.append({
            "algorithm": "FNV Hash",
            "indicator": "FNV offset basis constant found",
            "context": "FNV-1/FNV-1a initial value",
        })
    
    return api_hash


def _detect_string_encryption(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect string encryption/obfuscation."""
    str_enc = []
    
    indicators = [
        ("string encryption", "String Encryption"),
        ("encrypted strings", "Encrypted Strings"),
        ("stack strings", "Stack Strings"),
        ("heap strings", "Heap Strings"),
        ("runtime decryption", "Runtime Decryption"),
        ("decrypt string", "String Decryption Function"),
        ("xor string", "XOR String Encryption"),
        ("rc4 string", "RC4 String Encryption"),
        ("aes string", "AES String Encryption"),
        ("custom encryption", "Custom String Encryption"),
        ("obfuscated strings", "Obfuscated Strings"),
        ("string obfuscation", "String Obfuscation"),
        ("packed strings", "Packed Strings"),
        ("compressed strings", "Compressed Strings"),
        ("encoded strings", "Encoded Strings"),
        ("base64 string", "Base64 Encoded Strings"),
        ("rot13", "ROT13"),
        ("caesar", "Caesar Cipher"),
        ("vigenere", "Vigenere Cipher"),
    ]
    
    for keyword, name in indicators:
        if keyword in text:
            str_enc.append({
                "technique": name,
                "indicator": keyword,
                "context": text[max(0, text.find(keyword)-50):text.find(keyword)+100],
            })
    
    # Check for high-entropy strings in binary (potential encrypted strings)
    # This would need more sophisticated analysis
    
    return str_enc


def _detect_vm_protectors(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect virtual machine based protectors."""
    vm_prot = []
    
    vm_protectors = {
        "VMProtect": ["VMProtect", "VMP0", "VMP1", "VMP2", "VMP3", ".vmp0", ".vmp1", ".vmp2", ".vmp3", "Virtual Machine Protect"],
        "Themida": ["Themida", "Oreans", "WinLicense", ".themida", ".themida_"],
        "CodeVirtualizer": ["CodeVirtualizer", "Oreans", ".cv", ".cv_"],
        "Enigma Protector": ["Enigma Protector", "Enigma", ".enigma", ".enigma_", "EP_"],
        "Obsidium": ["Obsidium", ".obsidium"],
        "PElock": ["PELock", ".pelock"],
        "EXECryptor": ["EXECryptor", "StrongBit", ".execryptor"],
        "VMP": ["VMP", "VM Protect"],
    }
    
    for protector, indicators in vm_protectors.items():
        matches = []
        for ind in indicators:
            if ind.lower() in text:
                matches.append(ind)
            # Check sections
            if pe_info and "sections" in pe_info:
                for sec in pe_info["sections"]:
                    if ind.lower() in sec.get("name", "").lower():
                        matches.append(f"Section: {sec['name']}")
        
        if matches:
            vm_prot.append({
                "protector": protector,
                "matches": matches,
                "confidence": min(len(matches) * 20, 100),
            })
    
    return vm_prot


def _detect_custom_protectors(data: bytes, text: str, pe_info: dict) -> list[dict]:
    """Detect custom/unknown protectors."""
    custom = []
    
    # Look for unknown section names with high entropy
    if pe_info and "sections" in pe_info:
        for sec in pe_info["sections"]:
            name = sec.get("name", "")
            entropy = sec.get("entropy", 0)
            if entropy > 7.0 and name not in [".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".tls", ".idata", ".edata", ".pdata"]:
                # Check if it's a known packer section
                is_known = any(packer_sec.lower() in name.lower() for packer_sec in _KNOWN_PACKER_SECTIONS)
                if not is_known:
                    custom.append({
                        "type": "Unknown High-Entropy Section",
                        "section": name,
                        "entropy": entropy,
                        "description": "Section with high entropy and unknown name (possible custom packer/protector)",
                    })
    
    # Look for custom packer strings
    custom_strings = ["custom packer", "own packer", "homebrew packer", "proprietary packer", "internal packer", "private packer"]
    for cs in custom_strings:
        if cs in text:
            custom.append({
                "type": "Custom Packer Reference",
                "string": cs,
                "context": text[max(0, text.find(cs)-50):text.find(cs)+100],
            })
    
    return custom


def _calculate_obfuscation_risk(result: dict) -> int:
    """Calculate overall obfuscation risk score (0-100)."""
    score = 0
    
    # Packers
    for packer in result.get("packers_detected", []):
        score += min(packer.get("confidence", 0) // 2, 20)
    
    # Anti-debug
    score += min(len(result.get("anti_debug", [])) * 3, 20)
    
    # Anti-VM
    score += min(len(result.get("anti_vm", [])) * 2, 15)
    
    # Sandbox evasion
    score += min(len(result.get("sandbox_evasion", [])) * 2, 15)
    
    # Obfuscation techniques
    score += min(len(result.get("obfuscation_techniques", [])) * 4, 20)
    
    # Control flow
    score += min(len(result.get("control_flow_obfuscation", [])) * 5, 20)
    
    # API hashing
    score += min(len(result.get("api_hashing", [])) * 5, 15)
    
    # String encryption
    score += min(len(result.get("string_encryption", [])) * 3, 15)
    
    # VM protectors
    for prot in result.get("vm_protectors", []):
        score += min(prot.get("confidence", 0) // 2, 20)
    
    # Custom protectors
    score += min(len(result.get("custom_protectors", [])) * 5, 10)
    
    return min(100, score)


def _calculate_confidence(result: dict) -> str:
    """Calculate confidence level."""
    risk = result.get("overall_risk", 0)
    if risk >= 70:
        return "high"
    elif risk >= 40:
        return "medium"
    elif risk > 0:
        return "low"
    return "none"


# Import struct for constant checking
import struct

_KNOWN_PACKER_SECTIONS = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "ASPack", ".petite",
    ".themida", ".vmp0", ".vmp1", ".vmp2", ".vmp3", "pec1", "pec2",
    ".enigma", ".pcle", ".perplex", ".mew", ".y0da", ".y0da1", ".y0da2",
    ".kkrunchy", ".mppress", ".pecompact", ".rlpack", ".nspack",
    ".fsg", ".upack", ".packer", ".protect", ".guard", ".shield",
}