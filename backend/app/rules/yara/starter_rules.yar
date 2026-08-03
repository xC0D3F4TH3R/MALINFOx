rule MALINFO_Packer_UPX
{
    meta:
        description = "UPX Packer Detection"
        author = "MALINFO"
        severity = "medium"
        mitre = ["T1027.002"]
        version = "1"
    strings:
        $upx0 = "UPX!" ascii wide
        $upx1 = "UPX0" ascii wide
        $upx2 = "UPX1" ascii wide
        $upx3 = { 55 8B EC 81 EC ?? ?? ?? ?? 53 56 57 8D 85 ?? ?? ?? ?? 50 6A 00 6A 00 }
    condition:
        any of them
}

rule MALINFO_Packer_ASPack
{
    meta:
        description = "ASPack Packer Detection"
        author = "MALINFO"
        severity = "medium"
        mitre = ["T1027.002"]
        version = "1"
    strings:
        $aspack1 = ".aspack" ascii wide
        $aspack2 = "ASPack" ascii wide
    condition:
        any of them
}

rule MALINFO_Packer_Themida
{
    meta:
        description = "Themida/WinLicense Packer Detection"
        author = "MALINFO"
        severity = "high"
        mitre = ["T1027.003"]
        version = "1"
    strings:
        $themida1 = "Themida" ascii wide
        $themida2 = "WinLicense" ascii wide
        $themida3 = ".themida" ascii wide
    condition:
        any of them
}

rule MALINFO_Packer_VMProtect
{
    meta:
        description = "VMProtect Packer Detection"
        author = "MALINFO"
        severity = "high"
        mitre = ["T1027.003"]
        version = "1"
    strings:
        $vmprotect1 = "VMProtect" ascii wide
        $vmprotect2 = ".vmp" ascii wide
        $vmprotect3 = { 55 8B EC 83 EC 10 53 56 57 8B 7D 08 8B 47 3C }
    condition:
        any of them
}

rule MALINFO_Ransomware_Generic
{
    meta:
        description = "Generic Ransomware Indicators"
        author = "MALINFO"
        severity = "critical"
        mitre = ["T1486"]
        version = "1"
    strings:
        $ransom1 = "README" ascii wide nocase
        $ransom2 = "DECRYPT" ascii wide nocase
        $ransom3 = "RECOVER" ascii wide nocase
        $ransom4 = ".encrypted" ascii wide nocase
        $ransom5 = ".locked" ascii wide nocase
        $ransom6 = "bitcoin" ascii wide nocase
        $ransom7 = "ransom" ascii wide nocase
        $ransom8 = "pay" ascii wide nocase
        $crypto1 = "AES" ascii wide
        $crypto2 = "RSA" ascii wide
        $crypto3 = "CryptEncrypt" ascii wide
        $crypto4 = "CryptDecrypt" ascii wide
    condition:
        (3 of ($ransom*)) or (2 of ($ransom*) and 2 of ($crypto*))
}

rule MALINFO_C2_CobaltStrike
{
    meta:
        description = "Cobalt Strike Beacon Indicators"
        author = "MALINFO"
        severity = "critical"
        mitre = ["T1573.001", "T1071.001"]
        version = "1"
    strings:
        $cs1 = "cobaltstrike" ascii wide nocase
        $cs2 = "beacon" ascii wide nocase
        $cs3 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } // Watermark placeholder
        $cs4 = "pipe_" ascii wide nocase
        $cs5 = "msagent" ascii wide nocase
        $cs6 = "post_" ascii wide nocase
        $cs7 = "get_" ascii wide nocase
        $cs8 = "x64" ascii wide nocase
        $cs9 = "x86" ascii wide nocase
    condition:
        2 of them
}

rule MALINFO_C2_Sliver
{
    meta:
        description = "Sliver C2 Framework Indicators"
        author = "MALINFO"
        severity = "critical"
        mitre = ["T1573.001"]
        version = "1"
    strings:
        $sliver1 = "sliver" ascii wide nocase
        $sliver2 = "implant" ascii wide nocase
        $sliver3 = "session" ascii wide nocase
        $sliver4 = "mtls" ascii wide nocase
        $sliver5 = "wireguard" ascii wide nocase
    condition:
        any of them
}

rule MALINFO_Suspicious_API_Calls
{
    meta:
        description = "Suspicious Windows API Call Patterns"
        author = "MALINFO"
        severity = "medium"
        mitre = ["T1055", "T1027", "T1003"]
        version = "1"
    strings:
        $inj1 = "CreateRemoteThread" ascii wide
        $inj2 = "WriteProcessMemory" ascii wide
        $inj3 = "VirtualAllocEx" ascii wide
        $inj4 = "OpenProcess" ascii wide
        $inj5 = "NtCreateThreadEx" ascii wide
        $inj6 = "QueueUserAPC" ascii wide
        $inj7 = "SetThreadContext" ascii wide
        $elev1 = "AdjustTokenPrivileges" ascii wide
        $elev2 = "SeDebugPrivilege" ascii wide
        $cred1 = "LsaEnumerateLogonSessions" ascii wide
        $cred2 = "LsaGetLogonSessionData" ascii wide
        $cred3 = "CryptUnprotectData" ascii wide
        $persist1 = "RegSetValueEx" ascii wide
        $persist2 = "Run" ascii wide
        $persist3 = "RunOnce" ascii wide
        $persist4 = "ShellExecute" ascii wide
    condition:
        (3 of ($inj*)) or (2 of ($elev*)) or (2 of ($cred*)) or (3 of ($persist*))
}

rule MALINFO_Anti_Debug_VM
{
    meta:
        description = "Anti-Debugging and Anti-VM Techniques"
        author = "MALINFO"
        severity = "high"
        mitre = ["T1622", "T1497"]
        version = "1"
    strings:
        $dbg1 = "IsDebuggerPresent" ascii wide
        $dbg2 = "CheckRemoteDebuggerPresent" ascii wide
        $dbg3 = "NtQueryInformationProcess" ascii wide
        $dbg4 = "OutputDebugString" ascii wide
        $dbg5 = "CloseHandle" ascii wide
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "QEMU" ascii wide nocase
        $vm4 = "Xen" ascii wide nocase
        $vm5 = "Hyper-V" ascii wide nocase
        $vm6 = "VBOX" ascii wide nocase
        $vm7 = "redpill" ascii wide nocase
        $vm8 = "sidt" ascii wide nocase
        $vm9 = "sgdt" ascii wide nocase
        $vm10 = "str" ascii wide nocase
        $time1 = "RDTSC" ascii wide
        $time2 = "QueryPerformanceCounter" ascii wide
        $time3 = "GetTickCount" ascii wide
    condition:
        (2 of ($dbg*)) or (2 of ($vm*)) or (2 of ($time*))
}

rule MALINFO_Downloader_Generic
{
    meta:
        description = "Generic Downloader/Stager Patterns"
        author = "MALINFO"
        severity = "high"
        mitre = ["T1105", "T1059"]
        version = "1"
    strings:
        $dl1 = "URLDownloadToFile" ascii wide
        $dl2 = "WinHttpOpen" ascii wide
        $dl3 = "WinHttpConnect" ascii wide
        $dl4 = "WinHttpOpenRequest" ascii wide
        $dl5 = "WinHttpSendRequest" ascii wide
        $dl6 = "WinHttpReceiveResponse" ascii wide
        $dl7 = "InternetOpen" ascii wide
        $dl8 = "InternetOpenUrl" ascii wide
        $dl9 = "InternetReadFile" ascii wide
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "Invoke-Expression" ascii wide nocase
        $ps3 = "IEX" ascii wide nocase
        $ps4 = "DownloadString" ascii wide nocase
        $ps5 = "WebClient" ascii wide nocase
        $ps6 = "DownloadFile" ascii wide nocase
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "/c" ascii wide nocase
        $cmd3 = "certutil" ascii wide nocase
        $cmd4 = "bitsadmin" ascii wide nocase
    condition:
        (2 of ($dl*)) or (2 of ($ps*)) or (2 of ($cmd*))
}

rule MALINFO_Credential_Theft
{
    meta:
        description = "Credential Theft Tools and Techniques"
        author = "MALINFO"
        severity = "critical"
        mitre = ["T1003", "T1555", "T1558"]
        version = "1"
    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "sekurlsa" ascii wide nocase
        $mimi3 = "lsadump" ascii wide nocase
        $mimi4 = "privilege::debug" ascii wide nocase
        $mimi5 = "token::elevate" ascii wide nocase
        $lazagne1 = "lazagne" ascii wide nocase
        $lazagne2 = "LaZagne" ascii wide nocase
        $gsecdump = "gsecdump" ascii wide nocase
        $wce = "wce" ascii wide nocase
        $creddump = "creddump" ascii wide nocase
        $dpapi1 = "DPAPI" ascii wide nocase
        $dpapi2 = "CryptUnprotectData" ascii wide nocase
        $chrome1 = "Login Data" ascii wide nocase
        $chrome2 = "Chrome" ascii wide nocase
        $firefox1 = "logins.json" ascii wide nocase
        $firefox2 = "Firefox" ascii wide nocase
    condition:
        any of them
}

rule MALINFO_Exploit_CVE_2021_34527
{
    meta:
        description = "PrintNightmare (CVE-2021-34527) Indicators"
        author = "MALINFO"
        severity = "critical"
        mitre = ["T1190"]
        version = "1"
    strings:
        $cve1 = "CVE-2021-34527" ascii wide nocase
        $cve2 = "PrintNightmare" ascii wide nocase
        $cve3 = "spoolsv.exe" ascii wide nocase
        $cve4 = "RpcRemoteFindFirstPrinterChangeNotificationEx" ascii wide nocase
        $cve5 = "DllName" ascii wide nocase
        $cve6 = "ContainerName" ascii wide nocase
    condition:
        2 of them
}

rule MALINFO_Exploit_Log4Shell
{
    meta:
        description = "Log4Shell (CVE-2021-44228) Indicators"
        author = "MALINFO"
        severity = "critical"
        mitre = ["T1190"]
        version = "1"
    strings:
        $log4j1 = "log4j" ascii wide nocase
        $log4j2 = "JndiLookup" ascii wide nocase
        $log4j3 = "${jndi:" ascii wide nocase
        $log4j4 = "${${lower:" ascii wide nocase
        $log4j5 = "ldap://" ascii wide nocase
        $log4j6 = "rmi://" ascii wide nocase
        $log4j7 = "dns://" ascii wide nocase
    condition:
        2 of them
}

rule MALINFO_Shellcode_Generic
{
    meta:
        description = "Generic Shellcode Patterns"
        author = "MALINFO"
        severity = "high"
        mitre = ["T1055", "T1620"]
        version = "1"
    strings:
        $sc1 = { 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 8B CC }
        $sc2 = { E8 ?? ?? ?? ?? 5B 81 EB ?? ?? ?? ?? 8D 9B ?? ?? ?? ?? }
        $sc3 = { FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51 }
        $sc4 = { 31 C0 50 68 2E 65 78 65 68 63 61 6C 63 54 5B 50 }
        $sc5 = { 6A 00 6A 00 6A 00 6A 00 6A 00 E8 }
    condition:
        any of them
}