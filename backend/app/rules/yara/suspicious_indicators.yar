/*
    MALINFO — Starter YARA ruleset: generic suspicious indicators.
    These are intentionally broad, low-confidence triage rules meant to
    surface candidates for analyst review, NOT standalone malware verdicts.
    Extend this with CERT-In / MISP / your organization's curated feed.
*/

rule Suspicious_PowerShell_Download_Execute
{
    meta:
        description = "PowerShell download-and-execute pattern common in droppers"
        severity = "high"
        mitre_attack = "T1059.001"
    strings:
        $a1 = "IEX (New-Object Net.WebClient)" nocase
        $a2 = "DownloadString(" nocase
        $a3 = "-EncodedCommand" nocase
        $a4 = "Invoke-Expression" nocase
        $a5 = "Net.WebClient" nocase
        $a6 = "-nop -w hidden" nocase
    condition:
        2 of them
}

rule Suspicious_Reverse_Shell_Strings
{
    meta:
        description = "Common reverse-shell / remote-command execution strings"
        severity = "high"
        mitre_attack = "T1059"
    strings:
        $s1 = "/bin/sh -i" nocase
        $s2 = "cmd.exe /c" nocase
        $s3 = "socket.connect" nocase
        $s4 = "os.dup2" nocase
        $s5 = "nc -e" nocase
        $s6 = "bash -i >&" nocase
    condition:
        any of them
}

rule Suspicious_Credential_Access
{
    meta:
        description = "Strings associated with credential dumping / browser credential theft"
        severity = "high"
        mitre_attack = "T1555,T1003"
    strings:
        $c1 = "sekurlsa" nocase
        $c2 = "lsass.exe" nocase
        $c3 = "Login Data" nocase
        $c4 = "\\Login Data" nocase
        $c5 = "chrome_shortcut_icon" nocase
        $c6 = "SAM_KEY" nocase
        $c7 = "vaultcli.dll" nocase
    condition:
        any of them
}

rule Suspicious_Ransomware_Note_Language
{
    meta:
        description = "Language patterns typical of ransomware notes"
        severity = "critical"
        mitre_attack = "T1486"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "decrypt your files" nocase
        $r3 = "bitcoin wallet" nocase
        $r4 = "pay the ransom" nocase
        $r5 = ".onion" nocase
        $r6 = "do not rename" nocase
        $r7 = "restore your files" nocase
    condition:
        2 of them
}

rule Suspicious_AntiAnalysis_Techniques
{
    meta:
        description = "Anti-debugging / anti-VM / sandbox-evasion indicators"
        severity = "medium"
        mitre_attack = "T1497,T1622"
    strings:
        $v1 = "VMware" nocase
        $v2 = "VBoxService" nocase
        $v3 = "IsDebuggerPresent" nocase
        $v4 = "CheckRemoteDebuggerPresent" nocase
        $v5 = "SbieDll.dll" nocase
        $v6 = "SandboxieDllIsLoaded" nocase
        $v7 = "vmtoolsd.exe" nocase
    condition:
        2 of them
}

rule Suspicious_C2_Framework_Markers
{
    meta:
        description = "String markers associated with common C2 frameworks (Cobalt Strike, Metasploit, Sliver)"
        severity = "critical"
        mitre_attack = "T1071,T1105"
    strings:
        $cs1 = "%c%c%c%c%c%c%c%c.%x" nocase
        $cs2 = "ReflectiveLoader" nocase
        $cs3 = "/submit.php" nocase
        $cs4 = "/gate.php" nocase
        $cs5 = "beacon.dll" nocase
        $cs6 = "metsrv.dll" nocase
        $cs7 = "MSSE-" nocase
    condition:
        any of them
}

rule Suspicious_Persistence_RegistryRun
{
    meta:
        description = "Registry Run-key persistence markers"
        severity = "medium"
        mitre_attack = "T1547.001"
    strings:
        $p1 = "\\CurrentVersion\\Run" nocase
        $p2 = "\\CurrentVersion\\RunOnce" nocase
        $p3 = "schtasks /create" nocase
        $p4 = "reg add" nocase
    condition:
        any of them
}
