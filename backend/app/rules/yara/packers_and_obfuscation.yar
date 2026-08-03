/*
    MALINFO — Packer / obfuscation signature rules.
    Presence of a packer is not inherently malicious (legitimate software
    packs to protect IP), but combined with other signals it raises the
    overall risk score.
*/

rule Packer_UPX
{
    meta:
        description = "UPX packer signature"
        severity = "low"
    strings:
        $u1 = "UPX0"
        $u2 = "UPX1"
        $u3 = "UPX!"
    condition:
        any of them
}

rule Packer_Themida_VMProtect
{
    meta:
        description = "Themida / VMProtect commercial packer/protector"
        severity = "medium"
    strings:
        $t1 = ".themida"
        $t2 = ".vmp0"
        $t3 = ".vmp1"
        $t4 = "VProtect"
    condition:
        any of them
}

rule Obfuscation_Base64_PowerShell_Blob
{
    meta:
        description = "Large base64 blob adjacent to PowerShell invocation - common obfuscated-payload pattern"
        severity = "medium"
    strings:
        $ps = "powershell" nocase
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $ps and $b64
}

rule Obfuscation_Highly_Repeated_XOR_Loop_Strings
{
    meta:
        description = "String markers commonly left by simple XOR-loop shellcode encoders"
        severity = "low"
    strings:
        $x1 = "XOR_KEY" nocase
        $x2 = "decrypt_stub" nocase
        $x3 = "unpack_stub" nocase
    condition:
        any of them
}
