/*
    MALINFO — Ransomware-family indicator rules (generic, family-agnostic).
    Extend per-family (LockBit, BlackCat/ALPHV, Conti-derived, etc.) using
    curated IOC feeds from CERT-In / MHA-I4C advisories as they're published.
*/

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Volume Shadow Copy deletion - near-universal ransomware pre-encryption step"
        severity = "critical"
        mitre_attack = "T1490"
    strings:
        $s1 = "vssadmin delete shadows" nocase
        $s2 = "wmic shadowcopy delete" nocase
        $s3 = "bcdedit /set" nocase
        $s4 = "wbadmin delete catalog" nocase
    condition:
        any of them
}

rule Ransomware_File_Extension_Rename_Pattern
{
    meta:
        description = "Common ransomware-appended file extensions found in strings"
        severity = "high"
    strings:
        $e1 = ".locked" nocase
        $e2 = ".encrypted" nocase
        $e3 = ".crypt" nocase
        $e4 = ".lockbit" nocase
        $e5 = ".ryuk" nocase
        $e6 = ".conti" nocase
    condition:
        any of them
}

rule Ransomware_Crypto_API_Cluster
{
    meta:
        description = "Cluster of Windows CryptoAPI calls typical of file-encrypting ransomware"
        severity = "high"
    strings:
        $c1 = "CryptEncrypt" nocase
        $c2 = "CryptGenKey" nocase
        $c3 = "CryptAcquireContext" nocase
        $c4 = "CryptDeriveKey" nocase
    condition:
        3 of them
}
