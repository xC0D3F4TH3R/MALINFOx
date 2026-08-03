/*
    MALINFO — Test harness rule.

    Detects the EICAR Standard Anti-Virus Test File — a 68-byte string
    every AV/EDR/sandbox vendor recognizes by convention specifically so
    integrators can validate a detection pipeline without using real
    malware. It is not malicious code; it does nothing if executed beyond
    printing text. See https://www.eicar.org/download-anti-malware-testfile/

    Use this to confirm MALINFO's upload -> static analysis -> YARA ->
    risk-score -> report pipeline is wired correctly end-to-end before
    testing against real samples.
*/

rule EICAR_Test_File
{
    meta:
        description = "EICAR standard antivirus test file - used to validate detection pipelines, not malicious"
        severity = "critical"
        is_test_signature = "true"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
