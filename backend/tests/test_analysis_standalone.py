"""
MALINFO — standalone smoke test.

Deliberately depends on NOTHING outside the Python standard library, so it
runs even before you `pip install -r requirements.txt`. It exercises the
real hashing/filetype/entropy/IOC-extraction/APK/risk-scoring logic
against synthetic test files and fails loudly with a plain assertion if
anything is broken.

This is a first checkpoint, not a replacement for testing the full app —
run it first to confirm the core logic is sound, then move on to running
the actual server (see README.md "Quick start").

Usage:
    cd backend
    python3 tests/test_analysis_standalone.py
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

# Make `app.*` importable without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis import (
    apk_analysis,
    filetype,
    hashing,
    ioc_extraction,
    risk_scoring,
    strings_entropy,
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
results: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((name, condition, detail))
    print(f"[{PASS if condition else FAIL}] {name}" + (f" — {detail}" if detail and not condition else ""))


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="malinfo_smoketest_"))
    try:
        run_hashing_test(tmp)
        run_filetype_test(tmp)
        run_entropy_test(tmp)
        run_ioc_extraction_test()
        run_apk_test(tmp)
        run_risk_scoring_test()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print()
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


def run_hashing_test(tmp: Path) -> None:
    print("\n--- Hashing ---")
    f = tmp / "hash_test.txt"
    f.write_bytes(b"MALINFO test content")
    h = hashing.compute_hashes(f)
    # Known-good hashes for this exact byte string, computed independently.
    import hashlib
    expected_sha256 = hashlib.sha256(b"MALINFO test content").hexdigest()
    check("SHA-256 matches independently computed hash", h["sha256"] == expected_sha256)
    check("MD5 present and correct length", len(h["md5"]) == 32)
    check("SHA-1 present and correct length", len(h["sha1"]) == 40)


def run_filetype_test(tmp: Path) -> None:
    print("\n--- File type identification ---")
    pe_file = tmp / "fake.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    result = filetype.identify_file(pe_file)
    check("Detects PE signature -> windows", result["target_os"] == "windows", result["target_os"])

    elf_file = tmp / "fake.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    result = filetype.identify_file(elf_file)
    check("Detects ELF signature -> linux", result["target_os"] == "linux", result["target_os"])

    text_file = tmp / "plain.txt"
    text_file.write_text("just a plain text file, nothing interesting here")
    result = filetype.identify_file(text_file)
    check("Plain text does not falsely flag an OS target", result["target_os"] == "unknown", result["target_os"])


def run_entropy_test(tmp: Path) -> None:
    print("\n--- Entropy & string extraction ---")
    import os
    random_file = tmp / "random.bin"
    random_file.write_bytes(os.urandom(4096))
    high_entropy = strings_entropy.file_entropy(random_file)
    check("Random bytes score high entropy (>7.0)", high_entropy > 7.0, str(high_entropy))

    repetitive_file = tmp / "repetitive.bin"
    repetitive_file.write_bytes(b"AAAA" * 1024)
    low_entropy = strings_entropy.file_entropy(repetitive_file)
    check("Repetitive bytes score low entropy (<1.0)", low_entropy < 1.0, str(low_entropy))

    strings_file = tmp / "strings_test.bin"
    strings_file.write_bytes(b"\x00\x01garbage\x02\x03HELLO_WORLD_STRING\x04\x05another_visible_string\x06")
    extracted = strings_entropy.extract_strings(strings_file, min_length=5)
    found = " ".join(extracted["sample"])
    check("Extracts embedded ASCII strings", "HELLO_WORLD_STRING" in found and "another_visible_string" in found, found)


def run_ioc_extraction_test() -> None:
    print("\n--- IOC extraction ---")
    test_strings = [
        "connecting to http://185.220.101.42/gate.php for checkin",
        "beacon interval set, contacting c2 panel now",
        "powershell -nop -w hidden -EncodedCommand aGVsbG8=",
        "resolved malicious-domain-example.xyz successfully",
        "contact admin@legituniversity.edu for support",
        "local loopback traffic to 127.0.0.1 ignored",
    ]
    iocs = ioc_extraction.extract_iocs_from_strings(test_strings)
    types_found = {i["ioc_type"] for i in iocs}

    check("Extracts URL indicator", "url" in types_found)
    check("Extracts IP indicator", "ip" in types_found)
    check("Extracts domain indicator", "domain" in types_found)
    check("Extracts email indicator", "email" in types_found)

    ips = [i["value"] for i in iocs if i["ioc_type"] == "ip"]
    check("Filters out private/loopback IPs (127.0.0.1 excluded)", "127.0.0.1" not in ips, str(ips))

    c2_candidates = ioc_extraction.flag_likely_c2(iocs)
    check("Promotes gate.php/c2-context IOC to c2_candidate", len(c2_candidates) > 0, str(len(c2_candidates)))


def run_apk_test(tmp: Path) -> None:
    print("\n--- APK analysis ---")
    apk_path = tmp / "test.apk"
    manifest_strings = [
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
        "com.example.testapp",
        "MainActivity",
    ]
    # Simulate the UTF-16LE string pool the real parser scans for.
    fake_manifest = b"".join(s.encode("utf-16le") + b"\x00\x00" for s in manifest_strings)

    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("AndroidManifest.xml", fake_manifest)
        z.writestr("classes.dex", b"dex\n" + b"\x00" * 50)

    result = apk_analysis.analyze_apk(apk_path)
    check("APK parser runs without error", result.get("available") is True, str(result.get("error")))
    check("Detects classes.dex presence", result.get("has_dex") is True)
    check(
        "Flags SEND_SMS as high-risk permission",
        "android.permission.SEND_SMS" in result.get("high_risk_permissions", []),
        str(result.get("high_risk_permissions")),
    )
    check(
        "Does not flag INTERNET as high-risk (it isn't in the high-risk set)",
        "android.permission.INTERNET" not in result.get("high_risk_permissions", []),
    )


def run_risk_scoring_test() -> None:
    print("\n--- Risk scoring ---")
    clean_report = {
        "yara": {"matches": []},
        "entropy": 4.2,
        "format_specific": {},
        "iocs": [],
    }
    clean_result = risk_scoring.score_static_report(clean_report)
    check("Clean report scores low risk (<10)", clean_result["risk_score"] < 10, str(clean_result))
    check("Clean report verdict is 'clean'", clean_result["verdict"] == "clean", clean_result["verdict"])

    malicious_report = {
        "yara": {"matches": [
            {"rule": "Ransomware_Shadow_Copy_Deletion", "meta": {"severity": "critical"}},
            {"rule": "Suspicious_C2_Framework_Markers", "meta": {"severity": "critical"}},
        ]},
        "entropy": 7.8,
        "format_specific": {
            "pe": {
                "available": True,
                "suspicious_api_calls": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
                "packer_indicators": ["Section 'UPX0' — known packer"],
                "has_authenticode_signature": False,
                "has_overlay_data": True,
            }
        },
        "iocs": [
            {"ioc_type": "c2_candidate", "value": "185.220.101.42", "confidence": 0.9},
        ],
    }
    malicious_result = risk_scoring.score_static_report(malicious_report)
    check("Heavily-flagged report scores high risk (>=60)", malicious_result["risk_score"] >= 60, str(malicious_result["risk_score"]))
    check("Heavily-flagged report verdict is 'malicious'", malicious_result["verdict"] == "malicious", malicious_result["verdict"])
    check("Risk reasons are populated and human-readable", len(malicious_result["reasons"]) >= 4, str(len(malicious_result["reasons"])))


if __name__ == "__main__":
    main()
