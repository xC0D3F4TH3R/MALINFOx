"""
MALINFO — Unit tests for analysis modules.
"""
import hashlib
import os
import zipfile

import pytest

from app.analysis import (
    apk_analysis,
    filetype,
    hashing,
    ioc_extraction,
    risk_scoring,
    strings_entropy,
)


class TestHashing:
    """Tests for hashing module."""

    def test_compute_hashes_basic(self, temp_dir):
        """Test basic hash computation."""
        test_file = temp_dir / "test.txt"
        test_content = b"MALINFO test content"
        test_file.write_bytes(test_content)

        hashes = hashing.compute_hashes(test_file)

        expected_sha256 = hashlib.sha256(test_content).hexdigest()
        assert hashes["sha256"] == expected_sha256
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40

    def test_compute_hashes_empty_file(self, temp_dir):
        """Test hash computation for empty file."""
        test_file = temp_dir / "empty.txt"
        test_file.write_bytes(b"")

        hashes = hashing.compute_hashes(test_file)

        assert hashes["sha256"] == hashlib.sha256(b"").hexdigest()
        assert hashes["md5"] == hashlib.md5(b"").hexdigest()
        assert hashes["sha1"] == hashlib.sha1(b"").hexdigest()


class TestFileType:
    """Tests for file type identification."""

    def test_identify_pe_file(self, sample_pe_file):
        """Test PE file identification."""
        result = filetype.identify_file(sample_pe_file)
        assert result["target_os"] == "windows"
        assert "PE" in result["file_type"] or "executable" in result["file_type"].lower()

    def test_identify_elf_file(self, sample_elf_file):
        """Test ELF file identification."""
        result = filetype.identify_file(sample_elf_file)
        assert result["target_os"] == "linux"
        assert "ELF" in result["file_type"]

    def test_identify_text_file(self, sample_text_file):
        """Test plain text file identification."""
        result = filetype.identify_file(sample_text_file)
        assert result["target_os"] == "unknown"

    def test_identify_apk_file(self, sample_apk_file):
        """Test APK file identification."""
        result = filetype.identify_file(sample_apk_file)
        assert result["target_os"] == "android"
        assert "APK" in result["file_type"]


class TestEntropy:
    """Tests for entropy and string extraction."""

    def test_high_entropy_random(self, temp_dir):
        """Test that random bytes have high entropy."""
        random_file = temp_dir / "random.bin"
        random_file.write_bytes(os.urandom(4096))

        entropy = strings_entropy.file_entropy(random_file)
        assert entropy > 7.0

    def test_low_entropy_repetitive(self, temp_dir):
        """Test that repetitive bytes have low entropy."""
        repetitive_file = temp_dir / "repetitive.bin"
        repetitive_file.write_bytes(b"AAAA" * 1024)

        entropy = strings_entropy.file_entropy(repetitive_file)
        assert entropy < 1.0

    def test_extract_strings(self, temp_dir):
        """Test string extraction from binary."""
        strings_file = temp_dir / "strings_test.bin"
        strings_file.write_bytes(b"\x00\x01garbage\x02\x03HELLO_WORLD_STRING\x04\x05another_visible_string\x06")

        extracted = strings_entropy.extract_strings(strings_file, min_length=5)
        found = " ".join(extracted["sample"])

        assert "HELLO_WORLD_STRING" in found
        assert "another_visible_string" in found


class TestIOCExtraction:
    """Tests for IOC extraction."""

    def test_extract_url_ioc(self):
        """Test URL IOC extraction."""
        strings = ["connecting to http://185.220.101.42/gate.php for checkin"]
        iocs = ioc_extraction.extract_iocs_from_strings(strings)

        url_iocs = [i for i in iocs if i["ioc_type"] == "url"]
        assert len(url_iocs) >= 1
        assert "http://185.220.101.42/gate.php" in [i["value"] for i in url_iocs]

    def test_extract_ip_ioc(self):
        """Test IP IOC extraction."""
        strings = ["connecting to 185.220.101.42 for checkin"]
        iocs = ioc_extraction.extract_iocs_from_strings(strings)

        ip_iocs = [i for i in iocs if i["ioc_type"] == "ip"]
        assert len(ip_iocs) >= 1
        assert "185.220.101.42" in [i["value"] for i in ip_iocs]

    def test_filter_private_ips(self):
        """Test that private/loopback IPs are filtered."""
        strings = ["local loopback traffic to 127.0.0.1 ignored", "internal 192.168.1.1"]
        iocs = ioc_extraction.extract_iocs_from_strings(strings)

        ip_iocs = [i for i in iocs if i["ioc_type"] == "ip"]
        ip_values = [i["value"] for i in ip_iocs]
        assert "127.0.0.1" not in ip_values
        assert "192.168.1.1" not in ip_values

    def test_extract_domain_ioc(self):
        """Test domain IOC extraction."""
        strings = ["resolved malicious-domain-example.xyz successfully"]
        iocs = ioc_extraction.extract_iocs_from_strings(strings)

        domain_iocs = [i for i in iocs if i["ioc_type"] == "domain"]
        assert len(domain_iocs) >= 1

    def test_extract_email_ioc(self):
        """Test email IOC extraction."""
        strings = ["contact admin@legituniversity.edu for support"]
        iocs = ioc_extraction.extract_iocs_from_strings(strings)

        email_iocs = [i for i in iocs if i["ioc_type"] == "email"]
        assert len(email_iocs) >= 1
        assert "admin@legituniversity.edu" in [i["value"] for i in email_iocs]

    def test_flag_likely_c2(self):
        """Test C2 flagging heuristic."""
        strings = [
            "connecting to http://185.220.101.42/gate.php for checkin",
            "beacon interval set, contacting c2 panel now",
        ]
        iocs = ioc_extraction.extract_iocs_from_strings(strings)
        c2_candidates = ioc_extraction.flag_likely_c2(iocs)

        assert len(c2_candidates) > 0


class TestAPKAnalysis:
    """Tests for APK analysis."""

    def test_analyze_apk_basic(self, sample_apk_file):
        """Test basic APK analysis."""
        result = apk_analysis.analyze_apk(sample_apk_file)

        assert result.get("available") is True
        assert result.get("has_dex") is True

    def test_detect_high_risk_permissions(self, sample_apk_file):
        """Test detection of high-risk permissions."""
        result = apk_analysis.analyze_apk(sample_apk_file)

        high_risk = result.get("high_risk_permissions", [])
        assert "android.permission.SEND_SMS" in high_risk
        assert "android.permission.READ_CONTACTS" in high_risk

    def test_internet_not_high_risk(self, sample_apk_file):
        """Test that INTERNET permission is not flagged as high-risk."""
        result = apk_analysis.analyze_apk(sample_apk_file)

        high_risk = result.get("high_risk_permissions", [])
        assert "android.permission.INTERNET" not in high_risk


class TestRiskScoring:
    """Tests for risk scoring."""

    def test_clean_report_scores_low(self):
        """Test that a clean report scores low risk."""
        clean_report = {
            "yara": {"matches": []},
            "entropy": 4.2,
            "format_specific": {},
            "iocs": [],
        }

        result = risk_scoring.score_static_report(clean_report)

        assert result["risk_score"] < 10
        assert result["verdict"] == "clean"

    def test_malicious_report_scores_high(self):
        """Test that a heavily-flagged report scores high risk."""
        malicious_report = {
            "yara": {
                "matches": [
                    {"rule": "Ransomware_Shadow_Copy_Deletion", "meta": {"severity": "critical"}},
                    {"rule": "Suspicious_C2_Framework_Markers", "meta": {"severity": "critical"}},
                ]
            },
            "entropy": 7.8,
            "format_specific": {
                "pe": {
                    "available": True,
                    "suspicious_api_calls": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
                    "packer_indicators": ["Section 'UPX0' - known packer"],
                    "has_authenticode_signature": False,
                    "has_overlay_data": True,
                }
            },
            "iocs": [
                {"ioc_type": "c2_candidate", "value": "185.220.101.42", "confidence": 0.9},
            ],
        }

        result = risk_scoring.score_static_report(malicious_report)

        assert result["risk_score"] >= 60
        assert result["verdict"] == "malicious"
        assert len(result["reasons"]) >= 4