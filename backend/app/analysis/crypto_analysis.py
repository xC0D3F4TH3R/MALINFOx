"""MALINFO — Crypto/Key File Analysis (PEM, DER, PFX, P12, certificates, keys)

Analysis of cryptographic files for weak keys, exposed secrets, and certificate validation.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.crypto_analysis")

# Try to import cryptography
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.x509.oid import ExtensionOID, NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


def analyze_crypto_file(file_path: Path) -> dict:
    """
    Analyze cryptographic file (certificates, keys, PKCS#12, etc.).
    """
    result: dict = {
        "available": True,
        "format": "Cryptographic File",
        "file_type": "",
        "certificates": [],
        "keys": [],
        "pkcs12": {},
        "weak_keys": [],
        "expired_certs": [],
        "self_signed": [],
        "san_list": [],
        "key_usages": [],
        "signature_algorithms": [],
        "public_key_algorithms": [],
        "key_sizes": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        result["entropy"] = round(shannon_entropy(data[:8192]), 3)

        # Detect file type
        if data.startswith(b"-----BEGIN"):
            result["file_type"] = "PEM"
            _analyze_pem(data, result)
        elif data[:2] in (b"\x30\x82", b"\x30\x81", b"\x30\x80"):
            result["file_type"] = "DER"
            _analyze_der(data, result)
        elif file_path.suffix.lower() in (".pfx", ".p12"):
            result["file_type"] = "PKCS#12"
            _analyze_pkcs12(file_path, result)
        elif file_path.suffix.lower() in (".crt", ".cer", ".der", ".pem", ".key", ".pem"):
            # Try both
            if data.startswith(b"-----BEGIN"):
                _analyze_pem(data, result)
            else:
                _analyze_der(data, result)
        else:
            result["errors"].append("Unrecognized crypto file format")

    except Exception as exc:
        logger.debug(f"Crypto analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_pem(data: bytes, result: dict) -> None:
    """Analyze PEM-encoded data (can contain multiple objects)."""
    if not CRYPTOGRAPHY_AVAILABLE:
        result["errors"].append("cryptography library not installed")
        return

    text = data.decode("utf-8", errors="ignore")

    # Split into PEM blocks
    pem_blocks = re.findall(r'-----BEGIN ([A-Z ]+)-----\n(.*?)\n-----END \1-----', text, re.DOTALL)

    for block_type, block_data in pem_blocks:
        block_data = block_data.replace("\n", "").replace("\r", "").strip()

        try:
            import base64
            der_data = base64.b64decode(block_data)

            if "CERTIFICATE" in block_type or "X509" in block_type:
                _parse_certificate(der_data, result)
            elif "PRIVATE KEY" in block_type and "ENCRYPTED" not in block_type:
                _parse_private_key(der_data, result, encrypted=False)
            elif "ENCRYPTED PRIVATE KEY" in block_type or "PRIVATE KEY" in block_type:
                _parse_private_key(der_data, result, encrypted=True)
            elif "PUBLIC KEY" in block_type:
                _parse_public_key(der_data, result)
            elif "CERTIFICATE REQUEST" in block_type or "CSR" in block_type:
                _parse_csr(der_data, result)
            elif "PKCS7" in block_type or "PKCS #7" in block_type:
                _parse_pkcs7(der_data, result)
            elif "PKCS12" in block_type:
                _parse_pkcs12_data(der_data, result)

        except Exception as exc:
            logger.debug(f"Failed to parse PEM block {block_type}: {exc}")
            result["errors"].append(f"Failed to parse {block_type}: {exc}")


def _analyze_der(data: bytes, result: dict) -> None:
    """Analyze DER-encoded data."""
    if not CRYPTOGRAPHY_AVAILABLE:
        result["errors"].append("cryptography library not installed")
        return

    # Try to parse as certificate first
    try:
        cert = x509.load_der_x509_certificate(data)
        _parse_certificate_object(cert, result)
        return
    except Exception:
        pass

    # Try as private key
    try:
        key = serialization.load_der_private_key(data, password=None)
        _parse_private_key_object(key, result, encrypted=False)
        return
    except Exception:
        pass

    # Try as public key
    try:
        key = serialization.load_der_public_key(data)
        _parse_public_key_object(key, result)
        return
    except Exception:
        pass

    result["errors"].append("Could not parse DER data as cert/key")


def _analyze_pkcs12(file_path: Path, result: dict) -> None:
    """Analyze PKCS#12 file."""
    if not CRYPTOGRAPHY_AVAILABLE:
        result["errors"].append("cryptography library not installed")
        return

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # PKCS#12 typically requires password
        # Try empty password first
        try:
            pkcs12 = serialization.load_key_and_certificates_from_pkcs12(data, password=None)
            _parse_pkcs12_object(pkcs12, result)
        except ValueError:
            result["pkcs12"]["password_protected"] = True
            result["suspicious_indicators"].append("PKCS#12 file is password protected")
    except Exception as exc:
        result["errors"].append(f"PKCS#12 analysis failed: {exc}")


def _parse_certificate(der_data: bytes, result: dict) -> None:
    """Parse X.509 certificate from DER."""
    try:
        cert = x509.load_der_x509_certificate(der_data)
        _parse_certificate_object(cert, result)
    except Exception as exc:
        result["errors"].append(f"Certificate parsing failed: {exc}")


def _parse_certificate_object(cert: x509.Certificate, result: dict) -> None:
    """Extract info from certificate object."""
    cert_info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": hex(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat(),
        "version": cert.version.name,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "signature_hash_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
    }

    # Check expiry
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after < now:
        cert_info["expired"] = True
        result["expired_certs"].append(cert_info)

    # Check self-signed
    if cert.subject == cert.issuer:
        cert_info["self_signed"] = True
        result["self_signed"].append(cert_info)
        result["suspicious_indicators"].append("Self-signed certificate detected")

    # Subject Alternative Names
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [name.value for name in san_ext.value]
        cert_info["subject_alternative_names"] = sans
        result["san_list"].extend(sans)
    except x509.ExtensionNotFound:
        pass

    # Key Usage
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        usages = []
        for usage in [
            "digital_signature", "content_commitment", "key_encipherment",
            "data_encipherment", "key_agreement", "key_cert_sign",
            "crl_sign", "encipher_only", "decipher_only"
        ]:
            if getattr(ku_ext.value, usage, False):
                usages.append(usage)
        cert_info["key_usage"] = usages
        result["key_usages"].extend(usages)
    except x509.ExtensionNotFound:
        pass

    # Extended Key Usage
    try:
        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        cert_info["extended_key_usage"] = [oid._name for oid in eku_ext.value]
    except x509.ExtensionNotFound:
        pass

    # Basic Constraints
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        cert_info["is_ca"] = bc_ext.value.ca
        cert_info["path_length"] = bc_ext.value.path_length
    except x509.ExtensionNotFound:
        pass

    # Public key info
    pub_key = cert.public_key()
    cert_info["public_key_algorithm"] = type(pub_key).__name__
    result["public_key_algorithms"].append(type(pub_key).__name__)

    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        cert_info["key_size"] = key_size
        result["key_sizes"].append(key_size)
        if key_size < 2048:
            result["weak_keys"].append(f"RSA key size {key_size} < 2048 bits")
            result["suspicious_indicators"].append(f"Weak RSA key size: {key_size} bits")
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve = pub_key.curve.name
        cert_info["curve"] = curve
        result["key_sizes"].append(curve)
    elif isinstance(pub_key, dsa.DSAPublicKey):
        key_size = pub_key.key_size
        cert_info["key_size"] = key_size
        result["key_sizes"].append(key_size)
        if key_size < 2048:
            result["weak_keys"].append(f"DSA key size {key_size} < 2048 bits")

    result["certificates"].append(cert_info)
    result["signature_algorithms"].append(cert_info["signature_algorithm"])


def _parse_private_key(der_data: bytes, result: dict, encrypted: bool) -> None:
    """Parse private key from DER."""
    try:
        if encrypted:
            # Can't parse without password
            result["keys"].append({"type": "Encrypted Private Key", "encrypted": True})
            result["suspicious_indicators"].append("Encrypted private key found (password required)")
        else:
            key = serialization.load_der_private_key(der_data, password=None)
            _parse_private_key_object(key, result, encrypted=False)
    except Exception as exc:
        result["errors"].append(f"Private key parsing failed: {exc}")


def _parse_private_key_object(key, result: dict, encrypted: bool) -> None:
    """Extract info from private key object."""
    key_info = {
        "type": type(key).__name__,
        "encrypted": encrypted,
    }

    if isinstance(key, rsa.RSAPrivateKey):
        key_size = key.key_size
        key_info["key_size"] = key_size
        result["key_sizes"].append(key_size)
        if key_size < 2048:
            result["weak_keys"].append(f"RSA private key size {key_size} < 2048 bits")
            result["suspicious_indicators"].append(f"Weak RSA private key: {key_size} bits")
        # Check public exponent
        pub_exp = key.public_key().public_numbers().e
        key_info["public_exponent"] = pub_exp
        if pub_exp not in (65537, 3):
            result["suspicious_indicators"].append(f"Unusual RSA public exponent: {pub_exp}")

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        curve = key.curve.name
        key_info["curve"] = curve
        result["key_sizes"].append(curve)

    elif isinstance(key, dsa.DSAPrivateKey):
        key_size = key.key_size
        key_info["key_size"] = key_size
        result["key_sizes"].append(key_size)
        if key_size < 2048:
            result["weak_keys"].append(f"DSA private key size {key_size} < 2048 bits")

    elif isinstance(key, ed25519.Ed25519PrivateKey):
        key_info["algorithm"] = "Ed25519"

    elif isinstance(key, ed448.Ed448PrivateKey):
        key_info["algorithm"] = "Ed448"

    result["keys"].append(key_info)


def _parse_public_key(der_data: bytes, result: dict) -> None:
    """Parse public key from DER."""
    try:
        key = serialization.load_der_public_key(der_data)
        _parse_public_key_object(key, result)
    except Exception as exc:
        result["errors"].append(f"Public key parsing failed: {exc}")


def _parse_public_key_object(key, result: dict) -> None:
    """Extract info from public key object."""
    key_info = {
        "type": type(key).__name__,
    }

    if isinstance(key, rsa.RSAPublicKey):
        key_size = key.key_size
        key_info["key_size"] = key_size
        result["key_sizes"].append(key_size)
        if key_size < 2048:
            result["weak_keys"].append(f"RSA public key size {key_size} < 2048 bits")
        pub_exp = key.public_numbers().e
        key_info["public_exponent"] = pub_exp

    elif isinstance(key, ec.EllipticCurvePublicKey):
        curve = key.curve.name
        key_info["curve"] = curve
        result["key_sizes"].append(curve)

    elif isinstance(key, dsa.DSAPublicKey):
        key_size = key.key_size
        key_info["key_size"] = key_size
        result["key_sizes"].append(key_size)

    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_info["algorithm"] = "Ed25519"

    elif isinstance(key, ed448.Ed448PublicKey):
        key_info["algorithm"] = "Ed448"

    result["keys"].append(key_info)


def _parse_csr(der_data: bytes, result: dict) -> None:
    """Parse Certificate Signing Request."""
    try:
        csr = x509.load_der_x509_csr(der_data)
        result["certificates"].append({
            "type": "CSR",
            "subject": csr.subject.rfc4514_string(),
            "signature_algorithm": csr.signature_algorithm_oid._name,
        })
    except Exception as exc:
        result["errors"].append(f"CSR parsing failed: {exc}")


def _parse_pkcs7(der_data: bytes, result: dict) -> None:
    """Parse PKCS#7."""
    try:
        # PKCS#7 parsing would go here
        result["certificates"].append({"type": "PKCS#7", "note": "PKCS#7 parsing not fully implemented"})
    except Exception as exc:
        result["errors"].append(f"PKCS#7 parsing failed: {exc}")


def _parse_pkcs12_data(der_data: bytes, result: dict) -> None:
    """Parse PKCS#12 from DER."""
    try:
        pkcs12 = serialization.load_key_and_certificates_from_pkcs12(der_data, password=None)
        _parse_pkcs12_object(pkcs12, result)
    except Exception as exc:
        result["errors"].append(f"PKCS#12 parsing failed: {exc}")


def _parse_pkcs12_object(pkcs12, result: dict) -> None:
    """Extract info from PKCS#12 object."""
    private_key, certificate, additional_certs = pkcs12

    if private_key:
        _parse_private_key_object(private_key, result, encrypted=False)

    if certificate:
        _parse_certificate_object(certificate, result)

    for cert in additional_certs:
        _parse_certificate_object(cert, result)

    result["pkcs12"]["parsed"] = True
    result["pkcs12"]["password_protected"] = False


def analyze_crypto(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_crypto_file(file_path)