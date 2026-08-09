"""
MALINFO — Cryptographic Algorithm & Key Detection.

Detection of cryptographic constants, algorithms, and hardcoded keys in binaries.
Includes: AES, DES/3DES, RC4, ChaCha20, Salsa20, RSA, ECC, hash functions,
custom algorithms, XOR loops, key extraction from .data/.rdata sections.
"""
from __future__ import annotations

import logging
import re
import struct
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.crypto_detector")

# ──────────────────────────────────────────────────────────────────────────────
# Cryptographic Constant Signatures
# ──────────────────────────────────────────────────────────────────────────────

# AES S-Box (forward)
_AES_SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
])

# AES Inverse S-Box
_AES_INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
])

# DES S-Boxes (8 boxes, 64 entries each)
_DES_SBOXES = [
    # S1
    bytes([0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
           0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07,
           0x00, 0x0F, 0x07, 0x04, 0x0E, 0x02, 0x0D, 0x01,
           0x0A, 0x06, 0x0C, 0x0B, 0x09, 0x05, 0x03, 0x08,
           0x04, 0x01, 0x0E, 0x08, 0x0D, 0x06, 0x02, 0x0B,
           0x0F, 0x0C, 0x09, 0x07, 0x03, 0x0A, 0x05, 0x00,
           0x0F, 0x0C, 0x08, 0x02, 0x04, 0x09, 0x01, 0x07,
           0x05, 0x0B, 0x03, 0x0E, 0x0A, 0x00, 0x06, 0x0D]),
    # ... (other S-boxes would be here)
]

# RC4 KSA/PRGA pattern constants
_RC4_KSA_PATTERN = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])

# ChaCha20 constants (sigma)
_CHACHA20_SIGMA = b"expand 32-byte k"
_CHACHA20_TAU = b"expand 16-byte k"

# Salsa20 constants
_SALSA20_SIGMA = b"expand 32-byte k"
_SALSA20_TAU = b"expand 16-byte k"

# MD5 Initialization Vector
_MD5_IV = bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
                  0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76])

# SHA-1 Initialization Vector
_SHA1_IV = bytes([0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
                   0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76,
                   0xC3, 0xD2, 0xE1, 0xF0])

# SHA-256 Initialization Vector (first 8 32-bit words)
_SHA256_IV = bytes([
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
])

# SHA-256 Round Constants (first few)
_SHA256_K = bytes([
    0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
    0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
    0x39, 0x56, 0xc2, 0x5b, 0x59, 0xf1, 0x11, 0x41,
    0x92, 0x3f, 0x82, 0xa4, 0xab, 0x1c, 0x5e, 0xd5,
])

# RSA Common Public Exponents
_RSA_EXPONENTS = [0x03, 0x10001, 0x010001]  # 3, 65537, 65537

# Common ECC Curve Parameters (compressed)
_ECC_CURVES = {
    "secp256r1": "prime256v1",
    "secp384r1": "secp384r1",
    "secp521r1": "secp521r1",
    "secp256k1": "secp256k1",
    "Curve25519": "X25519",
    "Curve448": "X448",
}

# TEA/XTEA/XXTEA Constants
_TEA_DELTA = 0x9E3779B9
_XTEA_DELTA = 0x9E3779B9

# ──────────────────────────────────────────────────────────────────────────────

_CRYPTO_ALGORITHMS = [
    ("AES_SBOX", _AES_SBOX[:16], "AES (Rijndael) S-Box"),
    ("AES_INV_SBOX", _AES_INV_SBOX[:16], "AES Inverse S-Box"),
    ("AES_T_TABLE", b"\x63\x7c\x77\x7b", "AES T-Table (partial)"),
    ("DES_SBOX1", _DES_SBOXES[0][:16], "DES S-Box 1"),
    ("RC4_KSA", _RC4_KSA_PATTERN, "RC4 KSA Initialization"),
    ("CHACHA20_SIGMA", _CHACHA20_SIGMA, "ChaCha20 Sigma Constant"),
    ("CHACHA20_TAU", _CHACHA20_TAU, "ChaCha20 Tau Constant"),
    ("SALSA20_SIGMA", _SALSA20_SIGMA, "Salsa20 Sigma Constant"),
    ("SALSA20_TAU", _SALSA20_TAU, "Salsa20 Tau Constant"),
    ("MD5_IV", _MD5_IV, "MD5 Initialization Vector"),
    ("SHA1_IV", _SHA1_IV[:16], "SHA-1 Initialization Vector"),
    ("SHA256_IV", _SHA256_IV[:16], "SHA-256 Initialization Vector"),
    ("SHA256_K", _SHA256_K[:16], "SHA-256 Round Constants"),
    ("TEA_DELTA", struct.pack("<I", _TEA_DELTA), "TEA/XTEA Delta Constant"),
    ("XTEA_DELTA", struct.pack("<I", _XTEA_DELTA), "XTEA Delta Constant"),
    ("RSA_EXP_3", struct.pack("<I", 3), "RSA Public Exponent 3"),
    ("RSA_EXP_65537", struct.pack("<I", 65537), "RSA Public Exponent 65537"),
    ("RSA_EXP_17", struct.pack("<I", 17), "RSA Public Exponent 17"),
    ("BLOWFISH_PI", b"\x24\x3f\x6a\x88\x85\xa3\x08\xd3", "Blowfish P-array start (pi)"),
    ("TWOFISH_RS", b"\x01\xa4\x02\xa8\x05\xb0\x0b\xb8", "Twofish RS Matrix"),
    ("CAMELLIA_SIGMA", b"\xa0\x9e\x66\x7f\x3b\xcc\x90\x8b", "Camellia Sigma Constant"),
    ("SM4_SBOX", b"\xd6\x90\xe8\xfe\xcc\xe1\x3d\xb7", "SM4 S-Box (partial)"),
]

# ──────────────────────────────────────────────────────────────────────────────

def detect_crypto(file_path: Path) -> dict:
    """
    Detect cryptographic algorithms, constants, and potential keys in a file.
    """
    result: dict = {
        "available": True,
        "algorithms_detected": [],
        "constants_found": [],
        "potential_keys": [],
        "entropy_analysis": {},
        "xor_loops": [],
        "custom_crypto": [],
        "certificates": [],
        "asymmetric_params": [],
    }

    try:
        data = file_path.read_bytes()
        result["entropy_analysis"] = _analyze_entropy_per_section(data)
        
        # Scan for known crypto constants
        result["constants_found"] = _scan_crypto_constants(data)
        
        # Detect algorithm implementations
        result["algorithms_detected"] = _detect_algorithms(data, result["constants_found"])
        
        # Look for potential hardcoded keys
        result["potential_keys"] = _find_potential_keys(data)
        
        # Detect XOR loops
        result["xor_loops"] = _detect_xor_loops(data)
        
        # Detect certificates/keys in DER/PEM
        result["certificates"] = _find_certificates(data)
        
        # Asymmetric crypto parameters
        result["asymmetric_params"] = _find_asymmetric_params(data)
        
        # Custom/proprietary crypto
        result["custom_crypto"] = _detect_custom_crypto(data)
        
    except Exception as exc:
        logger.exception("Crypto detection failed")
        return {"error": f"Failed to detect crypto: {exc}", "available": False}

    return result


def _scan_crypto_constants(data: bytes) -> list[dict]:
    """Scan for known cryptographic constant signatures."""
    found = []
    for name, signature, description in _CRYPTO_ALGORITHMS:
        positions = []
        start = 0
        while True:
            pos = data.find(signature, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
            if len(positions) > 10:  # Limit matches per constant
                break
        
        if positions:
            found.append({
                "algorithm": name,
                "description": description,
                "signature": signature.hex(),
                "positions": positions,
                "count": len(positions),
            })
    return found


def _detect_algorithms(data: bytes, constants: list[dict]) -> list[dict]:
    """Determine which algorithms are likely implemented based on constants found."""
    algorithms = []
    const_names = {c["algorithm"] for c in constants}
    
    # AES detection
    if "AES_SBOX" in const_names or "AES_INV_SBOX" in const_names or "AES_T_TABLE" in const_names:
        algorithms.append({
            "algorithm": "AES",
            "confidence": "high",
            "evidence": [c for c in constants if "AES" in c["algorithm"]],
            "modes": _detect_aes_modes(data),
        })
    
    # DES/3DES
    if "DES_SBOX1" in const_names:
        algorithms.append({
            "algorithm": "DES/3DES",
            "confidence": "medium",
            "evidence": [c for c in constants if "DES" in c["algorithm"]],
        })
    
    # RC4
    if "RC4_KSA" in const_names:
        algorithms.append({
            "algorithm": "RC4",
            "confidence": "high",
            "evidence": [c for c in constants if "RC4" in c["algorithm"]],
            "note": "Check for KSA/PRGA implementation",
        })
    
    # ChaCha20
    if "CHACHA20_SIGMA" in const_names or "CHACHA20_TAU" in const_names:
        algorithms.append({
            "algorithm": "ChaCha20",
            "confidence": "high",
            "evidence": [c for c in constants if "CHACHA20" in c["algorithm"]],
        })
    
    # Salsa20
    if "SALSA20_SIGMA" in const_names or "SALSA20_TAU" in const_names:
        algorithms.append({
            "algorithm": "Salsa20",
            "confidence": "high",
            "evidence": [c for c in constants if "SALSA20" in c["algorithm"]],
        })
    
    # Hash functions
    hash_algos = []
    if "MD5_IV" in const_names:
        hash_algos.append("MD5")
    if "SHA1_IV" in const_names:
        hash_algos.append("SHA-1")
    if "SHA256_IV" in const_names or "SHA256_K" in const_names:
        hash_algos.append("SHA-256")
    
    if hash_algos:
        algorithms.append({
            "algorithm": "Hash Functions",
            "confidence": "high",
            "algorithms": hash_algos,
            "evidence": [c for c in constants if any(h in c["algorithm"] for h in ["MD5", "SHA1", "SHA256"])],
        })
    
    # TEA/XTEA/XXTEA
    if "TEA_DELTA" in const_names or "XTEA_DELTA" in const_names:
        algorithms.append({
            "algorithm": "TEA/XTEA/XXTEA",
            "confidence": "medium",
            "evidence": [c for c in constants if "TEA" in c["algorithm"] or "XTEA" in c["algorithm"]],
        })
    
    # RSA
    if any(e in const_names for e in ["RSA_EXP_3", "RSA_EXP_65537", "RSA_EXP_17"]):
        algorithms.append({
            "algorithm": "RSA",
            "confidence": "medium",
            "evidence": [c for c in constants if "RSA" in c["algorithm"]],
            "note": "Public exponent found; check for modulus/private key",
        })
    
    # Blowfish
    if "BLOWFISH_PI" in const_names:
        algorithms.append({
            "algorithm": "Blowfish",
            "confidence": "medium",
            "evidence": [c for c in constants if "BLOWFISH" in c["algorithm"]],
        })
    
    # Twofish
    if "TWOFISH_RS" in const_names:
        algorithms.append({
            "algorithm": "Twofish",
            "confidence": "medium",
            "evidence": [c for c in constants if "TWOFISH" in c["algorithm"]],
        })
    
    # Camellia
    if "CAMELLIA_SIGMA" in const_names:
        algorithms.append({
            "algorithm": "Camellia",
            "confidence": "medium",
            "evidence": [c for c in constants if "CAMELLIA" in c["algorithm"]],
        })
    
    # SM4
    if "SM4_SBOX" in const_names:
        algorithms.append({
            "algorithm": "SM4",
            "confidence": "medium",
            "evidence": [c for c in constants if "SM4" in c["algorithm"]],
        })
    
    return algorithms


def _detect_aes_modes(data: bytes) -> list[str]:
    """Detect AES modes of operation from code patterns."""
    modes = []
    text = data.decode("utf-8", errors="ignore").lower()
    
    mode_patterns = {
        "ECB": ["ecb", "electronic codebook"],
        "CBC": ["cbc", "cipher block chaining"],
        "CTR": ["ctr", "counter"],
        "GCM": ["gcm", "galois/counter"],
        "CCM": ["ccm", "counter with cbc-mac"],
        "CFB": ["cfb", "cipher feedback"],
        "OFB": ["ofb", "output feedback"],
        "XTS": ["xts", "xor-encrypt-xor"],
        "OCB": ["ocb", "offset codebook"],
        "EAX": ["eax"],
        "OCB": ["ocb"],
    }
    
    for mode, patterns in mode_patterns.items():
        if any(p in text for p in patterns):
            modes.append(mode)
    
    return modes


def _find_potential_keys(data: bytes) -> list[dict]:
    """Find potential hardcoded cryptographic keys."""
    keys = []
    
    # Look for high-entropy byte sequences of key lengths
    key_lengths = {
        16: "AES-128 / ChaCha20",
        24: "AES-192",
        32: "AES-256 / ChaCha20 / Salsa20",
        64: "RSA-512 (modulus) / 3DES",
        128: "RSA-1024",
        256: "RSA-2048",
        512: "RSA-4096",
    }
    
    # Scan .data/.rdata-like regions (high entropy, aligned)
    for length, algo in key_lengths.items():
        if len(data) < length:
            continue
        
        # Sliding window with step
        for i in range(0, len(data) - length, max(1, length // 4)):
            chunk = data[i:i+length]
            entropy = shannon_entropy(chunk)
            
            # High entropy suggests random key material
            if entropy > 7.0:
                # Additional checks: not all same byte, not repeating pattern
                if len(set(chunk)) > length * 0.5:  # At least 50% unique bytes
                    keys.append({
                        "offset": i,
                        "length": length,
                        "entropy": round(entropy, 3),
                        "algorithm": algo,
                        "hex": chunk[:32].hex() + ("..." if length > 32 else ""),
                        "confidence": "medium" if entropy > 7.5 else "low",
                    })
    
    # Look for key-like strings (base64, hex)
    text = data.decode("utf-8", errors="ignore")
    
    # Base64 encoded keys
    b64_keys = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text)
    for b64 in b64_keys[:20]:  # Limit
        try:
            decoded = bytes.fromhex(b64) if len(b64) % 2 == 0 else None
            if not decoded:
                import base64
                decoded = base64.b64decode(b64)
            if 16 <= len(decoded) <= 512:
                keys.append({
                    "type": "base64_encoded",
                    "offset": text.find(b64),
                    "length": len(decoded),
                    "algorithm": _guess_algo_from_keylen(len(decoded)),
                    "entropy": round(shannon_entropy(decoded), 3),
                    "confidence": "medium",
                })
        except Exception:
            pass
    
    # Hex encoded keys
    hex_keys = re.findall(r"[0-9a-fA-F]{32,}", text)
    for hex_key in hex_keys[:20]:
        try:
            decoded = bytes.fromhex(hex_key)
            if 16 <= len(decoded) <= 512:
                keys.append({
                    "type": "hex_encoded",
                    "offset": text.find(hex_key),
                    "length": len(decoded),
                    "algorithm": _guess_algo_from_keylen(len(decoded)),
                    "entropy": round(shannon_entropy(decoded), 3),
                    "confidence": "medium",
                })
        except Exception:
            pass
    
    return keys


def _guess_algo_from_keylen(keylen: int) -> str:
    if keylen == 16: return "AES-128 / ChaCha20"
    if keylen == 24: return "AES-192"
    if keylen == 32: return "AES-256 / ChaCha20 / Salsa20"
    if keylen == 64: return "RSA-512 / 3DES"
    if keylen in (128, 129): return "RSA-1024"
    if keylen in (256, 257): return "RSA-2048"
    if keylen in (512, 513): return "RSA-4096"
    return "Unknown"


def _detect_xor_loops(data: bytes) -> list[dict]:
    """Detect XOR encryption/decryption loops."""
    xor_loops = []
    text = data.decode("utf-8", errors="ignore").lower()
    
    # Common XOR patterns in assembly/high-level code
    patterns = [
        (r"xor\s+\[.*\]", "XOR memory operand"),
        (r"xor\s+(al|ah|ax|eax|rax),", "XOR register"),
        (r"\^=", "XOR assignment (C/C++)"),
        (r"xor\s+[a-zA-Z_][a-zA-Z0-9_]*\s*,", "XOR variable"),
        (r"for.*xor", "XOR in loop"),
        (r"while.*xor", "XOR in while loop"),
        (r"rolling\s*xor", "Rolling XOR"),
        (r"xor\s+key", "XOR key variable"),
    ]
    
    for pattern, desc in patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE))
        if matches:
            for m in matches[:5]:
                xor_loops.append({
                    "pattern": desc,
                    "offset": m.start(),
                    "context": text[max(0, m.start()-50):m.end()+50],
                })
    
    # Also look for XOR key arrays in data
    # Repeated XOR with same key (single-byte or multi-byte)
    for key_len in [1, 2, 4, 8, 16]:
        if len(data) < key_len * 4:
            continue
        # Check for repeating pattern
        for i in range(0, min(len(data) - key_len * 4, 1000), key_len):
            key = data[i:i+key_len]
            # See if this key is used repeatedly
            count = 0
            for j in range(i, len(data) - key_len, key_len):
                if data[j:j+key_len] == key:
                    count += 1
                else:
                    break
            if count >= 4:
                xor_loops.append({
                    "type": "repeating_xor_key",
                    "key_length": key_len,
                    "key": key.hex(),
                    "offset": i,
                    "repetitions": count,
                    "confidence": "medium",
                })
                break
    
    return xor_loops


def _find_certificates(data: bytes) -> list[dict]:
    """Find DER/PEM encoded certificates and private keys."""
    certs = []
    
    # PEM certificates
    pem_cert_pattern = rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"
    for match in re.finditer(pem_cert_pattern, data, re.DOTALL):
        certs.append({
            "type": "PEM_CERTIFICATE",
            "offset": match.start(),
            "size": len(match.group()),
            "preview": match.group()[:200].decode("ascii", errors="ignore"),
        })
    
    # PEM private keys
    pem_key_patterns = [
        (rb"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----.*?-----END \1 PRIVATE KEY-----", "PEM_PRIVATE_KEY"),
        (rb"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", "PEM_PRIVATE_KEY_PKCS8"),
    ]
    for pattern, ctype in pem_key_patterns:
        for match in re.finditer(pattern, data, re.DOTALL):
            certs.append({
                "type": ctype,
                "offset": match.start(),
                "size": len(match.group()),
                "preview": match.group()[:200].decode("ascii", errors="ignore"),
            })
    
    # PEM public keys
    pem_pub_pattern = rb"-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----"
    for match in re.finditer(pem_pub_pattern, data, re.DOTALL):
        certs.append({
            "type": "PEM_PUBLIC_KEY",
            "offset": match.start(),
            "size": len(match.group()),
            "preview": match.group()[:200].decode("ascii", errors="ignore"),
        })
    
    # DER certificates (look for 0x30 0x82 - SEQUENCE with long form length)
    # This is heuristic - real DER parsing needs ASN.1
    der_pos = 0
    while True:
        pos = data.find(b"\x30\x82", der_pos)
        if pos == -1:
            break
        # Check if it looks like a certificate (reasonable size)
        if pos + 4 < len(data):
            length = struct.unpack(">H", data[pos+2:pos+4])[0]
            if 100 < length < 10000:  # Reasonable cert size
                certs.append({
                    "type": "DER_CERTIFICATE_HEURISTIC",
                    "offset": pos,
                    "estimated_size": length,
                    "preview": data[pos:pos+min(length, 100)].hex(),
                })
        der_pos = pos + 1
    
    return certs


def _find_asymmetric_params(data: bytes) -> list[dict]:
    """Find RSA/ECC/DH parameters."""
    params = []
    text = data.decode("utf-8", errors="ignore")
    
    # RSA Modulus (large integers in hex/base64)
    # Look for patterns like "modulus", "publicExponent", "privateExponent"
    rsa_keywords = ["modulus", "publicexponent", "privateexponent", "prime1", "prime2", "exponent1", "exponent2", "coefficient"]
    for kw in rsa_keywords:
        if kw in text.lower():
            params.append({
                "type": "RSA_PARAMETER_REFERENCE",
                "keyword": kw,
                "context": text[max(0, text.lower().find(kw)-100):text.lower().find(kw)+200],
            })
    
    # ECC Curve references
    ecc_curves = ["secp256r1", "secp384r1", "secp521r1", "secp256k1", "prime256v1", "x25519", "x448", "ed25519", "ed448"]
    for curve in ecc_curves:
        if curve in text.lower():
            params.append({
                "type": "ECC_CURVE_REFERENCE",
                "curve": curve,
                "context": text[max(0, text.lower().find(curve)-50):text.lower().find(curve)+100],
            })
    
    # DH Parameters
    if "dhparam" in text.lower() or "diffie-hellman" in text.lower() or "diffiehellman" in text.lower():
        params.append({
            "type": "DH_PARAMETER_REFERENCE",
            "context": "Diffie-Hellman parameter reference found",
        })
    
    return params


def _detect_custom_crypto(data: bytes) -> list[dict]:
    """Detect custom/proprietary cryptographic implementations."""
    custom = []
    text = data.decode("utf-8", errors="ignore").lower()
    
    # Custom algorithm indicators
    indicators = [
        ("custom cipher", "Custom cipher implementation"),
        ("proprietary encryption", "Proprietary encryption"),
        ("homebrew crypto", "Homebrew cryptography"),
        ("custom hash", "Custom hash function"),
        ("own encryption", "Custom encryption"),
        ("xor encryption", "XOR-based encryption"),
        ("substitution", "Substitution cipher"),
        ("permutation", "Permutation cipher"),
        ("feistel", "Feistel network"),
        ("spn", "Substitution-Permutation Network"),
        ("aes-like", "AES-like custom"),
        ("rc4-like", "RC4-like custom"),
    ]
    
    for keyword, desc in indicators:
        if keyword in text:
            custom.append({
                "indicator": keyword,
                "description": desc,
                "context": text[max(0, text.find(keyword)-50):text.find(keyword)+100],
            })
    
    return custom


def _analyze_entropy_per_section(data: bytes, window_size: int = 4096) -> dict:
    """Calculate entropy per section/window of the file."""
    if len(data) < window_size:
        return {"overall": round(shannon_entropy(data), 3), "windows": []}
    
    windows = []
    for i in range(0, len(data), window_size):
        chunk = data[i:i+window_size]
        windows.append({
            "offset": i,
            "size": len(chunk),
            "entropy": round(shannon_entropy(chunk), 3),
        })
    
    entropies = [w["entropy"] for w in windows]
    return {
        "overall": round(shannon_entropy(data), 3),
        "min": round(min(entropies), 3),
        "max": round(max(entropies), 3),
        "avg": round(sum(entropies) / len(entropies), 3),
        "windows": windows[:50],  # Limit output
    }