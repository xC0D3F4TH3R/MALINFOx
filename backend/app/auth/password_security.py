"""
Password security utilities for MALINFO.
Implements strong password policies and breach detection.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    pass

logger = logging.getLogger("malinfo.auth.password")

# Common weak passwords (top 1000 most common)
WEAK_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password123",
    "admin", "letmein", "welcome", "monkey", "dragon", "master", "hello",
    "freedom", "whatever", "qazwsx", "trustno1", "654321", "jordan23",
    "harley", "password1", "shadow", "michael", "superman", "matthew",
    "jordan", "asshole", "thomas", "tigger", "robert", "charlie", "andrew",
    "michelle", "love", "sunshine", "jennifer", "mickey", "chocolate",
    "zaq1zaq1", "solo", "passw0rd", "starwars", "passw0rd123", "admin123",
    "welcome123", "qwerty123", "1q2w3e4r", "1qaz2wsx", "iloveyou", "football",
    "princess", "rockyou", "abc12345", "aaaaaa", "pass", "login", "adminadmin",
    "root", "toor", "user", "test", "guest", "info", "adm", "mysql", "oracle",
    "postgres", "sql", "server", "database", "backup", "dev", "prod", "stage",
    "demo", "example", "sample", "template", "default", "changeme", "changeme123",
}

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
    "6yhn", "7ujm", "8ik,", "9ol.", "0p;/", "qazwsx", "wsxedc", "edcrfv",
    "rfvtgb", "tgbhyhn", "yhnujm", "ujmik,", "ik,ol.", "ol.p;/",
    "123456", "234567", "345678", "456789", "567890", "67890-",
    "abcdef", "bcdefg", "cdefgh", "defghi", "efghij", "fghijk", "ghijkl",
    "hijklm", "ijklmn", "jklmno", "klmnop", "lmnopq", "mnopqr", "nopqrs",
    "opqrst", "pqrstu", "qrstuv", "rstuvw", "stuvwx", "tuvwxy", "uvwxyz",
]

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128
MIN_ENTROPY_BITS = 60


def calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of password in bits.
    """
    import math
    char_sets = set()
    if re.search(r"[a-z]", password):
        char_sets.add(26)
    if re.search(r"[A-Z]", password):
        char_sets.add(26)
    if re.search(r"\d", password):
        char_sets.add(10)
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        char_sets.add(32)

    pool_size = sum(char_sets)
    return len(password) * math.log2(pool_size) if pool_size > 0 else 0


def has_keyboard_pattern(password: str) -> bool:
    """Check if password contains keyboard patterns."""
    lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in lower:
            return True
    return False


def has_repeated_chars(password: str, max_repeat: int = 3) -> bool:
    """Check for repeated characters."""
    for i in range(len(password) - max_repeat + 1):
        if len(set(password[i:i+max_repeat])) == 1:
            return True
    return False


def has_sequential_chars(password: str, min_seq: int = 4) -> bool:
    """Check for sequential characters (abc, 123, etc.)."""
    lower = password.lower()
    for i in range(len(lower) - min_seq + 1):
        seq = lower[i:i+min_seq]
        # Check ascending
        if all(ord(seq[j+1]) - ord(seq[j]) == 1 for j in range(len(seq)-1)):
            return True
        # Check descending
        if all(ord(seq[j]) - ord(seq[j+1]) == 1 for j in range(len(seq)-1)):
            return True
    return False


def validate_password_strength(password: str) -> tuple[bool, list[str]]:
    """
    Validate password strength against policy.
    Returns (is_valid, list_of_errors).
    """
    errors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    if len(password) > MAX_PASSWORD_LENGTH:
        errors.append(f"Password must not exceed {MAX_PASSWORD_LENGTH} characters")

    if password.lower() in WEAK_PASSWORDS:
        errors.append("Password is too common - please choose a more unique password")

    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter")

    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter")

    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        errors.append("Password must contain at least one special character")

    if has_keyboard_pattern(password):
        errors.append("Password contains keyboard patterns - please avoid sequences like 'qwerty' or '1234'")

    if has_repeated_chars(password):
        errors.append("Password contains repeated characters - please avoid sequences like 'aaa' or '111'")

    if has_sequential_chars(password):
        errors.append("Password contains sequential characters - please avoid sequences like 'abcd' or '1234'")

    entropy = calculate_entropy(password)
    if entropy < MIN_ENTROPY_BITS:
        errors.append(f"Password entropy too low ({entropy:.1f} bits, minimum {MIN_ENTROPY_BITS})")

    return len(errors) == 0, errors


async def check_pwned_password(password: str) -> bool:
    """
    Check if password appears in HaveIBeenPwned breach database.
    Uses k-anonymity model - only sends first 5 chars of SHA1 hash.
    Returns True if password was found in breaches.
    """
    try:
        # Calculate SHA1 hash
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query HIBP API
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                # Parse response - each line is "SUFFIX:COUNT"
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = int(line.split(":")[1])
                        logger.warning(
                            "Password found in breach database",
                            extra={"breach_count": count, "hash_prefix": prefix}
                        )
                        return True
    except Exception as e:
        # Fail open - don't block on API errors
        logger.warning("Failed to check password breach database: %s", e)

    return False


async def validate_password(password: str) -> tuple[bool, list[str]]:
    """
    Complete password validation including breach check.
    Returns (is_valid, list_of_errors).
    """
    # Local validation
    is_valid, errors = validate_password_strength(password)
    if not is_valid:
        return False, errors

    # Check breach database
    if await check_pwned_password(password):
        errors.append("This password has appeared in data breaches - please choose a different password")
        return False, errors

    return True, []


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password."""
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        is_valid, _ = validate_password_strength(password)
        if is_valid:
            return password