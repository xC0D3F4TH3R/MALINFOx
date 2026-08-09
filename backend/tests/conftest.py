"""
MALINFO — pytest configuration and fixtures.
"""
import tempfile
from pathlib import Path

import pytest

# Configure pytest-asyncio
pytest_plugins = ("pytest_asyncio",)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    import asyncio
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory(prefix="malinfo_test_") as tmp:
        yield Path(tmp)


@pytest.fixture
def sample_pe_file(temp_dir):
    """Create a fake PE file for testing."""
    pe_file = temp_dir / "test.exe"
    pe_file.write_bytes(b"MZ" + b"\x00" * 100)
    return pe_file


@pytest.fixture
def sample_elf_file(temp_dir):
    """Create a fake ELF file for testing."""
    elf_file = temp_dir / "test.elf"
    elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)
    return elf_file


@pytest.fixture
def sample_text_file(temp_dir):
    """Create a plain text file for testing."""
    text_file = temp_dir / "test.txt"
    text_file.write_text("This is a plain text file for testing.")
    return text_file


@pytest.fixture
def sample_apk_file(temp_dir):
    """Create a fake APK file for testing."""
    import zipfile
    apk_file = temp_dir / "test.apk"
    manifest_strings = [
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET",
        "com.example.testapp",
        "MainActivity",
    ]
    fake_manifest = b"".join(s.encode("utf-16le") + b"\x00\x00" for s in manifest_strings)

    with zipfile.ZipFile(apk_file, "w") as z:
        z.writestr("AndroidManifest.xml", fake_manifest)
        z.writestr("classes.dex", b"dex\n" + b"\x00" * 50)
    return apk_file