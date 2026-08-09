"""File-type identification.

Uses libmagic when available (most accurate - reads content, not just the
extension), with a pure-Python magic-byte fallback so the pipeline still
works on a host where libmagic isn't installed yet.
"""
from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# (signature_bytes, offset, file_type, mime_type, target_os)
_SIGNATURES: list[tuple[bytes, int, str, str, str]] = [
    # Executables - Windows PE
    (b"MZ", 0, "PE (Windows Executable)", "application/x-msdownload", "windows"),
    (b"MZ", 0, "PE (Windows DLL)", "application/x-msdownload", "windows"),
    (b"MZ", 0, "PE (Windows Driver)", "application/x-msdownload", "windows"),
    (b"MZ", 0, "PE (Windows OCX)", "application/x-msdownload", "windows"),
    (b"MZ", 0, "PE (Windows CPL)", "application/x-msdownload", "windows"),
    (b"MZ", 0, "PE (Windows SCR)", "application/x-msdownload", "windows"),
    (b"MZ", 0, "PE (Windows SYS)", "application/x-msdownload", "windows"),
    
    # Executables - Linux ELF
    (b"\x7fELF", 0, "ELF (Linux Executable)", "application/x-elf", "linux"),
    (b"\x7fELF", 0, "ELF (Linux Shared Object)", "application/x-sharedlib", "linux"),
    (b"\x7fELF", 0, "ELF (Linux Kernel Module)", "application/x-kernel-module", "linux"),
    (b"\x7fELF", 0, "ELF (Linux Core Dump)", "application/x-coredump", "linux"),
    
    # Executables - macOS Mach-O
    (b"\xfe\xed\xfa\xce", 0, "Mach-O 32-bit (macOS/iOS)", "application/x-mach-binary", "macos"),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit (macOS/iOS)", "application/x-mach-binary", "macos"),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit reversed (macOS/iOS)", "application/x-mach-binary", "macos"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O Fat Binary / Java Class", "application/x-mach-binary", "macos"),
    
    # Archives - ZIP-based
    (b"PK\x03\x04", 0, "ZIP-based archive (APK/JAR/DOCX/ZIP/AAB)", "application/zip", "unknown"),
    (b"PK\x05\x06", 0, "ZIP Empty Archive", "application/zip", "unknown"),
    (b"PK\x07\x08", 0, "ZIP Spanned Archive", "application/zip", "unknown"),
    
    # Archives - Other
    (b"Rar!\x1a\x07", 0, "RAR Archive", "application/x-rar-compressed", "unknown"),
    (b"Rar!\x1a\x07\x01\x00", 0, "RAR5 Archive", "application/x-rar-compressed", "unknown"),
    (b"\x1f\x8b", 0, "GZIP Archive", "application/gzip", "unknown"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip Archive", "application/x-7z-compressed", "unknown"),
    (b"BZh", 0, "BZIP2 Archive", "application/x-bzip2", "unknown"),
    (b"\xfd7zXZ", 0, "XZ Archive", "application/x-xz", "unknown"),
    (b"\x28\xb5\x2f\xfd", 0, "ZSTD Archive", "application/zstd", "unknown"),
    (b"\x04\x22\x4d\x18", 0, "LZ4 Archive", "application/x-lz4", "unknown"),
    (b"\x5d\x00\x00\x80\x00", 0, "LZMA Archive", "application/x-lzma", "unknown"),
    (b"MSCF", 0, "Microsoft Cabinet (CAB)", "application/vnd.ms-cab-compressed", "windows"),
    (b"ITSF", 0, "Microsoft Compiled HTML Help (CHM)", "application/x-chm", "windows"),
    (b"!<arch>", 0, "AR Archive (Static Library)", "application/x-archive", "linux"),
    (b"USTAR", 257, "TAR Archive (POSIX)", "application/x-tar", "unknown"),
    (b"ustar", 257, "TAR Archive (GNU)", "application/x-tar", "unknown"),
    (b"ustar\x00", 257, "TAR Archive (GNU)", "application/x-tar", "unknown"),
    
    # Disk Images
    (b"CD001", 0x8001, "ISO 9660 Disk Image", "application/x-iso9660-image", "unknown"),
    (b"CD001", 0x8801, "ISO 9660 Disk Image (alt)", "application/x-iso9660-image", "unknown"),
    (b"conectix", 0, "VHD (Virtual Hard Disk)", "application/x-vhd", "unknown"),
    (b"vhdxfile", 0, "VHDX (Virtual Hard Disk v2)", "application/x-vhdx", "unknown"),
    (b"KDMV", 0, "VMDK (VMware Virtual Disk)", "application/x-vmdk", "unknown"),
    (b"QFI\xfb", 0, "QCOW2 (QEMU Copy-on-Write)", "application/x-qcow2", "unknown"),
    (b"QFI\xfb", 0, "QCOW (QEMU Copy-on-Write v1)", "application/x-qcow", "unknown"),
    
    # Documents - must come before Config/Data Formats
    (b"%PDF", 0, "PDF Document", "application/pdf", "unknown"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MS Office (Legacy OLE/CFB)", "application/x-ole-storage", "windows"),
    (b"{\\rtf", 0, "Rich Text Format (RTF)", "application/rtf", "unknown"),
    (b"{\\rtf1", 0, "Rich Text Format (RTF)", "application/rtf", "unknown"),
    
    # Mobile - Android
    (b"dex\n", 0, "DEX (Android Dalvik Bytecode)", "application/x-dex", "android"),
    (b"dex\n035", 0, "DEX 035 (Android)", "application/x-dex", "android"),
    (b"dex\n036", 0, "DEX 036 (Android)", "application/x-dex", "android"),
    (b"dex\n037", 0, "DEX 037 (Android)", "application/x-dex", "android"),
    (b"dex\n038", 0, "DEX 038 (Android)", "application/x-dex", "android"),
    (b"dex\n039", 0, "DEX 039 (Android)", "application/x-dex", "android"),
    
    # Mobile - iOS
    (b"PK\x03\x04", 0, "IPA (iOS App Store Package)", "application/zip", "ios"),
    
    # Email
    (b"From ", 0, "EML Email (RFC 5322)", "message/rfc822", "unknown"),
    (b"Return-Path:", 0, "EML Email (RFC 5322)", "message/rfc822", "unknown"),
    (b"Received:", 0, "EML Email (RFC 5322)", "message/rfc822", "unknown"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MSG Email (Outlook OLE)", "application/vnd.ms-outlook", "windows"),
    
    # Certificates/Keys
    (b"-----BEGIN", 0, "PEM Certificate/Key", "application/x-pem-file", "unknown"),
    (b"\x30\x82", 0, "DER Certificate (X.509)", "application/x-x509-ca-cert", "unknown"),
    (b"\x30\x81", 0, "DER Certificate (short)", "application/x-x509-ca-cert", "unknown"),
    (b"\x30\x80", 0, "DER Certificate (indefinite)", "application/x-x509-ca-cert", "unknown"),
    
    # Java
    (b"\xca\xfe\xba\xbe", 0, "Java Class File", "application/java-vm", "unknown"),
    
    # Fonts
    (b"\x00\x01\x00\x00", 0, "TrueType Font (TTF)", "font/ttf", "unknown"),
    (b"\x00\x00\x01\x00", 0, "TrueType Collection (TTC)", "font/ttf", "unknown"),
    (b"OTTO", 0, "OpenType Font (OTF)", "font/otf", "unknown"),
    (b"wOFF", 0, "WOFF Font", "font/woff", "unknown"),
    (b"wOF2", 0, "WOFF2 Font", "font/woff2", "unknown"),
    (b"ttcf", 0, "TrueType Collection (TTC)", "font/ttf", "unknown"),
    
    # Images
    (b"\x89PNG\r\n\x1a\n", 0, "PNG Image", "image/png", "unknown"),
    (b"\xff\xd8\xff", 0, "JPEG Image", "image/jpeg", "unknown"),
    (b"GIF87a", 0, "GIF87a Image", "image/gif", "unknown"),
    (b"GIF89a", 0, "GIF89a Image", "image/gif", "unknown"),
    (b"BM", 0, "BMP Image", "image/bmp", "unknown"),
    (b"BA", 0, "BMP Image (OS/2)", "image/bmp", "unknown"),
    (b"CI", 0, "BMP Image (OS/2)", "image/bmp", "unknown"),
    (b"CP", 0, "BMP Image (OS/2)", "image/bmp", "unknown"),
    (b"IC", 0, "BMP Image (OS/2)", "image/bmp", "unknown"),
    (b"PT", 0, "BMP Image (OS/2)", "image/bmp", "unknown"),
    (b"II\x2a\x00", 0, "TIFF Image (LE)", "image/tiff", "unknown"),
    (b"MM\x00\x2a", 0, "TIFF Image (BE)", "image/tiff", "unknown"),
    (b"II\x2b\x00", 0, "TIFF Image BigTIFF (LE)", "image/tiff", "unknown"),
    (b"MM\x00\x2b", 0, "TIFF Image BigTIFF (BE)", "image/tiff", "unknown"),
    (b"<svg", 0, "SVG Image", "image/svg+xml", "unknown"),
    (b"<?xml", 0, "SVG Image (XML)", "image/svg+xml", "unknown"),
    (b"\x00\x00\x00\x0cIHDR", 0, "PNG (alternate)", "image/png", "unknown"),
    (b"\x00\x00\x00\x0cJXL ", 0, "JPEG XL Image", "image/jxl", "unknown"),
    (b"RIFF", 0, "WEBP Image (RIFF)", "image/webp", "unknown"),
    (b"farb", 0, "FARBFELD Image", "image/x-farbfeld", "unknown"),
    (b"QOI", 0, "QOI Image", "image/x-qoi", "unknown"),
    
    # Video/Audio
    (b"ftyp", 4, "MP4/M4V/MOV/3GP", "video/mp4", "unknown"),
    (b"ftypisom", 4, "MP4 (ISO Base Media)", "video/mp4", "unknown"),
    (b"ftypmp42", 4, "MP4 v2", "video/mp4", "unknown"),
    (b"ftypavc1", 4, "MP4 (AVC)", "video/mp4", "unknown"),
    (b"ftypheic", 4, "HEIC Image", "image/heic", "unknown"),
    (b"ftypheix", 4, "HEIC Image", "image/heic", "unknown"),
    (b"RIFF", 0, "RIFF (AVI/WAV/WEBP)", "application/x-riff", "unknown"),
    (b"ID3", 0, "MP3 with ID3", "audio/mpeg", "unknown"),
    (b"\xff\xfb", 0, "MP3 (MPEG Audio)", "audio/mpeg", "unknown"),
    (b"\xff\xf3", 0, "MP3 (MPEG Audio)", "audio/mpeg", "unknown"),
    (b"\xff\xf2", 0, "MP3 (MPEG Audio)", "audio/mpeg", "unknown"),
    (b"\xff\xf1", 0, "MP3 (MPEG Audio)", "audio/mpeg", "unknown"),
    (b"\xff\xf0", 0, "MP3 (MPEG Audio)", "audio/mpeg", "unknown"),
    (b"OggS", 0, "Ogg Container (Vorbis/Opus/Theora)", "application/ogg", "unknown"),
    (b"\x1aE\xdf\xa3", 0, "Matroska (MKV/WebM)", "video/x-matroska", "unknown"),
    (b"FLAC", 0, "FLAC Audio", "audio/flac", "unknown"),
    (b"fLaC", 0, "FLAC Audio", "audio/flac", "unknown"),
    (b"RIFF", 0, "WAV Audio", "audio/wav", "unknown"),
    (b".snd", 0, "AU/SND Audio", "audio/basic", "unknown"),
    (b".SND", 0, "AU/SND Audio", "audio/basic", "unknown"),
    (b"FORM", 0, "AIFF Audio", "audio/aiff", "unknown"),
    (b"MAC ", 0, "Monkey's Audio", "audio/x-monkeys-audio", "unknown"),
    (b"wvpk", 0, "WavPack Audio", "audio/x-wavpack", "unknown"),
    
    # Database
    (b"SQLite format 3", 0, "SQLite Database", "application/x-sqlite3", "unknown"),
    (b"Standard Jet DB", 0, "Microsoft Access (MDB)", "application/x-msaccess", "windows"),
    (b"\x00\x01\x00\x00Standard Jet DB", 4, "Microsoft Access (MDB)", "application/x-msaccess", "windows"),
    
    # Logs/Forensics - Windows
    (b"ElfFile", 0, "EVTX (Windows Event Log)", "application/x-evtx", "windows"),
    (b"SCCC", 0, "Prefetch (.pf)", "application/x-windows-prefetch", "windows"),
    (b"MAM", 0, "Amcache.hve (registry)", "application/x-windows-registry", "windows"),
    (b"regf", 0, "Windows Registry Hive", "application/x-windows-registry", "windows"),
    (b"hbin", 0, "Windows Registry Hive Bin", "application/x-windows-registry", "windows"),
    
    # Installers/Packagers
    (b"MZP", 0, "NSIS Installer", "application/x-nsis", "windows"),
    (b"MZP", 0, "NSIS Installer (alt)", "application/x-nsis", "windows"),
    (b"\x4e\x53\x49\x53", 0, "NSIS Installer", "application/x-nsis", "windows"),
    (b"InnoSetup", 0, "Inno Setup Installer", "application/x-inno-setup", "windows"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip Self-Extracting", "application/x-7z-compressed", "windows"),
    (b"MSCF", 0, "Microsoft Cabinet (CAB)", "application/vnd.ms-cab-compressed", "windows"),
    (b"ISc(", 0, "InstallShield Cabinet", "application/x-installshield", "windows"),
    (b"WISE", 0, "WISE Installer", "application/x-wise", "windows"),
    
    # Firmware/Embedded
    (b"U-Boot", 0, "U-Boot Bootloader", "application/x-u-boot", "unknown"),
    (b"U-Boot\x00", 0, "U-Boot Bootloader", "application/x-u-boot", "unknown"),
    (b"BOOT", 0, "Generic Bootloader", "application/x-bootloader", "unknown"),
    (b"FIT", 0, "Flattened Image Tree (FIT)", "application/x-fit", "unknown"),
    (b"ANDROID!", 0, "Android Boot Image", "application/x-android-boot", "android"),
    (b"CHROMEOS", 0, "Chrome OS Image", "application/x-chromeos", "unknown"),
    
    # Compressed Filesystems
    (b"hsqs", 0, "SquashFS (LE)", "application/x-squashfs", "linux"),
    (b"sqsh", 0, "SquashFS (BE)", "application/x-squashfs", "linux"),
    (b"\x31\x18\x10\x06", 0, "JFFS2", "application/x-jffs2", "linux"),
    (b"\x19\x85\x20\x03", 0, "YAFFS2", "application/x-yaffs2", "linux"),
    (b"UBIFS", 0, "UBIFS", "application/x-ubifs", "linux"),
    (b"CRAMFS", 0, "CRAMFS", "application/x-cramfs", "linux"),
    (b"erofs", 0, "EROFS", "application/x-erofs", "linux"),
    (b"romfs", 0, "ROMFS", "application/x-romfs", "linux"),
    
    # Documents - must come before Config/Data Formats
    (b"%PDF", 0, "PDF Document", "application/pdf", "unknown"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MS Office (Legacy OLE/CFB)", "application/x-ole-storage", "windows"),
    (b"{\x5crtf", 0, "Rich Text Format (RTF)", "application/rtf", "unknown"),
    (b"{\x5crtf1", 0, "Rich Text Format (RTF)", "application/rtf", "unknown"),
    
    # Config/Data Formats
    (b"{", 0, "JSON (possible)", "application/json", "unknown"),
    (b"[", 0, "JSON Array (possible)", "application/json", "unknown"),
    (b"---", 0, "YAML Document", "application/yaml", "unknown"),
    (b"<?xml", 0, "XML Document", "application/xml", "unknown"),
    (b"<html", 0, "HTML Document", "text/html", "unknown"),
    (b"<HTML", 0, "HTML Document", "text/html", "unknown"),
    (b"<!DOCTYPE", 0, "HTML/SGML Document", "text/html", "unknown"),
    (b"<!doctype", 0, "HTML/SGML Document", "text/html", "unknown"),
    
    # Scripts (shebang detection)
    (b"#!/bin/bash", 0, "Bash Script", "text/x-shellscript", "linux"),
    (b"#!/bin/sh", 0, "Shell Script", "text/x-shellscript", "linux"),
    (b"#!/usr/bin/env", 0, "Script (env shebang)", "text/x-script", "unknown"),
    (b"#!/usr/bin/python", 0, "Python Script", "text/x-python", "unknown"),
    (b"#!/usr/bin/python3", 0, "Python 3 Script", "text/x-python", "unknown"),
    (b"#!/usr/bin/perl", 0, "Perl Script", "text/x-perl", "unknown"),
    (b"#!/usr/bin/ruby", 0, "Ruby Script", "text/x-ruby", "unknown"),
    (b"#!/usr/bin/php", 0, "PHP Script", "text/x-php", "unknown"),
    (b"#!/usr/bin/node", 0, "Node.js Script", "text/x-javascript", "unknown"),
    (b"@echo off", 0, "Batch Script", "text/x-batch", "windows"),
    (b"@ECHO OFF", 0, "Batch Script", "text/x-batch", "windows"),
    
    # Misc - Windows
    (b"MZ", 0, "DOS MZ Executable", "application/x-dosexec", "windows"),
    (b"NE", 0, "OS/2 NE Executable", "application/x-osexec", "windows"),
    (b"LE", 0, "OS/2 LE Executable", "application/x-osexec", "windows"),
    (b"LX", 0, "OS/2 LX Executable", "application/x-osexec", "windows"),
    (b"PE", 0, "PE (Windows)", "application/x-msdownload", "windows"),
    (b"MSCF", 0, "Microsoft Cabinet", "application/vnd.ms-cab-compressed", "windows"),
    (b".SFX", 0, "Self-Extracting Archive", "application/x-sfx", "windows"),
    
    # Windows Forensics
    (b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46", 0, "LNK (Windows Shortcut)", "application/x-ms-shortcut", "windows"),
    (b"SCCC", 0, "Prefetch (.pf)", "application/x-windows-prefetch", "windows"),
    (b"regf", 0, "Windows Registry Hive", "application/x-windows-registry", "windows"),
    
    # Misc - Certificates/Keys (extended)
    (b"-----BEGIN RSA PRIVATE KEY-----", 0, "RSA Private Key (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN PRIVATE KEY-----", 0, "Private Key (PEM PKCS#8)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN PUBLIC KEY-----", 0, "Public Key (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN CERTIFICATE-----", 0, "X.509 Certificate (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN CERTIFICATE REQUEST-----", 0, "CSR (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN PKCS7-----", 0, "PKCS#7 (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN PKCS12-----", 0, "PKCS#12 (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN ENCRYPTED PRIVATE KEY-----", 0, "Encrypted Private Key (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN DSA PRIVATE KEY-----", 0, "DSA Private Key (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN EC PRIVATE KEY-----", 0, "EC Private Key (PEM)", "application/x-pem-file", "unknown"),
    (b"-----BEGIN OPENSSH PRIVATE KEY-----", 0, "OpenSSH Private Key", "application/x-pem-file", "unknown"),
    (b"ssh-rsa ", 0, "SSH Public Key (RSA)", "text/x-ssh-public-key", "unknown"),
    (b"ssh-dss ", 0, "SSH Public Key (DSA)", "text/x-ssh-public-key", "unknown"),
    (b"ecdsa-sha2-", 0, "SSH Public Key (ECDSA)", "text/x-ssh-public-key", "unknown"),
    (b"ssh-ed25519 ", 0, "SSH Public Key (Ed25519)", "text/x-ssh-public-key", "unknown"),
    
    # Misc - Network/PCAP
    (b"\xd4\xc3\xb2\xa1", 0, "PCAP File (LE)", "application/vnd.tcpdump.pcap", "unknown"),
    (b"\xa1\xb2\xc3\xd4", 0, "PCAP File (BE)", "application/vnd.tcpdump.pcap", "unknown"),
    (b"\x0a\x0d\x0d\x0a", 0, "PCAPNG File", "application/vnd.tcpdump.pcapng", "unknown"),
    (b"MZP", 0, "PCAP (old)", "application/vnd.tcpdump.pcap", "unknown"),
]


def _magic_fallback(header: bytes) -> tuple[str, str, str]:
    for sig, offset, ftype, mime, os_ in _SIGNATURES:
        if len(header) >= offset + len(sig):
            if header[offset:offset + len(sig)] == sig:
                return ftype, mime, os_
    return "Unknown / raw data", "application/octet-stream", "unknown"


def identify_file(file_path: Path) -> dict:
    with open(file_path, "rb") as f:
        header = f.read(65536)  # Read more for deeper signatures (ISO at 32KB+)

    file_type, mime_type, target_os = _magic_fallback(header)

    # Prefer libmagic for a richer description when available.
    # Note: python-magic on Windows requires libmagic DLL which may not be available,
    # causing segmentation faults. We skip libmagic on Windows and use the
    # pure-Python signature fallback instead.
    if sys.platform != "win32":
        try:
            import magic  # python-magic

            mime_type = magic.from_file(str(file_path), mime=True) or mime_type
            file_type = magic.from_file(str(file_path)) or file_type
        except ImportError:
            pass  # python-magic not installed, fall back to signature match above
        except Exception:
            pass  # libmagic not available or other error, fall back to signature match above

    # APK vs generic ZIP disambiguation: APKs are ZIPs containing
    # AndroidManifest.xml and classes.dex at the root.
    if file_type.startswith("ZIP") or mime_type == "application/zip":
        apk_hint = _looks_like_apk(file_path)
        if apk_hint:
            file_type = "APK (Android Application Package)"
            mime_type = "application/vnd.android.package-archive"
            target_os = "android"
        elif _looks_like_aab(file_path):
            file_type = "AAB (Android App Bundle)"
            mime_type = "application/vnd.android.appbundle"
            target_os = "android"
        elif _looks_like_jar(file_path):
            file_type = "JAR (Java Archive)"
            mime_type = "application/java-archive"
            target_os = "unknown"
        elif _looks_like_war(file_path):
            file_type = "WAR (Web Application Archive)"
            mime_type = "application/java-archive"
            target_os = "unknown"
        elif _looks_like_ear(file_path):
            file_type = "EAR (Enterprise Archive)"
            mime_type = "application/java-archive"
            target_os = "unknown"
        elif _looks_like_docx_xlsx_pptx(file_path):
            file_type = "Office Open XML document (docx/xlsx/pptx)"
            target_os = "windows"
        elif _looks_like_epub(file_path):
            file_type = "EPUB (Electronic Publication)"
            mime_type = "application/epub+zip"
            target_os = "unknown"
        elif _looks_like_ipa(file_path):
            file_type = "IPA (iOS App Store Package)"
            mime_type = "application/zip"
            target_os = "ios"
        elif _looks_like_vsix(file_path):
            file_type = "VSIX (Visual Studio Extension)"
            mime_type = "application/zip"
            target_os = "windows"
        elif _looks_like_xpi(file_path):
            file_type = "XPI (Mozilla Extension)"
            mime_type = "application/zip"
            target_os = "unknown"
        elif _looks_like_office_template(file_path):
            file_type = "Office Open XML Template (dotx/xltx/potx)"
            target_os = "windows"

    # DEX detection (standalone)
    if file_type.startswith("DEX") or file_path.suffix.lower() == ".dex":
        file_type = "DEX (Android Dalvik Bytecode)"
        mime_type = "application/x-dex"
        target_os = "android"

    # Java Class file
    if header[:4] == b"\xca\xfe\xba\xbe":
        # Could be Mach-O Fat or Java Class - check further
        if len(header) >= 8:
            # Java class has minor/major version at offset 4
            minor = int.from_bytes(header[4:6], "big")
            major = int.from_bytes(header[6:8], "big")
            if 45 <= major <= 65:  # Valid Java class versions
                file_type = "Java Class File"
                mime_type = "application/java-vm"
                target_os = "unknown"

    # Mach-O Fat Binary vs Java Class disambiguation
    if file_type == "Mach-O Fat Binary / Java Class":
        if len(header) >= 8:
            nfat_arch = int.from_bytes(header[4:8], "big")
            if nfat_arch > 0 and nfat_arch < 100:
                file_type = "Mach-O Fat Binary (macOS/iOS)"
                mime_type = "application/x-mach-binary"
                target_os = "macos"
            else:
                # Check if Java class
                minor = int.from_bytes(header[4:6], "big")
                major = int.from_bytes(header[6:8], "big")
                if 45 <= major <= 65:
                    file_type = "Java Class File"
                    mime_type = "application/java-vm"
                    target_os = "unknown"

    return {"file_type": file_type, "mime_type": mime_type, "target_os": target_os}


def _looks_like_apk(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names)
    except Exception:
        return False


def _looks_like_aab(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "BundleConfig.pb" in names or "base/manifest/AndroidManifest.xml" in names
    except Exception:
        return False


def _looks_like_jar(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "META-INF/MANIFEST.MF" in names
    except Exception:
        return False


def _looks_like_war(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "WEB-INF/web.xml" in names or "WEB-INF/classes/" in [n for n in names if n.endswith("/")]
    except Exception:
        return False


def _looks_like_ear(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "META-INF/application.xml" in names
    except Exception:
        return False


def _looks_like_docx_xlsx_pptx(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "[Content_Types].xml" in names
    except Exception:
        return False


def _looks_like_epub(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "mimetype" in names and any(n.startswith("META-INF/container.xml") for n in names)
    except Exception:
        return False


def _looks_like_ipa(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return any(n.endswith(".app/Info.plist") for n in names)
    except Exception:
        return False


def _looks_like_vsix(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "extension.vsixmanifest" in names
    except Exception:
        return False


def _looks_like_xpi(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return "install.rdf" in names or "manifest.json" in names
    except Exception:
        return False


def _looks_like_office_template(file_path: Path) -> bool:
    try:
        import zipfile

        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            return any(n.endswith((".dotx", ".xltx", ".potx", ".dotm", ".xltm", ".potm")) for n in names)
    except Exception:
        return False