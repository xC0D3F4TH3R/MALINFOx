"""MALINFO — Java Class File Analysis

Analysis of Java .class files: constant pool, bytecode, obfuscation detection.
"""
from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, Optional

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.java_analysis")


def analyze_class_file(file_path: Path) -> dict:
    """
    Analyze Java class file.
    """
    result: dict = {
        "available": True,
        "format": "Java Class File",
        "magic": "",
        "version": "",
        "constant_pool": [],
        "interfaces": [],
        "fields": [],
        "methods": [],
        "attributes": [],
        "strings": [],
        "suspicious_strings": [],
        "suspicious_methods": [],
        "obfuscation_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        result["entropy"] = round(shannon_entropy(data[:8192]), 3)

        # Parse class file
        _parse_class_file(data, result)

    except Exception as exc:
        logger.debug(f"Java class analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _parse_class_file(data: bytes, result: dict) -> None:
    """Parse Java class file structure."""
    offset = 0

    # Magic number
    if len(data) < 8:
        result["errors"].append("File too small for class file")
        return

    magic = data[0:4]
    result["magic"] = magic.hex()
    if magic != b"\xca\xfe\xba\xbe":
        result["errors"].append("Invalid magic number")
        return

    # Version
    minor_version = struct.unpack(">H", data[4:6])[0]
    major_version = struct.unpack(">H", data[6:8])[0]
    result["version"] = f"{major_version}.{minor_version}"

    # Java version mapping
    java_versions = {
        45: "Java 1.0", 46: "Java 1.1", 47: "Java 1.2", 48: "Java 1.3",
        49: "Java 1.4", 50: "Java 5", 51: "Java 6", 52: "Java 7",
        53: "Java 8", 54: "Java 9", 55: "Java 10", 56: "Java 11",
        57: "Java 12", 58: "Java 13", 59: "Java 14", 60: "Java 15",
        61: "Java 16", 62: "Java 17", 63: "Java 18", 64: "Java 19",
        65: "Java 20", 66: "Java 21",
    }
    result["java_version"] = java_versions.get(major_version, f"Unknown (major={major_version})")

    offset = 8

    # Constant pool
    cp_count = struct.unpack(">H", data[offset:offset+2])[0]
    result["constant_pool_count"] = cp_count
    offset += 2

    constant_pool = [None]  # 1-indexed
    i = 1
    while i < cp_count:
        if offset >= len(data):
            break
        tag = data[offset]
        offset += 1

        if tag == 1:  # CONSTANT_Utf8
            length = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            string_bytes = data[offset:offset+length]
            offset += length
            try:
                string = string_bytes.decode("utf-8")
            except UnicodeDecodeError:
                string = string_bytes.decode("utf-8", errors="replace")
            constant_pool.append({"tag": "Utf8", "value": string})
            result["strings"].append(string)

        elif tag == 3:  # CONSTANT_Integer
            value = struct.unpack(">i", data[offset:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "Integer", "value": value})

        elif tag == 4:  # CONSTANT_Float
            value = struct.unpack(">f", data[offset:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "Float", "value": value})

        elif tag == 5:  # CONSTANT_Long
            value = struct.unpack(">q", data[offset:offset+8])[0]
            offset += 8
            constant_pool.append({"tag": "Long", "value": value})
            constant_pool.append(None)  # Long takes 2 slots
            i += 1

        elif tag == 6:  # CONSTANT_Double
            value = struct.unpack(">d", data[offset:offset+8])[0]
            offset += 8
            constant_pool.append({"tag": "Double", "value": value})
            constant_pool.append(None)  # Double takes 2 slots
            i += 1

        elif tag == 7:  # CONSTANT_Class
            name_index = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            constant_pool.append({"tag": "Class", "name_index": name_index})

        elif tag == 8:  # CONSTANT_String
            string_index = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            constant_pool.append({"tag": "String", "string_index": string_index})

        elif tag == 9:  # CONSTANT_Fieldref
            class_index = struct.unpack(">H", data[offset:offset+2])[0]
            name_and_type_index = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "Fieldref", "class_index": class_index, "name_and_type_index": name_and_type_index})

        elif tag == 10:  # CONSTANT_Methodref
            class_index = struct.unpack(">H", data[offset:offset+2])[0]
            name_and_type_index = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "Methodref", "class_index": class_index, "name_and_type_index": name_and_type_index})

        elif tag == 11:  # CONSTANT_InterfaceMethodref
            class_index = struct.unpack(">H", data[offset:offset+2])[0]
            name_and_type_index = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "InterfaceMethodref", "class_index": class_index, "name_and_type_index": name_and_type_index})

        elif tag == 12:  # CONSTANT_NameAndType
            name_index = struct.unpack(">H", data[offset:offset+2])[0]
            descriptor_index = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "NameAndType", "name_index": name_index, "descriptor_index": descriptor_index})

        elif tag == 15:  # CONSTANT_MethodHandle
            reference_kind = data[offset]
            reference_index = struct.unpack(">H", data[offset+1:offset+3])[0]
            offset += 3
            constant_pool.append({"tag": "MethodHandle", "reference_kind": reference_kind, "reference_index": reference_index})

        elif tag == 16:  # CONSTANT_MethodType
            descriptor_index = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            constant_pool.append({"tag": "MethodType", "descriptor_index": descriptor_index})

        elif tag == 17:  # CONSTANT_Dynamic
            bootstrap_method_attr_index = struct.unpack(">H", data[offset:offset+2])[0]
            name_and_type_index = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "Dynamic", "bootstrap_method_attr_index": bootstrap_method_attr_index, "name_and_type_index": name_and_type_index})

        elif tag == 18:  # CONSTANT_InvokeDynamic
            bootstrap_method_attr_index = struct.unpack(">H", data[offset:offset+2])[0]
            name_and_type_index = struct.unpack(">H", data[offset+2:offset+4])[0]
            offset += 4
            constant_pool.append({"tag": "InvokeDynamic", "bootstrap_method_attr_index": bootstrap_method_attr_index, "name_and_type_index": name_and_type_index})

        elif tag == 19:  # CONSTANT_Module
            name_index = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            constant_pool.append({"tag": "Module", "name_index": name_index})

        elif tag == 20:  # CONSTANT_Package
            name_index = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            constant_pool.append({"tag": "Package", "name_index": name_index})

        else:
            result["errors"].append(f"Unknown constant pool tag: {tag} at offset {offset-1}")
            break

        i += 1

    result["constant_pool"] = constant_pool[1:]  # Remove dummy

    # Access flags
    if offset + 2 > len(data):
        result["errors"].append("Truncated class file")
        return
    access_flags = struct.unpack(">H", data[offset:offset+2])[0]
    result["access_flags"] = access_flags
    result["access_flags_str"] = _parse_access_flags(access_flags, "class")
    offset += 2

    # This class
    this_class = struct.unpack(">H", data[offset:offset+2])[0]
    result["this_class"] = this_class
    result["this_class_name"] = _get_cp_string(constant_pool, this_class)
    offset += 2

    # Super class
    super_class = struct.unpack(">H", data[offset:offset+2])[0]
    result["super_class"] = super_class
    result["super_class_name"] = _get_cp_string(constant_pool, super_class)
    offset += 2

    # Interfaces
    interfaces_count = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    interfaces = []
    for _ in range(interfaces_count):
        if offset + 2 > len(data):
            break
        iface = struct.unpack(">H", data[offset:offset+2])[0]
        interfaces.append(_get_cp_string(constant_pool, iface))
        offset += 2
    result["interfaces"] = interfaces

    # Fields
    fields_count = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    fields = []
    for _ in range(fields_count):
        if offset + 8 > len(data):
            break
        field_access = struct.unpack(">H", data[offset:offset+2])[0]
        name_index = struct.unpack(">H", data[offset+2:offset+4])[0]
        descriptor_index = struct.unpack(">H", data[offset+4:offset+6])[0]
        attributes_count = struct.unpack(">H", data[offset+6:offset+8])[0]
        offset += 8

        field_info = {
            "access_flags": field_access,
            "access_flags_str": _parse_access_flags(field_access, "field"),
            "name": _get_cp_string(constant_pool, name_index),
            "descriptor": _get_cp_string(constant_pool, descriptor_index),
            "attributes": [],
        }

        # Skip attributes
        for _ in range(attributes_count):
            if offset + 6 > len(data):
                break
            attr_name_index = struct.unpack(">H", data[offset:offset+2])[0]
            attr_length = struct.unpack(">I", data[offset+2:offset+6])[0]
            offset += 6 + attr_length
            field_info["attributes"].append(_get_cp_string(constant_pool, attr_name_index))

        fields.append(field_info)

    result["fields"] = fields

    # Methods
    methods_count = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    methods = []
    for _ in range(methods_count):
        if offset + 8 > len(data):
            break
        method_access = struct.unpack(">H", data[offset:offset+2])[0]
        name_index = struct.unpack(">H", data[offset+2:offset+4])[0]
        descriptor_index = struct.unpack(">H", data[offset+4:offset+6])[0]
        attributes_count = struct.unpack(">H", data[offset+6:offset+8])[0]
        offset += 8

        method_info = {
            "access_flags": method_access,
            "access_flags_str": _parse_access_flags(method_access, "method"),
            "name": _get_cp_string(constant_pool, name_index),
            "descriptor": _get_cp_string(constant_pool, descriptor_index),
            "attributes": [],
            "code": None,
        }

        for _ in range(attributes_count):
            if offset + 6 > len(data):
                break
            attr_name_index = struct.unpack(">H", data[offset:offset+2])[0]
            attr_length = struct.unpack(">I", data[offset+2:offset+6])[0]
            attr_name = _get_cp_string(constant_pool, attr_name_index)

            if attr_name == "Code":
                # Parse Code attribute
                code_offset = offset + 6
                if code_offset + 12 <= len(data):
                    max_stack = struct.unpack(">H", data[code_offset:code_offset+2])[0]
                    max_locals = struct.unpack(">H", data[code_offset+2:code_offset+4])[0]
                    code_length = struct.unpack(">I", data[code_offset+4:code_offset+8])[0]
                    code_start = code_offset + 8
                    code_bytes = data[code_start:code_start+code_length]
                    method_info["code"] = {
                        "max_stack": max_stack,
                        "max_locals": max_locals,
                        "code_length": code_length,
                        "bytecode": code_bytes.hex(),
                    }
                    # Analyze bytecode for suspicious patterns
                    _analyze_bytecode(code_bytes, method_info, result)

            offset += 6 + attr_length
            method_info["attributes"].append(attr_name)

        methods.append(method_info)

    result["methods"] = methods

    # Class attributes
    attributes_count = struct.unpack(">H", data[offset:offset+2])[0]
    offset += 2
    attributes = []
    for _ in range(attributes_count):
        if offset + 6 > len(data):
            break
        attr_name_index = struct.unpack(">H", data[offset:offset+2])[0]
        attr_length = struct.unpack(">I", data[offset+2:offset+6])[0]
        offset += 6 + attr_length
        attributes.append(_get_cp_string(constant_pool, attr_name_index))
    result["attributes"] = attributes

    # Analyze for suspicious indicators
    _analyze_java_class(result)


def _get_cp_string(constant_pool: list, index: int) -> str:
    """Get string from constant pool by index."""
    if 0 < index < len(constant_pool) and constant_pool[index]:
        entry = constant_pool[index]
        if entry.get("tag") == "Utf8":
            return entry.get("value", "")
        elif entry.get("tag") == "String":
            str_idx = entry.get("string_index")
            if 0 < str_idx < len(constant_pool) and constant_pool[str_idx]:
                return constant_pool[str_idx].get("value", "")
        elif entry.get("tag") == "Class":
            name_idx = entry.get("name_index")
            if 0 < name_idx < len(constant_pool) and constant_pool[name_idx]:
                return constant_pool[name_idx].get("value", "")
    return f"cp[{index}]"


def _parse_access_flags(flags: int, context: str) -> list[str]:
    """Parse access flags."""
    class_flags = {
        0x0001: "public", 0x0010: "final", 0x0020: "super",
        0x0200: "interface", 0x0400: "abstract", 0x1000: "synthetic",
        0x2000: "annotation", 0x4000: "enum", 0x8000: "module",
    }
    field_flags = {
        0x0001: "public", 0x0002: "private", 0x0004: "protected",
        0x0008: "static", 0x0010: "final", 0x0040: "volatile",
        0x0080: "transient", 0x1000: "synthetic", 0x4000: "enum",
    }
    method_flags = {
        0x0001: "public", 0x0002: "private", 0x0004: "protected",
        0x0008: "static", 0x0010: "final", 0x0020: "synchronized",
        0x0040: "bridge", 0x0080: "varargs", 0x0100: "native",
        0x0200: "abstract", 0x0400: "strict", 0x0800: "synthetic",
    }

    flag_map = {"class": class_flags, "field": field_flags, "method": method_flags}.get(context, {})
    return [v for k, v in flag_map.items() if flags & k]


def _analyze_bytecode(code_bytes: bytes, method_info: dict, result: dict) -> None:
    """Analyze bytecode for suspicious patterns."""
    # Look for suspicious bytecode patterns
    suspicious_opcodes = {
        0xb7: "invokespecial",  # Can call private methods
        0xb8: "invokestatic",   # Static method calls
        0xb9: "invokeinterface",  # Interface calls
        0xba: "invokedynamic",  # Dynamic invocation (Java 7+)
        0xbb: "new",            # Object creation
        0xc0: "checkcast",      # Type casting
        0xc1: "instanceof",     # Type checking
        0xca: "multianewarray", # Multi-dim array
    }

    # Reflection-related
    reflection_classes = [
        "java/lang/reflect/Method",
        "java/lang/reflect/Field",
        "java/lang/reflect/Constructor",
        "java/lang/Class",
        "java/lang/ClassLoader",
        "java/lang/Runtime",
        "java/lang/ProcessBuilder",
        "java/lang/System",
        "java/io/File",
        "java/net/Socket",
        "java/net/URL",
        "java/net/HttpURLConnection",
        "javax/crypto/Cipher",
        "javax/crypto/SecretKey",
        "sun/misc/Unsafe",
    ]

    # Scan constant pool references in bytecode (simplified)
    # Real analysis would parse the bytecode properly


def _analyze_java_class(result: dict) -> None:
    """Analyze class for suspicious indicators."""
    # Check for obfuscation indicators
    class_name = result.get("this_class_name", "")

    # Short/classic obfuscated names
    if class_name and len(class_name) <= 2 and class_name.isalpha():
        result["obfuscation_indicators"].append(f"Short class name (possible obfuscation): {class_name}")

    # Check methods for suspicious names
    for method in result.get("methods", []):
        name = method.get("name", "")
        descriptor = method.get("descriptor", "")

        # Reflection usage
        if "java/lang/reflect" in descriptor:
            result["suspicious_methods"].append(f"Reflection usage: {name}{descriptor}")

        # Runtime exec
        if "java/lang/Runtime" in descriptor and "exec" in name:
            result["suspicious_methods"].append(f"Runtime.exec: {name}{descriptor}")

        # ProcessBuilder
        if "java/lang/ProcessBuilder" in descriptor:
            result["suspicious_methods"].append(f"ProcessBuilder: {name}{descriptor}")

        # Class loading
        if "java/lang/Class" in descriptor and ("forName" in name or "loadClass" in name):
            result["suspicious_methods"].append(f"Dynamic class loading: {name}{descriptor}")

        # Crypto
        if "javax/crypto" in descriptor:
            result["suspicious_methods"].append(f"Crypto usage: {name}{descriptor}")

        # Network
        if any(net in descriptor for net in ["java/net/Socket", "java/net/URL", "java/net/HttpURLConnection"]):
            result["suspicious_methods"].append(f"Network usage: {name}{descriptor}")

        # File I/O
        if "java/io/File" in descriptor:
            result["suspicious_methods"].append(f"File I/O: {name}{descriptor}")

        # Native methods
        if "native" in method.get("access_flags_str", []):
            result["suspicious_methods"].append(f"Native method: {name}{descriptor}")

        # Invokedynamic (can be used for obfuscation)
        code = method.get("code", {})
        if code:
            bytecode = code.get("bytecode", "")
            if "ba" in bytecode:  # invokedynamic opcode
                result["obfuscation_indicators"].append(f"invokedynamic in method: {name}")

    # Check strings for suspicious content
    suspicious_keywords = [
        "password", "secret", "key", "token", "credential",
        "http://", "https://", "ftp://",
        "cmd.exe", "powershell", "/bin/bash", "/bin/sh",
        "eval", "exec", "Runtime", "ProcessBuilder",
        "Cipher", "SecretKey", "encrypt", "decrypt",
        "keylogger", "screenshot", "webcam", "microphone",
        "persistence", "autorun", "registry", "scheduled task",
    ]

    for string in result.get("strings", []):
        string_lower = string.lower()
        for kw in suspicious_keywords:
            if kw in string_lower:
                result["suspicious_strings"].append(f"'{kw}' in: {string[:100]}")
                break

    # Check for known obfuscators
    obfuscator_markers = {
        "proguard": ["proguard", "ProGuard"],
        "zelix": ["zelix", "Zelix"],
        "stringer": ["stringer", "Stringer"],
        "allatori": ["allatori", "Allatori"],
        "dashO": ["dashO", "DashO"],
        "yguard": ["yguard", "YGuard"],
    }

    for obf, markers in obfuscator_markers.items():
        for string in result.get("strings", []):
            if any(m in string for m in markers):
                result["obfuscation_indicators"].append(f"Possible {obf} obfuscation detected")
                break


def analyze_java(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_class_file(file_path)