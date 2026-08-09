"""MALINFO — Configuration File Analysis (JSON, YAML, XML, INI, TOML, etc.)

Analysis of configuration files for malware C2 extraction and sensitive data.
"""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.config_analysis")

# Try to import optional dependencies
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import tomli
    TOML_AVAILABLE = True
except ImportError:
    TOML_AVAILABLE = False

try:
    import configparser
    INI_AVAILABLE = True
except ImportError:
    INI_AVAILABLE = False


def analyze_config(file_path: Path) -> dict:
    """
    Analyze configuration file.
    """
    result: dict = {
        "available": True,
        "format": "Configuration File",
        "config_type": "",
        "parsed": {},
        "structure": {},
        "sensitive_data": [],
        "urls": [],
        "ips": [],
        "domains": [],
        "emails": [],
        "keys_secrets": [],
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        result["entropy"] = round(shannon_entropy(data[:8192]), 3)

        ext = file_path.suffix.lower()

        if ext == ".json":
            result["config_type"] = "JSON"
            _analyze_json(data, result)
        elif ext in (".yaml", ".yml"):
            result["config_type"] = "YAML"
            _analyze_yaml(data, result)
        elif ext == ".xml":
            result["config_type"] = "XML"
            _analyze_xml(data, result)
        elif ext in (".ini", ".cfg", ".conf", ".config"):
            result["config_type"] = "INI"
            _analyze_ini(data, result)
        elif ext == ".toml":
            result["config_type"] = "TOML"
            _analyze_toml(data, result)
        elif ext in (".env", ".env.local", ".env.production"):
            result["config_type"] = "Environment"
            _analyze_env(data, result)
        else:
            # Try to detect by content
            _analyze_generic_config(data, result)

    except Exception as exc:
        logger.debug(f"Config analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_json(data: bytes, result: dict) -> None:
    """Analyze JSON configuration."""
    try:
        text = data.decode("utf-8", errors="ignore")
        parsed = json.loads(text)
        result["parsed"] = parsed
        result["structure"] = _get_json_structure(parsed)
        _extract_sensitive_from_dict(parsed, result)
    except json.JSONDecodeError as exc:
        result["errors"].append(f"Invalid JSON: {exc}")
    except Exception as exc:
        result["errors"].append(f"JSON analysis failed: {exc}")


def _analyze_yaml(data: bytes, result: dict) -> None:
    """Analyze YAML configuration."""
    if not YAML_AVAILABLE:
        result["errors"].append("PyYAML not installed")
        return

    try:
        text = data.decode("utf-8", errors="ignore")
        parsed = yaml.safe_load(text)
        result["parsed"] = parsed
        result["structure"] = _get_json_structure(parsed) if parsed else {}
        _extract_sensitive_from_dict(parsed, result)
    except yaml.YAMLError as exc:
        result["errors"].append(f"Invalid YAML: {exc}")
    except Exception as exc:
        result["errors"].append(f"YAML analysis failed: {exc}")


def _analyze_xml(data: bytes, result: dict) -> None:
    """Analyze XML configuration."""
    try:
        text = data.decode("utf-8", errors="ignore")
        root = ET.fromstring(text)
        result["parsed"] = _xml_to_dict(root)
        result["structure"] = _get_json_structure(result["parsed"])
        _extract_sensitive_from_dict(result["parsed"], result)
    except ET.ParseError as exc:
        result["errors"].append(f"Invalid XML: {exc}")
    except Exception as exc:
        result["errors"].append(f"XML analysis failed: {exc}")


def _analyze_ini(data: bytes, result: dict) -> None:
    """Analyze INI configuration."""
    if not INI_AVAILABLE:
        result["errors"].append("configparser not available")
        return

    try:
        text = data.decode("utf-8", errors="ignore")
        parser = configparser.ConfigParser()
        parser.read_string(text)

        parsed = {}
        for section in parser.sections():
            parsed[section] = dict(parser[section])

        result["parsed"] = parsed
        result["structure"] = _get_json_structure(parsed)
        _extract_sensitive_from_dict(parsed, result)
    except Exception as exc:
        result["errors"].append(f"INI analysis failed: {exc}")


def _analyze_toml(data: bytes, result: dict) -> None:
    """Analyze TOML configuration."""
    if not TOML_AVAILABLE:
        result["errors"].append("tomli not installed")
        return

    try:
        text = data.decode("utf-8", errors="ignore")
        parsed = tomli.loads(text)
        result["parsed"] = parsed
        result["structure"] = _get_json_structure(parsed)
        _extract_sensitive_from_dict(parsed, result)
    except Exception as exc:
        result["errors"].append(f"TOML analysis failed: {exc}")


def _analyze_env(data: bytes, result: dict) -> None:
    """Analyze .env file."""
    try:
        text = data.decode("utf-8", errors="ignore")
        parsed = {}
        for line in text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                parsed[key.strip()] = value.strip()

        result["parsed"] = parsed
        result["structure"] = _get_json_structure(parsed)
        _extract_sensitive_from_dict(parsed, result)
    except Exception as exc:
        result["errors"].append(f"ENV analysis failed: {exc}")


def _analyze_generic_config(data: bytes, result: dict) -> None:
    """Try to detect config format by content."""
    text = data.decode("utf-8", errors="ignore")

    # Try JSON
    try:
        parsed = json.loads(text)
        result["config_type"] = "JSON (detected)"
        result["parsed"] = parsed
        result["structure"] = _get_json_structure(parsed)
        _extract_sensitive_from_dict(parsed, result)
        return
    except Exception:
        pass

    # Try YAML
    if YAML_AVAILABLE:
        try:
            parsed = yaml.safe_load(text)
            if parsed:
                result["config_type"] = "YAML (detected)"
                result["parsed"] = parsed
                result["structure"] = _get_json_structure(parsed)
                _extract_sensitive_from_dict(parsed, result)
                return
        except Exception:
            pass

    # Try XML
    try:
        root = ET.fromstring(text)
        result["config_type"] = "XML (detected)"
        result["parsed"] = _xml_to_dict(root)
        result["structure"] = _get_json_structure(result["parsed"])
        _extract_sensitive_from_dict(result["parsed"], result)
        return
    except Exception:
        pass

    result["errors"].append("Could not determine config format")


def _xml_to_dict(element: ET.Element) -> dict:
    """Convert XML element to dict."""
    result = {}
    if element.attrib:
        result["@attributes"] = element.attrib
    if element.text and element.text.strip():
        result["#text"] = element.text.strip()

    for child in element:
        child_dict = _xml_to_dict(child)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_dict)
        else:
            result[child.tag] = child_dict

    return result


def _get_json_structure(obj: any, path: str = "", max_depth: int = 3, current_depth: int = 0) -> dict:
    """Get structure of JSON-like object."""
    if current_depth >= max_depth:
        return {"type": type(obj).__name__, "truncated": True}

    if isinstance(obj, dict):
        return {
            "type": "object",
            "keys": list(obj.keys())[:50],
            "children": {k: _get_json_structure(v, f"{path}.{k}", max_depth, current_depth + 1) for k, v in list(obj.items())[:20]}
        }
    elif isinstance(obj, list):
        return {
            "type": "array",
            "length": len(obj),
            "children": _get_json_structure(obj[0], f"{path}[0]", max_depth, current_depth + 1) if obj else {}
        }
    else:
        return {"type": type(obj).__name__, "value": str(obj)[:100]}


def _extract_sensitive_from_dict(obj: any, result: dict, path: str = "") -> None:
    """Recursively extract sensitive data from parsed config."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            _check_sensitive_key(key, value, new_path, result)
            _extract_sensitive_from_dict(value, result, new_path)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _extract_sensitive_from_dict(item, result, f"{path}[{i}]")


def _check_sensitive_key(key: str, value: any, path: str, result: dict) -> None:
    """Check if key/value contains sensitive data."""
    key_lower = key.lower()

    # Secrets/keys
    secret_keywords = [
        "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
        "access_key", "secret_key", "private_key", "public_key", "auth",
        "credential", "username", "user", "login", "session", "cookie",
        "jwt", "bearer", "oauth", "client_secret", "client_id",
        "encryption_key", "decryption_key", "signing_key", "hmac",
        "database_url", "db_password", "db_user", "redis_url",
        "aws_access", "aws_secret", "gcp_key", "azure_key",
        "ssh_key", "rsa_key", "dsa_key", "ecdsa_key",
    ]

    for sk in secret_keywords:
        if sk in key_lower:
            result["keys_secrets"].append({
                "path": path,
                "key": key,
                "type": sk,
                "value_preview": str(value)[:50] if value else "",
            })
            break

    # URLs
    if isinstance(value, str):
        import re
        urls = re.findall(r'https?://[^\s"\']+', value)
        for url in urls:
            result["urls"].append({"path": path, "url": url})

        # IPs
        ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b', value)
        for ip in ips:
            result["ips"].append({"path": path, "ip": ip})

        # Domains
        domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|biz|xyz|top|ru|cn|tk|cc|io|onion|gov|edu|in|co|me|club|site|online|link)\b', value, re.IGNORECASE)
        for domain in domains:
            result["domains"].append({"path": path, "domain": domain})

        # Emails
        emails = re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', value)
        for email in emails:
            result["emails"].append({"path": path, "email": email})

    # C2 patterns
    c2_keywords = [
        "c2", "command", "control", "beacon", "callback", "checkin",
        "gate", "panel", "cnc", "botnet", "implant", "agent",
    ]

    for c2k in c2_keywords:
        if c2k in key_lower:
            result["suspicious_indicators"].append(f"Possible C2 config: {path} (key: {key})")
            break


def analyze_config_file(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_config(file_path)