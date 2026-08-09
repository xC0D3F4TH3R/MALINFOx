"""MALINFO — Email Analysis (EML, MSG)

Analysis of email files with header analysis, attachment extraction, and phishing detection.
"""
from __future__ import annotations

import logging
import re
from email import policy
from email.parser import BytesParser
from typing import TYPE_CHECKING

from app.analysis.strings_entropy import shannon_entropy

if TYPE_CHECKING:
    from email.message import EmailMessage
    from pathlib import Path

logger = logging.getLogger("malinfo.email_analysis")


def analyze_email(file_path: Path) -> dict:
    """
    Analyze email file (EML or MSG).
    """
    result: dict = {
        "available": True,
        "format": "unknown",
        "email_type": "",
        "headers": {},
        "header_analysis": {},
        "body": {},
        "attachments": [],
        "embedded_objects": [],
        "urls": [],
        "ips": [],
        "domains": [],
        "emails": [],
        "phishing_indicators": [],
        "spf_dkim_dmarc": {},
        "suspicious_indicators": [],
        "entropy": 0.0,
        "errors": [],
    }

    try:
        ext = file_path.suffix.lower()

        if ext == ".eml":
            return _analyze_eml(file_path, result)
        elif ext == ".msg":
            return _analyze_msg(file_path, result)
        else:
            result["error"] = f"Unsupported email format: {ext}"
            result["available"] = False

    except Exception as exc:
        logger.debug(f"Email analysis failed: {exc}")
        result["error"] = str(exc)
        result["available"] = False

    return result


def _analyze_eml(file_path: Path, result: dict) -> dict:
    """Analyze EML file (RFC 5322)."""
    result["format"] = "EML (RFC 5322)"
    result["email_type"] = "EML"

    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()

        result["entropy"] = round(shannon_entropy(raw_data[:8192]), 3)

        # Parse email
        msg = BytesParser(policy=policy.default).parsebytes(raw_data)

        # Extract headers
        result["headers"] = dict(msg.items())
        result["header_analysis"] = _analyze_headers(msg)

        # Extract body
        result["body"] = _extract_body(msg)

        # Extract attachments
        result["attachments"] = _extract_attachments(msg)

        # Extract URLs, IPs, domains, emails from body and headers
        full_text = str(msg)
        result["urls"] = _extract_urls(full_text)
        result["ips"] = _extract_ips(full_text)
        result["domains"] = _extract_domains(full_text)
        result["emails"] = _extract_emails(full_text)

        # SPF/DKIM/DMARC analysis
        result["spf_dkim_dmarc"] = _analyze_spf_dkim_dmarc(msg)

        # Phishing detection
        result["phishing_indicators"] = _detect_phishing(msg, result)

        # Suspicious indicators
        _check_suspicious_email(result)

    except Exception as exc:
        result["errors"].append(f"EML parsing failed: {exc}")

    return result


def _analyze_msg(file_path: Path, result: dict) -> dict:
    """Analyze MSG file (Outlook OLE)."""
    result["format"] = "MSG (Outlook OLE)"
    result["email_type"] = "MSG"

    try:
        import olefile

        with open(file_path, "rb") as f:
            raw_data = f.read()

        result["entropy"] = round(shannon_entropy(raw_data[:8192]), 3)

        ole = olefile.OleFileIO(str(file_path))

        # MSG structure - main streams
        # __substg1.0_XXXX properties
        # We'll extract what we can

        # Try to get subject, sender, etc. from known property tags
        # This is a simplified extraction
        result["headers"] = {}
        result["body"] = {"text": "", "html": ""}
        result["attachments"] = []

        # List streams for debugging
        streams = ole.listdir()
        result["ole_streams"] = ["/".join(s) for s in streams]

        # Try to extract using extract-msg if available
        try:
            import extract_msg
            msg = extract_msg.Message(str(file_path))
            msg.parse()

            result["headers"] = {
                "Subject": msg.subject,
                "From": msg.sender,
                "To": msg.to,
                "Cc": msg.cc,
                "Date": msg.date,
                "Message-ID": msg.message_id,
            }
            result["body"] = {
                "text": msg.body,
                "html": msg.html_body,
            }

            # Attachments
            for att in msg.attachments:
                result["attachments"].append({
                    "filename": att.long_filename or att.short_filename,
                    "size": len(att.data) if att.data else 0,
                    "content_type": att.mimetype,
                    "data_preview": att.data[:100].hex() if att.data else "",
                })

            # Full text for extraction
            full_text = f"{msg.subject or ''} {msg.body or ''} {msg.html_body or ''}"
            result["urls"] = _extract_urls(full_text)
            result["ips"] = _extract_ips(full_text)
            result["domains"] = _extract_domains(full_text)
            result["emails"] = _extract_emails(full_text)

            # Phishing detection
            class MockMsg:
                def __init__(self, headers, body):
                    self._headers = headers
                    self._body = body
                def get(self, key, default=""):
                    return self._headers.get(key, default)
                def __str__(self):
                    return str(self._body)

            mock_msg = MockMsg(result["headers"], full_text)
            result["phishing_indicators"] = _detect_phishing(mock_msg, result)

        except ImportError:
            result["errors"].append("extract-msg not installed for full MSG parsing")

        ole.close()

    except Exception as exc:
        result["errors"].append(f"MSG parsing failed: {exc}")

    return result


def _analyze_headers(msg: EmailMessage) -> dict:
    """Analyze email headers for anomalies."""
    analysis = {
        "received_chain": [],
        "routing_anomalies": [],
        "authentication_results": {},
        "x_headers": {},
        "suspicious_headers": [],
    }

    # Received chain
    received = msg.get_all("Received", [])
    for r in received:
        analysis["received_chain"].append(r[:500])

    # Authentication-Results
    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        analysis["authentication_results"]["raw"] = auth_results[:1000]
        # Parse SPF/DKIM/DMARC
        for auth_type in ["spf", "dkim", "dmarc"]:
            match = re.search(rf"{auth_type}=(\w+)", auth_results, re.IGNORECASE)
            if match:
                analysis["authentication_results"][auth_type] = match.group(1)

    # X-Headers
    for key, value in msg.items():
        if key.lower().startswith("x-"):
            analysis["x_headers"][key] = value[:500]

    # Suspicious header patterns
    suspicious_patterns = [
        (r"X-Mailer:.*(php|perl|python|ruby|mass|bulk|mailer)", "Mass mailer detected"),
        (r"X-Priority:\s*1", "High priority (urgency tactic)"),
        (r"X-MSMail-Priority:\s*High", "High priority (urgency tactic)"),
        (r"Importance:\s*high", "High importance (urgency tactic)"),
        (r"X-Originating-IP:\s*(\d+\.\d+\.\d+\.\d+)", "Originating IP"),
    ]

    for pattern, desc in suspicious_patterns:
        for key, value in msg.items():
            if re.search(pattern, f"{key}: {value}", re.IGNORECASE):
                analysis["suspicious_headers"].append(desc)

    return analysis


def _extract_body(msg: EmailMessage) -> dict:
    """Extract text and HTML body parts."""
    body = {"text": "", "html": "", "parts": []}

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)

            if payload:
                text = payload.decode("utf-8", errors="ignore")
                if content_type == "text/plain":
                    body["text"] += text
                    body["parts"].append({"type": "text/plain", "size": len(text)})
                elif content_type == "text/html":
                    body["html"] += text
                    body["parts"].append({"type": "text/html", "size": len(text)})
                else:
                    body["parts"].append({"type": content_type, "size": len(payload)})
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="ignore")
            content_type = msg.get_content_type()
            if content_type == "text/html":
                body["html"] = text
            else:
                body["text"] = text
            body["parts"].append({"type": content_type, "size": len(text)})

    return body


def _extract_attachments(msg: EmailMessage) -> list[dict]:
    """Extract attachments from email."""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = part.get("Content-Disposition", "")
            if "attachment" in disposition.lower():
                filename = part.get_filename()
                payload = part.get_payload(decode=True)
                content_type = part.get_content_type()

                if payload:
                    attachments.append({
                        "filename": filename or "unknown",
                        "content_type": content_type,
                        "size": len(payload),
                        "entropy": round(shannon_entropy(payload[:8192]), 3),
                        "magic": payload[:8].hex() if len(payload) >= 8 else "",
                        "content_id": part.get("Content-ID", ""),
                    })

    return attachments


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text."""
    url_pattern = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+')
    urls = url_pattern.findall(text)
    # Deduplicate
    seen = set()
    unique = []
    for url in urls:
        url_lower = url.lower()
        if url_lower not in seen:
            seen.add(url_lower)
            unique.append(url)
    return unique[:100]


def _extract_ips(text: str) -> list[str]:
    """Extract IP addresses from text."""
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
    ips = ip_pattern.findall(text)
    return list(set(ips))[:100]


def _extract_domains(text: str) -> list[str]:
    """Extract domains from text."""
    domain_pattern = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|info|biz|xyz|top|ru|cn|tk|cc|io|onion|gov|edu|in|co|me|club|site|online|link)\b',
        re.IGNORECASE
    )
    domains = domain_pattern.findall(text)
    return list(set(domains))[:100]


def _extract_emails(text: str) -> list[str]:
    """Extract email addresses from text."""
    email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
    emails = email_pattern.findall(text)
    return list(set(emails))[:100]


def _analyze_spf_dkim_dmarc(msg: EmailMessage) -> dict:
    """Analyze SPF, DKIM, DMARC results."""
    result = {
        "spf": "none",
        "dkim": "none",
        "dmarc": "none",
        "details": {},
    }

    auth_results = msg.get("Authentication-Results", "")
    if auth_results:
        for auth_type in ["spf", "dkim", "dmarc"]:
            match = re.search(rf"{auth_type}=(\w+)", auth_results, re.IGNORECASE)
            if match:
                result[auth_type] = match.group(1)
            result["details"][auth_type] = auth_results[:500]

    # Also check Received-SPF header
    received_spf = msg.get("Received-SPF", "")
    if received_spf and result["spf"] == "none":
        match = re.search(r"(pass|fail|softfail|neutral|none|temperror|permerror)", received_spf, re.IGNORECASE)
        if match:
            result["spf"] = match.group(1)

    return result


def _detect_phishing(msg: EmailMessage, email_result: dict) -> list[str]:
    """Detect phishing indicators."""
    indicators = []

    # Subject analysis
    subject = msg.get("Subject", "").lower()
    phishing_subjects = [
        "urgent", "immediate", "action required", "verify", "confirm",
        "suspended", "locked", "expired", "security alert", "unusual activity",
        "password", "login", "account", "update", "payment", "invoice",
        "refund", "tax", "bank", "paypal", "amazon", "apple", "microsoft",
        "google", "facebook", "linkedin", "dropbox", "onedrive",
    ]
    for kw in phishing_subjects:
        if kw in subject:
            indicators.append(f"Phishing keyword in subject: {kw}")

    # From address vs display name mismatch
    from_header = msg.get("From", "")
    if from_header:
        # Check for display name spoofing
        if "<" in from_header and ">" in from_header:
            display = from_header.split("<")[0].strip().strip('"')
            addr = from_header.split("<")[1].split(">")[0].strip()
            # Check if display name looks like a known brand but email doesn't match
            brands = ["paypal", "amazon", "apple", "microsoft", "google", "facebook", "bank", "support", "security", "admin"]
            for brand in brands:
                if brand in display.lower() and brand not in addr.lower():
                    indicators.append(f"Display name spoofing: '{display}' but email is '{addr}'")

    # Reply-To mismatch
    reply_to = msg.get("Reply-To", "")
    from_addr = msg.get("From", "")
    if reply_to and from_addr:
        if "<" in from_addr:
            from_email = from_addr.split("<")[1].split(">")[0].strip()
        else:
            from_email = from_addr.strip()
        if "<" in reply_to:
            reply_email = reply_to.split("<")[1].split(">")[0].strip()
        else:
            reply_email = reply_to.strip()
        if from_email.lower() != reply_email.lower():
            indicators.append(f"Reply-To mismatch: From={from_email}, Reply-To={reply_email}")

    # URLs in body
    body_text = email_result.get("body", {}).get("text", "") + email_result.get("body", {}).get("html", "")
    urls = _extract_urls(body_text)
    for url in urls:
        # Check for URL shorteners
        shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly"]
        for short in shorteners:
            if short in url:
                indicators.append(f"URL shortener detected: {url}")
        # Check for suspicious TLDs
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".date"]
        for tld in suspicious_tlds:
            if tld in url:
                indicators.append(f"Suspicious TLD in URL: {url}")

    # Attachment analysis
    for att in email_result.get("attachments", []):
        filename = att.get("filename", "").lower()
        if filename.endswith((".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".msi", ".jar", ".vbs", ".js", ".wsf")):
            indicators.append(f"Dangerous attachment type: {filename}")
        if filename.endswith((".zip", ".rar", ".7z", ".gz")):
            indicators.append(f"Archive attachment (may contain malware): {filename}")
        if filename.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")):
            # Could have embedded exploits
            indicators.append(f"Document attachment (check for exploits): {filename}")

    # SPF/DKIM/DMARC failures
    auth = email_result.get("spf_dkim_dmarc", {})
    if auth.get("spf") in ("fail", "softfail"):
        indicators.append("SPF check failed")
    if auth.get("dkim") == "fail":
        indicators.append("DKIM check failed")
    if auth.get("dmarc") == "fail":
        indicators.append("DMARC check failed")

    return indicators


def _check_suspicious_email(result: dict) -> None:
    """Check for general suspicious indicators."""
    # Many attachments
    if len(result.get("attachments", [])) > 5:
        result["suspicious_indicators"].append(f"Many attachments ({len(result['attachments'])})")

    # High entropy attachments
    for att in result.get("attachments", []):
        if att.get("entropy", 0) > 7.5:
            result["suspicious_indicators"].append(f"High entropy attachment: {att.get('filename')} ({att.get('entropy')})")

    # Many URLs
    if len(result.get("urls", [])) > 10:
        result["suspicious_indicators"].append(f"Many URLs in email ({len(result['urls'])})")

    # No authentication
    auth = result.get("spf_dkim_dmarc", {})
    if all(v == "none" for v in [auth.get("spf"), auth.get("dkim"), auth.get("dmarc")]):
        result["suspicious_indicators"].append("No email authentication (SPF/DKIM/DMARC)")

def analyze_email_file(file_path: Path) -> dict:
    """Main entry point."""
    return analyze_email(file_path)