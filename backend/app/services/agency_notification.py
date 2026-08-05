"""
MALINFO — Agency Notification Service

Formats and sends structured incident reports to configured agencies
(CERT-In, Cyber Crime Cell, Law Enforcement, etc.) via email.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any

from app.config import settings

logger = logging.getLogger("malinfo.agency_notification")


class AgencyType(Enum):
    """Types of agencies to notify"""
    CERT_IN = "cert_in"
    CYBER_CRIME_CELL = "cyber_crime_cell"
    LAW_ENFORCEMENT = "law_enforcement"
    CUSTOM = "custom"


@dataclass
class AgencyContact:
    """Agency contact information"""
    agency_type: AgencyType
    name: str
    email: str
    priority: str = "high"  # high, medium, low
    requires_formal_format: bool = True


@dataclass
class IncidentReport:
    """Structured incident report for agency notification"""
    reference_code: str
    incident_type: str  # file, url, ip, app, network, malware
    severity: str  # critical, high, medium, low
    title: str
    description: str
    submitted_by: str  # reporter name or "Anonymous"
    submitted_contact: str | None
    submitted_value: str | None  # URL, IP, hash, filename
    iocs: list[dict] = field(default_factory=list)
    analysis_summary: str | None = None
    risk_score: int | None = None
    verdict: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    submitted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    report_id: str | None = None
    sample_id: str | None = None
    file_info: dict | None = None  # filename, size, hash, type
    network_info: dict | None = None  # connections, C2, DNS
    recommended_actions: list[str] = field(default_factory=list)


# Default agency contacts (can be overridden via env/config)
DEFAULT_AGENCIES = [
    AgencyContact(
        agency_type=AgencyType.CERT_IN,
        name="CERT-In (Indian Computer Emergency Response Team)",
        email="incident@cert-in.org.in",
        priority="critical",
        requires_formal_format=True,
    ),
    AgencyContact(
        agency_type=AgencyType.CYBER_CRIME_CELL,
        name="National Cyber Crime Reporting Portal",
        email="cybercrime@gov.in",
        priority="critical",
        requires_formal_format=True,
    ),
    AgencyContact(
        agency_type=AgencyType.LAW_ENFORCEMENT,
        name="State Cyber Crime Cell",
        email="cybercell@police.gov.in",
        priority="high",
        requires_formal_format=True,
    ),
    AgencyContact(
        agency_type=AgencyType.CUSTOM,
        name="MALINFO Central Notification",
        email=settings.AGENCY_NOTIFICATION_EMAIL,
        priority="high",
        requires_formal_format=False,
    ),
]


class AgencyNotificationService:
    """Service for sending formatted incident reports to agencies"""

    def __init__(self):
        self.smtp_host = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD
        self.smtp_tls = settings.SMTP_TLS
        self.from_email = settings.NOTIFICATION_FROM_EMAIL
        self.default_recipient = settings.AGENCY_NOTIFICATION_EMAIL

    def _get_smtp_connection(self) -> smtplib.SMTP | None:
        """Create SMTP connection"""
        if not self.smtp_host or not self.smtp_user:
            logger.warning("SMTP not configured, skipping email notification")
            return None

        try:
            if self.smtp_tls:
                conn = smtplib.SMTP(self.smtp_host, self.smtp_port)
                conn.starttls()
            else:
                conn = smtplib.SMTP(self.smtp_host, self.smtp_port)

            conn.login(self.smtp_user, self.smtp_password)
            return conn
        except Exception as e:
            logger.exception(f"Failed to connect to SMTP: {e}")
            return None

    def _format_incident_email(self, incident: IncidentReport, agency: AgencyContact) -> MIMEMultipart:
        """Format incident report as structured email"""

        msg = MIMEMultipart()
        msg["Subject"] = f"[MALINFO-{incident.severity.upper()}] {incident.title} - {incident.reference_code}"
        msg["From"] = self.from_email
        msg["To"] = agency.email

        # Build email body
        if agency.requires_formal_format:
            body = self._build_formal_report(incident, agency)
        else:
            body = self._build_simple_report(incident)

        msg.attach(MIMEText(body, "plain", "utf-8"))
        return msg

    def _build_formal_report(self, incident: IncidentReport, agency: AgencyContact) -> str:
        """Build formal structured report for government agencies"""

        lines = [
            "=" * 80,
            "MALINFO INCIDENT REPORT",
            "=" * 80,
            "",
            f"Report Reference: {incident.reference_code}",
            f"Agency: {agency.name}",
            f"Date/Time (UTC): {incident.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Report ID: {incident.report_id or 'N/A'}",
            "",
            "INCIDENT CLASSIFICATION",
            "-" * 40,
            f"Type: {incident.incident_type.upper()}",
            f"Severity: {incident.severity.upper()}",
            f"Risk Score: {incident.risk_score or 'N/A'}/100",
            f"Verdict: {incident.verdict or 'PENDING'}",
            "",
            "SUBMITTER INFORMATION",
            "-" * 40,
            f"Submitted By: {incident.submitted_by}",
            f"Contact: {incident.submitted_contact or 'Anonymous/Not Provided'}",
            f"Reference Code: {incident.reference_code}",
            "",
            "INCIDENT DETAILS",
            "-" * 40,
            f"Title: {incident.title}",
            f"Description: {incident.description}",
        ]

        if incident.submitted_value:
            lines.extend([
                "",
                "SUBMITTED INDICATOR",
                "-" * 40,
                f"Value: {incident.submitted_value}",
            ])

        if incident.file_info:
            lines.extend([
                "",
                "FILE INFORMATION",
                "-" * 40,
                f"Filename: {incident.file_info.get('filename', 'N/A')}",
                f"Size: {incident.file_info.get('size', 'N/A')} bytes",
                f"SHA256: {incident.file_info.get('sha256', 'N/A')}",
                f"MD5: {incident.file_info.get('md5', 'N/A')}",
                f"SHA1: {incident.file_info.get('sha1', 'N/A')}",
                f"File Type: {incident.file_info.get('type', 'N/A')}",
                f"Target OS: {incident.file_info.get('target_os', 'N/A')}",
            ])

        if incident.iocs:
            lines.extend([
                "",
                "INDICATORS OF COMPROMISE (IOCs)",
                "-" * 40,
            ])
            for ioc in incident.iocs:
                lines.append(f"  • {ioc.get('type', 'UNKNOWN').upper()}: {ioc.get('value', 'N/A')} (Confidence: {ioc.get('confidence', 'N/A')})")

        if incident.mitre_techniques:
            lines.extend([
                "",
                "MITRE ATT&CK TECHNIQUES",
                "-" * 40,
            ])
            for tech in incident.mitre_techniques:
                lines.append(f"  • {tech}")

        if incident.network_info:
            lines.extend([
                "",
                "NETWORK ANALYSIS",
                "-" * 40,
            ])
            if incident.network_info.get("connections"):
                for conn in incident.network_info["connections"][:20]:
                    lines.append(f"  • {conn.get('protocol', 'TCP')} {conn.get('src_ip', '')}:{conn.get('src_port', '')} -> {conn.get('dst_ip', '')}:{conn.get('dst_port', '')} ({conn.get('status', '')})")
            if incident.network_info.get("dns_queries"):
                for dns in incident.network_info["dns_queries"][:20]:
                    lines.append(f"  • DNS {dns.get('type', 'A')}: {dns.get('query', '')} -> {', '.join(dns.get('answers', []))}")

        if incident.analysis_summary:
            lines.extend([
                "",
                "ANALYSIS SUMMARY",
                "-" * 40,
                incident.analysis_summary,
            ])

        if incident.recommended_actions:
            lines.extend([
                "",
                "RECOMMENDED ACTIONS",
                "-" * 40,
            ])
            for i, action in enumerate(incident.recommended_actions, 1):
                lines.append(f"  {i}. {action}")

        lines.extend([
            "",
            "=" * 80,
            "END OF REPORT",
            f"Generated by MALINFO Platform at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "This is an automated report. For queries, contact MALINFO support.",
            "=" * 80,
        ])

        return "\n".join(lines)

    def _build_simple_report(self, incident: IncidentReport) -> str:
        """Build simple report for internal/custom notifications"""

        lines = [
            f"MALINFO Incident Notification: {incident.reference_code}",
            f"Severity: {incident.severity.upper()}",
            f"Type: {incident.incident_type}",
            f"Title: {incident.title}",
            f"Description: {incident.description}",
            f"Submitted: {incident.submitted_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"Reporter: {incident.submitted_by}",
            f"Contact: {incident.submitted_contact or 'Anonymous'}",
        ]

        if incident.submitted_value:
            lines.append(f"Indicator: {incident.submitted_value}")

        if incident.file_info:
            lines.append(f"File: {incident.file_info.get('filename', 'N/A')} ({incident.file_info.get('sha256', 'N/A')})")

        if incident.iocs:
            lines.append(f"IOCs Found: {len(incident.iocs)}")

        if incident.mitre_techniques:
            lines.append(f"MITRE Techniques: {', '.join(incident.mitre_techniques[:10])}")

        lines.append(f"\nView full report: https://malinfo.yourdomain.gov/public/report/{incident.report_id}/status")

        return "\n".join(lines)

    def send_notification(self, incident: IncidentReport, agencies: list[AgencyContact] | None = None) -> dict:
        """Send incident notification to specified agencies"""

        if agencies is None:
            agencies = DEFAULT_AGENCIES

        conn = self._get_smtp_connection()
        if not conn:
            logger.warning("SMTP not available, logging notification instead")
            self._log_notification(incident, agencies)
            return {"sent": False, "reason": "SMTP not configured"}

        results = {"sent": [], "failed": []}

        try:
            for agency in agencies:
                try:
                    msg = self._format_incident_email(incident, agency)
                    conn.send_message(msg)
                    results["sent"].append(agency.name)
                    logger.info(f"Incident {incident.reference_code} sent to {agency.name} ({agency.email})")
                except Exception as e:
                    results["failed"].append({"agency": agency.name, "error": str(e)})
                    logger.exception(f"Failed to send to {agency.name}: {e}")

        finally:
            try:
                conn.quit()
            except Exception:
                pass

        return results

    def _log_notification(self, incident: IncidentReport, agencies: list[AgencyContact]):
        """Log notification when email not available"""
        logger.info(
            f"NOTIFICATION (no SMTP): {incident.reference_code} | "
            f"Severity: {incident.severity} | Type: {incident.incident_type} | "
            f"Agencies: {[a.name for a in agencies]}"
        )

    def notify_agencies(
        self,
        report_id: str,
        reference_code: str,
        incident_type: str,
        severity: str,
        title: str,
        description: str,
        submitted_by: str,
        submitted_contact: str | None,
        submitted_value: str | None = None,
        iocs: list[dict] | None = None,
        analysis_summary: str | None = None,
        risk_score: int | None = None,
        verdict: str | None = None,
        mitre_techniques: list[str] | None = None,
        sample_id: str | None = None,
        file_info: dict | None = None,
        network_info: dict | None = None,
        recommended_actions: list[str] | None = None,
        agencies: list[AgencyContact] | None = None,
    ) -> dict:
        """Convenience method to build and send notification"""

        incident = IncidentReport(
            reference_code=reference_code,
            incident_type=incident_type,
            severity=severity,
            title=title,
            description=description,
            submitted_by=submitted_by,
            submitted_contact=submitted_contact,
            submitted_value=submitted_value,
            iocs=iocs or [],
            analysis_summary=analysis_summary,
            risk_score=risk_score,
            verdict=verdict,
            mitre_techniques=mitre_techniques or [],
            report_id=report_id,
            sample_id=sample_id,
            file_info=file_info,
            network_info=network_info,
            recommended_actions=recommended_actions or [],
        )

        return self.send_notification(incident, agencies)


# Singleton instance
_notification_service: AgencyNotificationService | None = None


def get_notification_service() -> AgencyNotificationService:
    """Get global notification service instance"""
    global _notification_service
    if _notification_service is None:
        _notification_service = AgencyNotificationService()
    return _notification_service