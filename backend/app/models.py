from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class Verdict(str, enum.Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class AnalysisStatus(str, enum.Enum):
    QUEUED = "queued"
    STATIC_RUNNING = "static_running"
    STATIC_DONE = "static_done"
    SANDBOX_QUEUED = "sandbox_queued"
    SANDBOX_RUNNING = "sandbox_running"
    NETWORK_ANALYSIS = "network_analysis"
    COMPLETE = "complete"
    FAILED = "failed"


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    original_filename: Mapped[str] = mapped_column(String(512))
    stored_path: Mapped[str] = mapped_column(String(1024))
    file_size: Mapped[int] = mapped_column(default=0)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    sha1: Mapped[str] = mapped_column(String(40))
    md5: Mapped[str] = mapped_column(String(32), index=True)
    ssdeep: Mapped[str | None] = mapped_column(String(256), nullable=True)
    file_type: Mapped[str] = mapped_column(String(128), default="unknown")
    mime_type: Mapped[str] = mapped_column(String(128), default="unknown")
    target_os: Mapped[str] = mapped_column(String(32), default="unknown")  # windows/linux/android/macos/ios

    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus), default=AnalysisStatus.QUEUED
    )
    verdict: Mapped[Verdict] = mapped_column(Enum(Verdict), default=Verdict.UNKNOWN)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100

    submitted_by: Mapped[str] = mapped_column(String(128), default="analyst")
    source: Mapped[str] = mapped_column(String(32), default="manual_upload")
    # manual_upload | citizen_report | gateway_intercept | scheduled_watch | monitor_intercept

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow
    )

    static_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sandbox_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    network_report: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    iocs: Mapped[list[IOC]] = relationship(back_populates="sample", cascade="all, delete-orphan")


class IOC(Base):
    """Indicator of Compromise extracted from a sample (IP, domain, URL, C2, mutex, etc.)"""

    __tablename__ = "iocs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    sample_id: Mapped[str] = mapped_column(ForeignKey("samples.id"))
    sample: Mapped[Sample] = relationship(back_populates="iocs")

    ioc_type: Mapped[str] = mapped_column(String(32))  # ip | domain | url | c2 | mutex | registry_key | email
    value: Mapped[str] = mapped_column(String(1024), index=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)  # 0-1
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)


class CitizenReport(Base):
    """Public-facing 'Report a malicious file / C2 server' submissions."""

    __tablename__ = "citizen_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    reporter_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reporter_contact: Mapped[str | None] = mapped_column(String(256), nullable=True)  # optional / anonymous allowed
    report_type: Mapped[str] = mapped_column(String(32))  # file | url | ip | app
    description: Mapped[str] = mapped_column(Text)
    submitted_value: Mapped[str | None] = mapped_column(String(2048), nullable=True)  # URL/IP/app id if not a file
    sample_id: Mapped[str | None] = mapped_column(ForeignKey("samples.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="received")  # received|triaging|confirmed|dismissed
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=dt.datetime.utcnow)
