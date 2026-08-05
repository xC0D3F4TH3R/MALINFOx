"""
Public-facing reporting endpoint: lets any citizen report a suspected
malicious file, phishing URL, C2 IP, or malicious app for triage by
analysts — the "help government / help the public" feature. Deliberately
rate-limited and does not require identity disclosure (anonymous
reporting is allowed; contact info is optional so a reporter can be
followed up with if they choose).

In production, put this behind a public-facing reverse proxy with request
rate-limiting (e.g. nginx limit_req, or a WAF) — anonymous public intake
endpoints are an abuse target.

Automatically notifies CERT-In, Cyber Crime Cell, and other configured
agencies upon submission.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    HTTPException,
    UploadFile,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import CitizenReport, Sample
from app.routers.upload import _run_pipeline
from app.schemas import CitizenReportIn, CitizenReportOut
from app.services.agency_notification import (
    AgencyContact,
    AgencyNotificationService,
    AgencyType,
    get_notification_service,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/public/report", tags=["public-reporting"])


def _reference_code(report_id: str) -> str:
    return f"MALINFO-{report_id[:8].upper()}"


def _notify_agencies(
    report: CitizenReport,
    incident_type: str,
    severity: str,
    title: str,
    description: str,
    submitted_value: str | None = None,
    file_info: dict | None = None,
    iocs: list[dict] | None = None,
    sample_id: str | None = None,
):
    """Send notification to configured agencies"""
    try:
        notification_service = get_notification_service()
        notification_service.notify_agencies(
            report_id=report.id,
            reference_code=_reference_code(report.id),
            incident_type=incident_type,
            severity=severity,
            title=f"Citizen Report: {incident_type}",
            description=report.description,
            submitted_by=report.reporter_name or "Anonymous",
            submitted_contact=report.reporter_contact,
            submitted_value=submitted_value,
            iocs=iocs,
            analysis_summary=None,  # Will be updated after analysis
            risk_score=None,
            verdict=None,
            mitre_techniques=[],
            sample_id=sample_id,
            file_info=file_info,
            network_info=None,
            recommended_actions=[
                "Review submitted indicator for malicious activity",
                "Cross-reference with threat intelligence feeds",
                "Initiate takedown if malicious infrastructure identified",
                "Notify affected parties if data exposure detected",
            ],
        )
    except Exception:
        # Don't fail the report submission if notification fails
        pass


@router.post("/details", response_model=CitizenReportOut)
async def submit_report_details(payload: CitizenReportIn, db: AsyncSession = Depends(get_db)):
    """Report a URL, IP, or app (no file attached) — e.g. a suspicious link received via SMS/WhatsApp."""
    # Determine severity based on report type
    severity_map = {
        "url": "high",
        "ip": "high",
        "app": "medium",
    }
    severity = severity_map.get(payload.report_type, "medium")
    
    # Extract IOCs from submitted value
    iocs = []
    if payload.submitted_value:
        # Simple IOC extraction - in production use proper IOC extractor
        import re
        if re.match(r'^https?://', payload.submitted_value):
            iocs.append({"type": "url", "value": payload.submitted_value, "confidence": 0.7})
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', payload.submitted_value):
            iocs.append({"type": "ip", "value": payload.submitted_value, "confidence": 0.7})
        elif re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', payload.submitted_value):
            iocs.append({"type": "hash", "value": payload.submitted_value, "confidence": 0.8})

    report = CitizenReport(
        reporter_name=payload.reporter_name,
        reporter_contact=payload.reporter_contact,
        report_type=payload.report_type,
        description=payload.description,
        submitted_value=payload.submitted_value,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Notify agencies immediately
    _notify_agencies(
        report=report,
        incident_type=payload.report_type,
        severity=severity,
        title=f"Citizen Report: {payload.report_type}",
        description=payload.description,
        submitted_value=payload.submitted_value,
        iocs=iocs,
    )

    return CitizenReportOut(
        id=report.id, report_type=report.report_type, status=report.status,
        created_at=report.created_at, reference_code=_reference_code(report.id),
    )


@router.post("/file", response_model=CitizenReportOut)
async def submit_report_with_file(
    background_tasks: BackgroundTasks,
    description: str = Form(...),
    file: UploadFile = File(...),
    reporter_name: str | None = Form(None),
    reporter_contact: str | None = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Report a suspected malicious file — automatically triggers the full analysis pipeline."""
    if file.size and file.size > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB} MB limit")

    sample_id = str(uuid.uuid4())
    dest = settings.UPLOAD_DIR / f"{sample_id}__{file.filename}"
    with dest.open("wb") as out:
        shutil.copyfileobj(file.file, out)

    # Calculate file hashes
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()
    with dest.open("rb") as f:
        while chunk := f.read(8192):
            sha256_hash.update(chunk)
            sha1_hash.update(chunk)
            md5_hash.update(chunk)

    sample = Sample(
        id=sample_id,
        original_filename=file.filename or "unknown",
        stored_path=str(dest),
        file_size=dest.stat().st_size,
        sha256=sha256_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        md5=md5_hash.hexdigest(),
        source="citizen_report",
    )
    db.add(sample)

    # Determine severity - files get high severity by default
    severity = "high"

    # File info for agency notification
    file_info = {
        "filename": file.filename,
        "size": dest.stat().st_size,
        "sha256": sha256_hash.hexdigest(),
        "sha1": sha1_hash.hexdigest(),
        "md5": md5_hash.hexdigest(),
        "type": "file",
        "target_os": "unknown",
    }

    # IOCs from file
    iocs = [
        {"type": "hash", "value": sha256_hash.hexdigest(), "confidence": 0.9},
        {"type": "hash", "value": sha1_hash.hexdigest(), "confidence": 0.8},
        {"type": "hash", "value": md5_hash.hexdigest(), "confidence": 0.7},
    ]

    report = CitizenReport(
        reporter_name=reporter_name,
        reporter_contact=reporter_contact,
        report_type="file",
        description=description,
        sample_id=sample_id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    # Notify agencies immediately
    _notify_agencies(
        report=report,
        incident_type="file",
        severity=severity,
        title="Citizen Report: Malicious File",
        description=description,
        submitted_value=file.filename,
        file_info=file_info,
        iocs=iocs,
        sample_id=sample_id,
    )

    background_tasks.add_task(_run_pipeline, sample_id, dest)

    return CitizenReportOut(
        id=report.id, report_type=report.report_type, status=report.status,
        created_at=report.created_at, reference_code=_reference_code(report.id),
    )


@router.get("/{report_id}/status")
async def check_report_status(report_id: str, db: AsyncSession = Depends(get_db)):
    report = await db.get(CitizenReport, report_id)
    if report is None:
        raise HTTPException(404, "Report not found — check your reference code")

    sample_status = None
    if report.sample_id:
        sample = await db.get(Sample, report.sample_id)
        if sample:
            sample_status = {"status": sample.status, "verdict": sample.verdict, "risk_score": sample.risk_score}

    return {
        "reference_code": _reference_code(report.id),
        "status": report.status,
        "submitted_at": report.created_at,
        "analysis": sample_status,
    }
