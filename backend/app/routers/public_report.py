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
"""
from __future__ import annotations

import shutil
import uuid

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

router = APIRouter(prefix="/public/report", tags=["public-reporting"])


def _reference_code(report_id: str) -> str:
    return f"MALINFO-{report_id[:8].upper()}"


@router.post("/details", response_model=CitizenReportOut)
async def submit_report_details(payload: CitizenReportIn, db: AsyncSession = Depends(get_db)):
    """Report a URL, IP, or app (no file attached) — e.g. a suspicious link received via SMS/WhatsApp."""
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
    with open(dest, "wb") as out:
        shutil.copyfileobj(file.file, out)

    sample = Sample(
        id=sample_id,
        original_filename=file.filename or "unknown",
        stored_path=str(dest),
        file_size=dest.stat().st_size,
        sha256="", sha1="", md5="",
        source="citizen_report",
    )
    db.add(sample)

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
