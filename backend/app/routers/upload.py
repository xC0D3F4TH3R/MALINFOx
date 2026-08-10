from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile

from app.analysis.pipeline import run_static_analysis
from app.config import settings
from app.database import get_db
from app.models import IOC, AnalysisStatus, Sample, Verdict
from app.reporting.report_generator import (
    build_full_report,
    render_html_report,
    save_report,
)
from app.sandbox.orchestrator import detonate_sample
from app.schemas import UploadResponse
from app.security_upload import (
    get_safe_destination_path,
    validate_upload_file,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/upload", tags=["upload"])


@router.post("", response_model=UploadResponse)
async def upload_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    # Comprehensive file validation
    is_valid, error, file_info = await validate_upload_file(file, settings.UPLOAD_DIR)

    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

    # Get safe destination path
    try:
        dest = get_safe_destination_path(settings.UPLOAD_DIR, file_info["safe_filename"])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    # Move validated file from temp to final location
    temp_path = Path(file_info["temp_path"])
    try:
        shutil.move(str(temp_path), str(dest))
    except Exception as e:
        # Cleanup temp file on error
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}") from e

    sample_id = str(uuid.uuid4())

    sample = Sample(
        id=sample_id,
        original_filename=file.filename or "unknown",
        stored_path=str(dest),
        file_size=dest.stat().st_size,
        sha256="", sha1="", md5="",
        status=AnalysisStatus.QUEUED,
        source="manual_upload",
    )
    db.add(sample)
    await db.commit()

    background_tasks.add_task(_run_pipeline, sample_id, dest)

    return UploadResponse(sample_id=sample_id, status="queued", message="Analysis started")


async def _run_pipeline(sample_id: str, file_path: Path) -> None:
    """
    Runs in the background after the HTTP response returns: static analysis
    now, dynamic sandbox + network forensics if enabled. Uses its own DB
    session since it executes outside the request lifecycle.
    """
    from app.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        sample = await db.get(Sample, sample_id)
        if sample is None:
            return

        sample.status = AnalysisStatus.STATIC_RUNNING
        await db.commit()

        static_report = run_static_analysis(file_path)

        sample.sha256 = static_report["hashes"]["sha256"]
        sample.sha1 = static_report["hashes"]["sha1"]
        sample.md5 = static_report["hashes"]["md5"]
        sample.ssdeep = static_report["hashes"].get("ssdeep")
        sample.file_type = static_report["file_type"]
        sample.mime_type = static_report["mime_type"]
        sample.target_os = static_report["target_os"]
        sample.static_report = static_report
        sample.risk_score = static_report["risk_score"]
        sample.verdict = Verdict(static_report["verdict"])
        sample.status = AnalysisStatus.STATIC_DONE

        for ioc in static_report.get("iocs", []):
            db.add(IOC(
                sample_id=sample.id,
                ioc_type=ioc["ioc_type"],
                value=ioc["value"],
                context=ioc.get("context"),
                confidence=ioc["confidence"],
            ))
        await db.commit()

        sandbox_report = None
        if settings.SANDBOX_ENABLED:
            sample.status = AnalysisStatus.SANDBOX_RUNNING
            await db.commit()
            sandbox_report = await detonate_sample(file_path, sample.target_os)
            sample.sandbox_report = sandbox_report
            await db.commit()

        network_report = None
        if sandbox_report and sandbox_report.get("pcap_path"):
            from app.network_forensics.pcap_analyzer import analyze_pcap
            sample.status = AnalysisStatus.NETWORK_ANALYSIS
            await db.commit()
            network_report = analyze_pcap(Path(sandbox_report["pcap_path"]))
            sample.network_report = network_report
            await db.commit()

        from app.analysis.risk_scoring import merge_dynamic_score
        final_score = merge_dynamic_score(
            {"risk_score": sample.risk_score, "reasons": static_report["risk_reasons"]},
            sandbox_report, network_report,
        )
        sample.risk_score = final_score["risk_score"]
        sample.verdict = Verdict(final_score["verdict"])

        full_report = build_full_report(sample, static_report, sandbox_report, network_report)
        html = render_html_report(full_report)
        save_report(sample.id, full_report, html)

        sample.status = AnalysisStatus.COMPLETE
        await db.commit()