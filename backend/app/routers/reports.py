from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import or_, select

from app.config import settings
from app.database import get_db
from app.models import IOC, AnalysisStatus, Sample, Verdict
from app.routers.upload import _run_pipeline
from app.schemas import SampleDetail, SampleSummary

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[SampleSummary])
async def list_reports(db: AsyncSession = Depends(get_db), limit: int = 100):
    result = await db.execute(select(Sample).order_by(Sample.created_at.desc()).limit(limit))
    return result.scalars().all()


@router.get("/search")
async def search_reports(
    q: str = Query(..., min_length=2, description="Search query (filename, hash, IOC, etc.)"),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
):
    """Search samples by filename, hash, or IOC value."""
    query = f"%{q}%"
    
    # Search in samples
    sample_result = await db.execute(
        select(Sample)
        .where(
            or_(
                Sample.original_filename.ilike(query),
                Sample.sha256.ilike(query),
                Sample.sha1.ilike(query),
                Sample.md5.ilike(query),
                Sample.ssdeep.ilike(query),
            )
        )
        .order_by(Sample.created_at.desc())
        .limit(limit)
    )
    samples = sample_result.scalars().all()
    
    # Search in IOCs
    ioc_result = await db.execute(
        select(IOC)
        .where(IOC.value.ilike(query))
        .limit(limit)
    )
    iocs = ioc_result.scalars().all()
    
    # Combine results - get unique sample IDs from IOCs
    ioc_sample_ids = {ioc.sample_id for ioc in iocs}
    for sample_id in ioc_sample_ids:
        if not any(s.id == sample_id for s in samples):
            sample = await db.get(Sample, sample_id)
            if sample:
                samples.append(sample)
    
    return [
        {
            "id": s.id,
            "original_filename": s.original_filename,
            "file_size": s.file_size,
            "sha256": s.sha256,
            "file_type": s.file_type,
            "target_os": s.target_os,
            "status": s.status,
            "verdict": s.verdict,
            "risk_score": s.risk_score,
            "created_at": s.created_at,
        }
        for s in samples[:limit]
    ]


@router.get("/{sample_id}", response_model=SampleDetail)
async def get_report(sample_id: str, db: AsyncSession = Depends(get_db)):
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(404, "Sample not found")
    await db.refresh(sample, attribute_names=["iocs"])
    return sample


@router.get("/{sample_id}/html", response_class=HTMLResponse)
async def get_report_html(sample_id: str):
    html_path = settings.REPORT_DIR / f"{sample_id}.html"
    if not html_path.exists():
        raise HTTPException(404, "Report not yet generated — analysis may still be running")
    return HTMLResponse(html_path.read_text())


@router.get("/{sample_id}/download")
async def download_report(sample_id: str):
    json_path = settings.REPORT_DIR / f"{sample_id}.json"
    if not json_path.exists():
        raise HTTPException(404, "Report not yet generated")
    return FileResponse(json_path, filename=f"malinfo_report_{sample_id}.json", media_type="application/json")


@router.post("/{sample_id}/reanalyze")
async def reanalyze_sample(
    sample_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Re-run the full analysis pipeline on an existing sample."""
    sample = await db.get(Sample, sample_id)
    if sample is None:
        raise HTTPException(404, "Sample not found")

    from pathlib import Path
    file_path = Path(sample.stored_path)
    if not file_path.exists():
        raise HTTPException(404, "Original file not found on disk")

    # Reset sample status
    sample.status = AnalysisStatus.QUEUED
    sample.static_report = None
    sample.sandbox_report = None
    sample.network_report = None
    sample.iocs = []
    sample.risk_score = 0.0
    sample.verdict = Verdict.UNKNOWN
    await db.commit()

    # Re-run pipeline in background
    background_tasks.add_task(_run_pipeline, sample_id, file_path)

    return {"message": "Re-analysis started", "sample_id": sample_id, "status": "queued"}
