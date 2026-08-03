from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models import Sample
from app.schemas import SampleDetail, SampleSummary

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[SampleSummary])
async def list_reports(db: AsyncSession = Depends(get_db), limit: int = 100):
    result = await db.execute(select(Sample).order_by(Sample.created_at.desc()).limit(limit))
    return result.scalars().all()


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
