"""
Sandbox API routes for dynamic analysis management.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import User, require_analyst
from app.config import settings
from app.database import get_db
from app.sandbox.capev2_client import CapeV2Client, SandboxUnavailableError
from app.sandbox.orchestrator import detonate_sample

router = APIRouter(prefix="/sandbox", tags=["sandbox"])


@router.get("/profiles")
async def get_sandbox_profiles(current_user: User = Depends(require_analyst)):
    """Get available sandbox profiles."""
    return settings.SANDBOX_PROFILES


@router.post("/detonate")
async def submit_to_sandbox(
    sample_id: str,
    profile: str | None = None,
    current_user: User = Depends(require_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Submit a sample for dynamic analysis."""
    from sqlalchemy import select

    from app.models import AnalysisStatus, Sample
    
    result = await db.execute(select(Sample).where(Sample.id == sample_id))
    sample = result.scalar_one_or_none()
    
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")
    
    if not settings.SANDBOX_ENABLED:
        raise HTTPException(status_code=503, detail="Sandbox not enabled")
    
    # Determine target OS
    target_os = sample.target_os
    if profile and profile in settings.SANDBOX_PROFILES:
        target_os = profile
    
    # Submit to sandbox
    from pathlib import Path
    sandbox_report = await detonate_sample(Path(sample.stored_path), target_os)
    
    if not sandbox_report.get("available"):
        raise HTTPException(status_code=500, detail=sandbox_report.get("reason", "Sandbox submission failed"))
    
    # Update sample with sandbox report
    sample.sandbox_report = sandbox_report
    sample.status = AnalysisStatus.SANDBOX_RUNNING
    await db.commit()
    
    return {
        "task_id": sandbox_report.get("task_id"),
        "status": "submitted",
        "profile": target_os,
    }


@router.get("/status/{task_id}")
async def get_sandbox_status(
    task_id: str,
    current_user: User = Depends(require_analyst),
):
    """Get sandbox task status."""
    client = CapeV2Client()
    try:
        status = client.get_status(task_id)
        return {"task_id": task_id, "status": status}
    except SandboxUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Status check failed: {exc}")


@router.get("/report/{task_id}")
async def get_sandbox_report(
    task_id: str,
    current_user: User = Depends(require_analyst),
):
    """Get sandbox analysis report."""
    client = CapeV2Client()
    try:
        report = client.get_report(task_id)
        return report
    except SandboxUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report retrieval failed: {exc}")