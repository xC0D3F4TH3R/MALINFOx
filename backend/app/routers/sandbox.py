"""
Sandbox API routes for dynamic analysis management.

Supports both legacy CAPEv2 integration and new built-in VM orchestrator.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.rbac import User, require_analyst
from app.config import settings
from app.database import get_db
from app.sandbox.capev2_client import CapeV2Client, SandboxUnavailableError
from app.sandbox.orchestrator import detonate_sample
from app.sandbox.vm_orchestrator import get_orchestrator, TaskState

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
    
    # Try new VM orchestrator first, fall back to CAPEv2
    if settings.SANDBOX_ENABLED:
        # Use CAPEv2
        target_os = sample.target_os
        if profile and profile in settings.SANDBOX_PROFILES:
            target_os = profile
        
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
            "engine": "capev2",
        }
    else:
        # Use built-in VM orchestrator
        orchestrator = get_orchestrator()
        
        # Find a suitable template
        templates = await orchestrator.list_templates()
        ready_templates = [t for t in templates if t.state.value == "ready"]
        
        if not ready_templates:
            raise HTTPException(status_code=503, detail="No VM templates ready. Please create a template first.")
        
        # Select template based on sample type or profile
        template = ready_templates[0]  # Default to first ready template
        if profile:
            for t in ready_templates:
                if t.os_type == profile or t.name.lower().startswith(profile.lower()):
                    template = t
                    break
        
        try:
            task = await orchestrator.submit_analysis(
                sample_id=sample_id,
                sample_path=sample.stored_path,
                template_id=template.id,
                timeout=settings.SANDBOX_TIMEOUT_SEC,
            )
            
            # Update sample
            sample.sandbox_report = {"vm_task_id": task.id, "engine": "vm_orchestrator"}
            sample.status = AnalysisStatus.SANDBOX_RUNNING
            await db.commit()
            
            return {
                "task_id": task.id,
                "status": "submitted",
                "template": template.name,
                "engine": "vm_orchestrator",
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"VM orchestrator submission failed: {e}")


@router.get("/status/{task_id}")
async def get_sandbox_status(
    task_id: str,
    current_user: User = Depends(require_analyst),
):
    """Get sandbox task status."""
    # Try VM orchestrator first
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    
    if task:
        return {
            "task_id": task.id,
            "status": task.state.value,
            "progress": orchestrator._get_task_progress(task),
            "malscore": task.malscore,
            "engine": "vm_orchestrator",
        }
    
    # Fall back to CAPEv2
    client = CapeV2Client()
    try:
        status = client.get_status(task_id)
        return {"task_id": task_id, "status": status, "engine": "capev2"}
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
    # Try VM orchestrator first
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    
    if task:
        return {
            "task_id": task.id,
            "sample_id": task.sample_id,
            "sample_hash": task.sample_hash,
            "state": task.state.value,
            "malscore": task.malscore,
            "signatures": task.signatures,
            "mitre_techniques": task.mitre_techniques,
            "process_tree": task.process_tree,
            "api_calls": task.api_calls,
            "network_events": task.network_events,
            "file_events": task.file_events,
            "registry_events": task.registry_events,
            "dropped_files": task.dropped_files,
            "screenshots": task.screenshots,
            "memory_dumps": task.memory_dumps,
            "engine": "vm_orchestrator",
        }
    
    # Fall back to CAPEv2
    client = CapeV2Client()
    try:
        report = client.get_report(task_id)
        return report
    except SandboxUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Report retrieval failed: {exc}")