"""
MALINFO — VM Orchestrator API Router

REST API endpoints for VM template management, ISO uploads, and dynamic analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app.sandbox.vm_orchestrator import (
    AnalysisTask,
    TaskState,
    get_orchestrator,
)

logger = logging.getLogger("malinfo.vm_router")

router = APIRouter(prefix="/vm", tags=["VM Orchestrator"])

# ─── Constants ───

MALSCORE_CRITICAL = 80
MALSCORE_HIGH = 40
MALSCORE_MEDIUM = 20

# ─── Pydantic Models ───


class ISOUploadResponse(BaseModel):
    name: str
    path: str
    hash: str
    size: int
    os_type: str
    os_version: str


class TemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    os_type: str = Field(..., pattern="^(windows|linux|android|macos)$")
    os_version: str = Field(..., min_length=1, max_length=50)
    iso_name: str = Field(..., min_length=1)
    arch: str = Field(default="x86_64", pattern="^(x86_64|aarch64|arm64)$")
    disk_size_gb: int = Field(default=60, ge=20, le=500)
    memory_mb: int = Field(default=4096, ge=1024, le=32768)
    vcpus: int = Field(default=2, ge=1, le=16)
    network_mode: str = Field(default="isolated", pattern="^(isolated|routed|nat)$")


class TemplateResponse(BaseModel):
    id: str
    name: str
    os_type: str
    os_version: str
    arch: str
    iso_path: str
    disk_size_gb: int
    memory_mb: int
    vcpus: int
    network_mode: str
    agent_installed: bool
    state: str
    created_at: str
    updated_at: str
    error: str | None = None


class AnalysisSubmitRequest(BaseModel):
    sample_id: str
    template_id: str
    timeout: int = Field(default=300, ge=60, le=3600)
    options: dict = Field(default_factory=dict)


class AnalysisSubmitResponse(BaseModel):
    task_id: str
    sample_id: str
    template_id: str
    state: str
    created_at: str


class TaskStatusResponse(BaseModel):
    id: str
    sample_id: str
    sample_hash: str
    template_id: str
    vm_instance_id: str | None
    state: str
    created_at: str
    started_at: str | None
    completed_at: str | None
    timeout: int
    options: dict
    error: str | None
    progress: int
    malscore: int
    signatures_count: int
    processes_count: int
    network_events_count: int
    file_events_count: int
    mitre_techniques: list[str]


class TaskDetailResponse(TaskStatusResponse):
    process_tree: list[dict] = []
    api_calls: list[dict] = []
    network_events: list[dict] = []
    file_events: list[dict] = []
    registry_events: list[dict] = []
    dropped_files: list[dict] = []
    screenshots: list[dict] = []
    memory_dumps: list[dict] = []
    signatures: list[dict] = []


# ─── ISO Management ───


@router.post("/isos/upload", response_model=ISOUploadResponse)
async def upload_iso(
    file: UploadFile = File(...),
    os_type: str = Form(..., pattern="^(windows|linux|android|macos)$"),
    os_version: str = Form(..., min_length=1, max_length=50),
    name: str | None = Form(None),
):
    """Upload an ISO file for VM template creation"""
    orchestrator = get_orchestrator()

    # Validate file
    if not file.filename or not file.filename.endswith(".iso"):
        raise HTTPException(status_code=400, detail="File must be an ISO image")

    # Save to temporary location
    temp_dir = Path("/tmp/malinfo_uploads")
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"{uuid.uuid4()}.iso"

    try:
        # Stream upload to disk
        async with temp_path.open("wb") as f:
            while chunk := await file.read(8192):
                f.write(chunk)

        # Register ISO
        result = await orchestrator.upload_iso(temp_path, os_type, os_version, name)
        return ISOUploadResponse(**result)

    except Exception as e:
        logger.exception("ISO upload failed")
        raise HTTPException(status_code=500, detail=str(e)) from e
    finally:
        # Cleanup temp file
        if temp_path.exists():
            temp_path.unlink()


@router.get("/isos", response_model=list[dict])
async def list_isos():
    """List available ISO files"""
    orchestrator = get_orchestrator()
    return await orchestrator.list_isos()


@router.delete("/isos/{name}")
async def delete_iso(name: str):
    """Delete an ISO file"""
    orchestrator = get_orchestrator()
    success = await orchestrator.delete_iso(name)
    if not success:
        raise HTTPException(status_code=404, detail="ISO not found")
    return {"success": True, "message": f"ISO {name} deleted"}


# ─── Template Management ───


@router.post("/templates", response_model=TemplateResponse)
async def create_template(request: TemplateCreateRequest):
    """Create a VM template from an ISO"""
    orchestrator = get_orchestrator()

    try:
        template = await orchestrator.create_template(
            name=request.name,
            os_type=request.os_type,
            os_version=request.os_version,
            iso_name=request.iso_name,
            arch=request.arch,
            disk_size_gb=request.disk_size_gb,
            memory_mb=request.memory_mb,
            vcpus=request.vcpus,
            network_mode=request.network_mode,
        )
        return TemplateResponse(
            id=template.id,
            name=template.name,
            os_type=template.os_type,
            os_version=template.os_version,
            arch=template.arch,
            iso_path=template.iso_path,
            disk_size_gb=template.disk_size_gb,
            memory_mb=template.memory_mb,
            vcpus=template.vcpus,
            network_mode=template.network_mode,
            agent_installed=template.agent_installed,
            state=template.state.value,
            created_at=template.created_at.isoformat(),
            updated_at=template.updated_at.isoformat(),
            error=template.error,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.exception("Template creation failed")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/templates", response_model=list[TemplateResponse])
async def list_templates():
    """List all VM templates"""
    orchestrator = get_orchestrator()
    templates = await orchestrator.list_templates()
    return [
        TemplateResponse(
            id=t.id,
            name=t.name,
            os_type=t.os_type,
            os_version=t.os_version,
            arch=t.arch,
            iso_path=t.iso_path,
            disk_size_gb=t.disk_size_gb,
            memory_mb=t.memory_mb,
            vcpus=t.vcpus,
            network_mode=t.network_mode,
            agent_installed=t.agent_installed,
            state=t.state.value,
            created_at=t.created_at.isoformat(),
            updated_at=t.updated_at.isoformat(),
            error=t.error,
        )
        for t in templates
    ]


@router.get("/templates/{template_id}", response_model=TemplateResponse)
async def get_template(template_id: str):
    """Get a specific template"""
    orchestrator = get_orchestrator()
    template = await orchestrator.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return TemplateResponse(
        id=template.id,
        name=template.name,
        os_type=template.os_type,
        os_version=template.os_version,
        arch=template.arch,
        iso_path=template.iso_path,
        disk_size_gb=template.disk_size_gb,
        memory_mb=template.memory_mb,
        vcpus=template.vcpus,
        network_mode=template.network_mode,
        agent_installed=template.agent_installed,
        state=template.state.value,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
        error=template.error,
    )


@router.delete("/templates/{template_id}")
async def delete_template(template_id: str):
    """Delete a VM template"""
    orchestrator = get_orchestrator()
    success = await orchestrator.delete_template(template_id)
    if not success:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"success": True, "message": f"Template {template_id} deleted"}


@router.post("/templates/{template_id}/rebuild")
async def rebuild_template(template_id: str):
    """Rebuild a template (reinstall OS, agent, create new snapshot)"""
    orchestrator = get_orchestrator()
    template = await orchestrator.get_template(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    # Trigger rebuild in background
    _ = asyncio.create_task(orchestrator._build_template(template))

    return {"success": True, "message": "Template rebuild started"}


# ─── Analysis Tasks ───


@router.post("/analyze", response_model=AnalysisSubmitResponse)
async def submit_analysis(request: AnalysisSubmitRequest):
    """Submit a sample for dynamic analysis"""
    orchestrator = get_orchestrator()

    try:
        task = await orchestrator.submit_analysis(
            sample_id=request.sample_id,
            sample_path=Path(request.sample_id),
            template_id=request.template_id,
            timeout=request.timeout,
            options=request.options,
        )
        return AnalysisSubmitResponse(
            task_id=task.id,
            sample_id=task.sample_id,
            template_id=task.template_id,
            state=task.state.value,
            created_at=task.created_at.isoformat(),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.exception("Analysis submission failed")
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/tasks", response_model=list[TaskStatusResponse])
async def list_tasks(limit: int = 50, offset: int = 0):
    """List analysis tasks"""
    orchestrator = get_orchestrator()
    tasks = await orchestrator.list_tasks(limit, offset)
    return [_task_to_status_response(t) for t in tasks]


@router.get("/tasks/{task_id}", response_model=TaskDetailResponse)
async def get_task(task_id: str):
    """Get detailed task status and results"""
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return _task_to_detail_response(task)


@router.get("/tasks/{task_id}/status", response_model=TaskStatusResponse)
async def get_task_status(task_id: str):
    """Get task status (lightweight)"""
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return _task_to_status_response(task)


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """Cancel a running analysis task"""
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if task.state in (TaskState.COMPLETED, TaskState.FAILED):
        raise HTTPException(status_code=400, detail="Task already completed")

    # Cancel the task
    if task.vm_instance_id:
        await orchestrator.destroy_instance(task.vm_instance_id)

    task.state = TaskState.FAILED
    task.error = "Cancelled by user"
    task.completed_at = datetime.now(UTC)
    await orchestrator._save_results(task)
    await orchestrator._notify_task_update(task)

    return {"success": True, "message": "Task cancelled"}


@router.get("/tasks/{task_id}/report")
async def download_task_report(task_id: str, format: str = "json"):
    """Download analysis report"""
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if format == "json":
        return _task_to_detail_response(task)
    if format == "html":
        # Generate HTML report
        html = _generate_html_report(task)
        return JSONResponse(content={"html": html})
    raise HTTPException(status_code=400, detail="Unsupported format")


@router.get("/tasks/{task_id}/pcap")
async def download_pcap(task_id: str):
    """Download PCAP file for task"""
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # PCAP would be stored with results
    pcap_path = orchestrator.storage_path / "analysis_results" / task_id / "capture.pcap"
    if pcap_path.exists():
        return FileResponse(pcap_path, filename=f"{task_id}.pcap")
    raise HTTPException(status_code=404, detail="PCAP not available")


@router.get("/tasks/{task_id}/screenshots")
async def get_screenshots(task_id: str):
    """Get screenshots for task"""
    orchestrator = get_orchestrator()
    task = await orchestrator.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"screenshots": task.screenshots}


# ─── WebSocket for Real-time Updates ───


@router.websocket("/ws/{task_id}")
async def websocket_task_updates(websocket: WebSocket, task_id: str):
    """WebSocket endpoint for real-time task updates"""
    orchestrator = get_orchestrator()

    # Verify task exists
    task = await orchestrator.get_task(task_id)
    if not task:
        await websocket.close(code=4004, reason="Task not found")
        return

    await websocket.accept()
    orchestrator.register_websocket(task_id, websocket)

    try:
        # Send initial state
        await websocket.send_json({
            "type": "initial_state",
            "task": _task_to_status_response(task).model_dump(),
        })

        # Keep connection alive
        while True:
            # Wait for messages (ping/pong or client commands)
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        pass
    except Exception:
        logger.exception("WebSocket error")
    finally:
        orchestrator.unregister_websocket(task_id, websocket)


# ─── Helper Functions ───


def _task_to_status_response(task: AnalysisTask) -> TaskStatusResponse:
    """Convert task to status response"""
    orchestrator = get_orchestrator()
    return TaskStatusResponse(
        id=task.id,
        sample_id=task.sample_id,
        sample_hash=task.sample_hash,
        template_id=task.template_id,
        vm_instance_id=task.vm_instance_id,
        state=task.state.value,
        created_at=task.created_at.isoformat(),
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
        timeout=task.timeout,
        options=task.options,
        error=task.error,
        progress=orchestrator._get_task_progress(task),
        malscore=task.malscore,
        signatures_count=len(task.signatures),
        processes_count=len(task.process_tree),
        network_events_count=len(task.network_events),
        file_events_count=len(task.file_events),
        mitre_techniques=task.mitre_techniques,
    )


def _task_to_detail_response(task: AnalysisTask) -> TaskDetailResponse:
    """Convert task to detail response"""
    base = _task_to_status_response(task)
    return TaskDetailResponse(
        **base.model_dump(),
        process_tree=task.process_tree,
        api_calls=task.api_calls,
        network_events=task.network_events,
        file_events=task.file_events,
        registry_events=task.registry_events,
        dropped_files=task.dropped_files,
        screenshots=task.screenshots,
        memory_dumps=task.memory_dumps,
        signatures=task.signatures,
    )


def _generate_html_report(task: AnalysisTask) -> str:
    """Generate HTML report for task"""
    verdict_class = "unknown"
    if task.malscore >= MALSCORE_CRITICAL:
        verdict_class = "malicious"
    elif task.malscore >= MALSCORE_HIGH:
        verdict_class = "suspicious"
    elif task.malscore >= MALSCORE_MEDIUM:
        verdict_class = "clean"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MALINFO Dynamic Analysis Report - {task.id}</title>
        <style>
            body {{ font-family: 'IBM Plex Sans', sans-serif; background: #0a1220; color: #e9edf6; padding: 2rem; }}
            .header {{ border-bottom: 1px solid #253352; padding-bottom: 1rem; margin-bottom: 2rem; }}
            .verdict {{ display: inline-block; width: 80px; height: 80px; clip-path: polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%);
                         display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 20px; }}
            .verdict.malicious {{ background: #4a201c; color: #e2493c; }}
            .verdict.suspicious {{ background: #4a3a1f; color: #e8a33d; }}
            .verdict.clean {{ background: #17402f; color: #33b880; }}
            .verdict.unknown {{ background: #16223a; color: #566284; }}
            .section {{ background: #111a2c; border: 1px solid #253352; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
            .section h2 {{ color: #e8a33d; border-bottom: 1px solid #253352; padding-bottom: 0.5rem; }}
            .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }}
            .stat {{ background: #14203a; padding: 1rem; border-radius: 6px; }}
            .stat-label {{ font-size: 11px; color: #8fa0c2; text-transform: uppercase; }}
            .stat-value {{ font-size: 24px; font-weight: 600; font-family: 'Space Grotesk', sans-serif; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #253352; }}
            th {{ color: #8fa0c2; font-weight: 500; font-size: 12px; text-transform: uppercase; }}
            .mitre-tag {{ background: #17383e; color: #2fb6c4; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin: 2px; display: inline-block; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Dynamic Analysis Report</h1>
            <p>Task ID: <code>{task.id}</code> | Sample: {task.sample_id} | Completed: {task.completed_at or 'N/A'}</p>
        </div>

        <div class="section">
            <div style="display: flex; align-items: center; gap: 2rem;">
                <div class="verdict {verdict_class}">{task.malscore}</div>
                <div>
                    <h2 style="margin: 0; color: #e8a33d;">MALSCORE: {task.malscore}/100</h2>
                    <p style="margin: 0.5rem 0 0; color: #8fa0c2;">Risk Assessment</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Summary Statistics</h2>
            <div class="stat-grid">
                <div class="stat"><div class="stat-label">Processes Created</div><div class="stat-value">{len(task.process_tree)}</div></div>
                <div class="stat"><div class="stat-label">API Calls Monitored</div><div class="stat-value">{len(task.api_calls)}</div></div>
                <div class="stat"><div class="stat-label">Network Events</div><div class="stat-value">{len(task.network_events)}</div></div>
                <div class="stat"><div class="stat-label">File Events</div><div class="stat-value">{len(task.file_events)}</div></div>
                <div class="stat"><div class="stat-label">Registry Events</div><div class="stat-value">{len(task.registry_events)}</div></div>
                <div class="stat"><div class="stat-label">Dropped Files</div><div class="stat-value">{len(task.dropped_files)}</div></div>
                <div class="stat"><div class="stat-label">Screenshots</div><div class="stat-value">{len(task.screenshots)}</div></div>
                <div class="stat"><div class="stat-label">MITRE Techniques</div><div class="stat-value">{len(task.mitre_techniques)}</div></div>
            </div>
        </div>

        <div class="section">
            <h2>MITRE ATT&CK Techniques</h2>
            <div>
                {''.join(f'<span class="mitre-tag">{t}</span>' for t in task.mitre_techniques) or '<span style="color:#8fa0c2;">None detected</span>'}
            </div>
        </div>

        <div class="section">
            <h2>Signatures Triggered</h2>
            <table>
                <thead><tr><th>Description</th><th>Severity</th><th>MITRE</th></tr></thead>
                <tbody>
                    {''.join(f'<tr><td>{s.get("description", "")}</td><td>{s.get("severity", "")}</td><td>{", ".join(s.get("mitre", []))}</td></tr>' for s in task.signatures)}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Process Tree</h2>
            <pre style="background: #0a1220; padding: 1rem; border-radius: 4px; overflow-x: auto;">{json.dumps(task.process_tree, indent=2)}</pre>
        </div>

        <div class="section">
            <h2>Network Events</h2>
            <table>
                <thead><tr><th>Time</th><th>Process</th><th>Type</th><th>Src</th><th>Dst</th><th>Protocol</th></tr></thead>
                <tbody>
                    {''.join(f'<tr><td>{e.get("timestamp", "")}</td><td>{e.get("process_name", "")}</td><td>{e.get("event_type", "")}</td><td>{e.get("src_ip", "")}:{e.get("src_port", "")}</td><td>{e.get("dst_ip", "")}:{e.get("dst_port", "")}</td><td>{e.get("protocol", "")}</td></tr>' for e in task.network_events[:50])}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """
