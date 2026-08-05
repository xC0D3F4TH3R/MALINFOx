"""
MALINFO — Decompiler Integration API Router
Ghidra headless API integration with retdec fallback
"""
from __future__ import annotations

import asyncio
import logging
import tempfile
import uuid
from pathlib import Path

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    status,
)
from pydantic import BaseModel

from app.auth.rbac import User, require_analyst
from app.config import settings

logger = logging.getLogger("malinfo.decompiler")

router = APIRouter(prefix="/api/decompiler", tags=["decompiler"])

# Global task tracking
_decompiler_tasks: dict[str, dict] = {}


# ── Schemas ──

class DecompilerTaskCreate(BaseModel):
    sample_id: str
    engine: str = "ghidra"  # ghidra | retdec
    options: dict = {}


class DecompilerTaskResponse(BaseModel):
    task_id: str
    status: str  # pending, running, completed, failed
    engine: str
    sample_id: str
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error: str | None = None
    result: dict | None = None


class DecompilerFunction(BaseModel):
    address: str
    name: str
    signature: str
    calling_convention: str | None = None
    decompiled: str | None = None
    xrefs_to: list[str] = []
    xrefs_from: list[str] = []


# ── Decompiler Engines ──

class DecompilerEngine:
    """Base decompiler engine"""
    
    async def analyze(self, file_path: Path, options: dict) -> dict:
        raise NotImplementedError
    
    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        raise NotImplementedError
    
    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        raise NotImplementedError


class GhidraEngine(DecompilerEngine):
    """Ghidra headless analyzer"""
    
    def __init__(self):
        self.ghidra_path = settings.GHIDRA_PATH if hasattr(settings, 'GHIDRA_PATH') else "/opt/ghidra"
        self.ghidra_timeout = 300  # 5 minutes
    
    async def _run_ghidra(self, script: str, file_path: Path, output_dir: Path, extra_args: list | None = None) -> tuple[int, str, str]:
        """Run Ghidra headless with a script"""
        cmd = [
            f"{self.ghidra_path}/support/analyzeHeadless",
            str(output_dir),
            f"malinfo_{uuid.uuid4().hex[:8]}",
            "-import", str(file_path),
            "-postScript", script,
            "-deleteProject"
        ]
        if extra_args:
            cmd.extend(extra_args)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(file_path.parent)
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.ghidra_timeout)
            return proc.returncode, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            return -1, "", "Ghidra analysis timed out"
        except Exception as e:
            return -1, "", str(e)
    
    async def analyze(self, file_path: Path, options: dict) -> dict:
        """Full binary analysis with Ghidra"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            script = self._get_analysis_script()
            
            returncode, _stdout, stderr = await self._run_ghidra(script, file_path, output_dir)
            
            if returncode != 0:
                raise Exception(f"Ghidra analysis failed: {stderr}")
            
            # Parse results from output files
            return self._parse_results(output_dir)
    
    def _get_analysis_script(self) -> str:
        """Get Ghidra analysis script"""
        # This would be a separate .java or .py script for Ghidra
        # For now, return a placeholder
        return "AnalyzeAll.java"
    
    def _parse_results(self, output_dir: Path) -> dict:
        """Parse Ghidra output"""
        return {"status": "completed", "functions": [], "note": "Ghidra integration requires Ghidra installation and scripts"}
    
    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        """Decompile single function"""
        return {"address": address, "decompiled": "// Ghidra decompilation not implemented"}
    
    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        """Get all functions"""
        return []


class RetdecEngine(DecompilerEngine):
    """Retdec decompiler fallback"""
    
    def __init__(self):
        self.retdec_path = "/usr/bin/retdec-decompiler"
        self.timeout = 180  # 3 minutes
    
    async def analyze(self, file_path: Path, options: dict) -> dict:
        """Full binary analysis with Retdec"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            output_file = output_dir / "output.c"
            
            cmd = [
                self.retdec_path,
                str(file_path),
                "-o", str(output_file),
                "--backend-keep-library-funcs",
                "--select-ranges=all"
            ]
            
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                _stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
                
                if proc.returncode != 0:
                    raise Exception(f"Retdec failed: {stderr.decode()}")
                
                # Read decompiled output
                decompiled = output_file.read_text() if output_file.exists() else ""
                
                return {
                    "status": "completed",
                    "engine": "retdec",
                    "decompiled": decompiled,
                    "functions": self._parse_functions(decompiled)
                }
            except asyncio.TimeoutError:
                raise Exception("Retdec analysis timed out")
    
    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        """Decompile single function - Retdec does whole binary"""
        return await self.analyze(file_path, options)
    
    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        """Get functions from decompilation"""
        result = await self.analyze(file_path, options)
        return result.get("functions", [])
    
    def _parse_functions(self, decompiled: str) -> list[dict]:
        """Parse functions from Retdec output"""
        functions = []
        # Simple parsing - look for function definitions
        import re
        for match in re.finditer(r'(\w+\s+\w+)\s*\([^)]*\)\s*\{', decompiled):
            functions.append({
                "signature": match.group(1),
                "name": match.group(1).split()[-1] if match.group(1) else "unknown"
            })
        return functions


# Get engine instance
def get_engine(engine_name: str) -> DecompilerEngine:
    if engine_name == "ghidra":
        return GhidraEngine()
    elif engine_name == "retdec":
        return RetdecEngine()
    else:
        raise HTTPException(status_code=400, detail=f"Unknown engine: {engine_name}")


# ── API Endpoints ──

@router.post("/analyze", response_model=DecompilerTaskResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_decompilation(
    task_data: DecompilerTaskCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_analyst),
):
    """Start decompilation task for a sample"""
    
    # Verify sample exists
    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models import Sample
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Sample).where(Sample.id == task_data.sample_id))
        sample = result.scalar_one_or_none()
        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")
        
        file_path = Path(sample.stored_path)
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Sample file not found")
    
    # Create task
    task_id = str(uuid.uuid4())
    task = {
        "task_id": task_id,
        "status": "pending",
        "engine": task_data.engine,
        "sample_id": task_data.sample_id,
        "file_path": str(file_path),
        "options": task_data.options,
        "created_at": __import__('datetime').datetime.utcnow().isoformat() + "Z",
        "started_at": None,
        "completed_at": None,
        "error": None,
        "result": None,
    }
    _decompiler_tasks[task_id] = task
    
    # Run in background
    background_tasks.add_task(run_decompilation_task, task_id)
    
    return DecompilerTaskResponse(**task)


@router.get("/tasks", response_model=list[DecompilerTaskResponse])
async def list_tasks(
    status_filter: str | None = None,
    current_user: User = Depends(require_analyst),
):
    """List decompilation tasks"""
    tasks = list(_decompiler_tasks.values())
    if status_filter:
        tasks = [t for t in tasks if t["status"] == status_filter]
    return [DecompilerTaskResponse(**t) for t in tasks]


@router.get("/tasks/{task_id}", response_model=DecompilerTaskResponse)
async def get_task(task_id: str, current_user: User = Depends(require_analyst)):
    """Get decompilation task status"""
    task = _decompiler_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return DecompilerTaskResponse(**task)


@router.get("/tasks/{task_id}/result")
async def get_task_result(task_id: str, current_user: User = Depends(require_analyst)):
    """Get decompilation result"""
    task = _decompiler_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Task not completed (status: {task['status']})")
    return task.get("result", {})


@router.get("/tasks/{task_id}/functions", response_model=list[DecompilerFunction])
async def get_functions(task_id: str, current_user: User = Depends(require_analyst)):
    """Get decompiled functions"""
    task = _decompiler_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if task["status"] != "completed":
        raise HTTPException(status_code=400, detail=f"Task not completed (status: {task['status']})")
    
    result = task.get("result", {})
    functions = result.get("functions", [])
    return [DecompilerFunction(**f) for f in functions]


@router.get("/tasks/{task_id}/decompile/{address}")
async def decompile_function(
    task_id: str,
    address: str,
    current_user: User = Depends(require_analyst),
):
    """Decompile specific function by address"""
    task = _decompiler_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    engine = get_engine(task["engine"])
    file_path = Path(task["file_path"])
    
    result = await engine.decompile_function(file_path, address, task["options"])
    return result


# ── Background Task ──

async def run_decompilation_task(task_id: str):
    """Run decompilation in background"""
    task = _decompiler_tasks[task_id]
    task["status"] = "running"
    task["started_at"] = __import__('datetime').datetime.utcnow().isoformat() + "Z"
    
    try:
        engine = get_engine(task["engine"])
        file_path = Path(task["file_path"])
        
        logger.info(f"Starting decompilation task {task_id} with {task['engine']}")
        result = await engine.analyze(file_path, task["options"])
        
        task["status"] = "completed"
        task["result"] = result
        logger.info(f"Decompilation task {task_id} completed")
        
    except Exception as e:
        task["status"] = "failed"
        task["error"] = str(e)
        logger.exception(f"Decompilation task {task_id} failed: {e}")
    
    finally:
        task["completed_at"] = __import__('datetime').datetime.utcnow().isoformat() + "Z"