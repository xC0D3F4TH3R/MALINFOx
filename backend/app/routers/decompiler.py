"""
MALINFO — Decompiler Integration API Router
Ghidra headless API integration with retdec fallback and built-in analysis
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Optional

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
    engine: str = "builtin"  # builtin | ghidra | retdec
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
        """Full binary analysis - should be implemented by subclasses"""
        raise NotImplementedError("analyze() must be implemented by subclass")

    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        """Decompile single function - should be implemented by subclasses"""
        raise NotImplementedError("decompile_function() must be implemented by subclass")

    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        """Get all functions - should be implemented by subclasses"""
        raise NotImplementedError("get_functions() must be implemented by subclass")


class BuiltinEngine(DecompilerEngine):
    """Built-in decompiler using radare2/r2pipe or objdump/strings for basic analysis"""

    def __init__(self):
        self.timeout = settings.DECOMPILER_TIMEOUT_SEC if hasattr(settings, 'DECOMPILER_TIMEOUT_SEC') else 300
        self._check_tools()

    def _check_tools(self):
        """Check available analysis tools"""
        self.has_r2 = self._which("r2") or self._which("radare2")
        self.has_objdump = self._which("objdump")
        self.has_nm = self._which("nm")
        self.has_strings = self._which("strings")
        self.has_file = self._which("file")
        logger.info(f"Builtin engine tools: r2={self.has_r2}, objdump={self.has_objdump}, nm={self.has_nm}, strings={self.has_strings}")

    def _which(self, cmd: str) -> str | None:
        """Check if command exists"""
        try:
            result = subprocess.run(["which", cmd], capture_output=True, text=True, timeout=5)
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    async def _run_cmd(self, cmd: list[str], cwd: Path | None = None, timeout: int | None = None) -> tuple[int, str, str]:
        """Run command with timeout"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout or self.timeout)
            return proc.returncode, stdout.decode(errors='replace'), stderr.decode(errors='replace')
        except TimeoutError:
            return -1, "", f"Command timed out after {timeout or self.timeout}s"
        except Exception as e:
            return -1, "", str(e)

    async def analyze(self, file_path: Path, options: dict) -> dict:
        """Full binary analysis using available tools"""
        results = {
            "status": "completed",
            "engine": "builtin",
            "file_info": {},
            "functions": [],
            "strings": [],
            "imports": [],
            "exports": [],
            "sections": [],
            "architecture": "unknown",
            "format": "unknown",
        }

        # Get basic file info
        if self.has_file:
            rc, out, err = await self._run_cmd(["file", "-b", str(file_path)])
            if rc == 0:
                results["file_info"]["file_command"] = out.strip()

        # Detect architecture and format
        results["architecture"], results["format"] = await self._detect_arch_format(file_path)

        # Extract strings
        if self.has_strings:
            rc, out, _err = await self._run_cmd(["strings", "-a", "-n", "4", str(file_path)])
            if rc == 0:
                strings = [s for s in out.strip().split('\n') if s and len(s) >= 4]
                results["strings"] = strings[:5000]  # Limit to 5000 strings

        # Get functions via objdump/nm
        functions = await self._extract_functions(file_path)
        results["functions"] = functions

        # Get imports/exports
        imports, exports = await self._extract_imports_exports(file_path)
        results["imports"] = imports
        results["exports"] = exports

        # Get sections
        sections = await self._extract_sections(file_path)
        results["sections"] = sections

        # Try radare2 for deeper analysis if available
        if self.has_r2:
            r2_results = await self._analyze_with_r2(file_path)
            results.update(r2_results)

        return results

    async def _detect_arch_format(self, file_path: Path) -> tuple[str, str]:
        """Detect architecture and binary format"""
        arch = "unknown"
        fmt = "unknown"

        if self.has_objdump:
            rc, out, err = await self._run_cmd(["objdump", "-f", str(file_path)])
            if rc == 0:
                for line in out.split('\n'):
                    if 'architecture' in line.lower():
                        arch = line.split(':')[-1].strip()
                    if 'file format' in line.lower():
                        fmt = line.split(':')[-1].strip()

        # Also check file command output
        if self.has_file:
            rc, out, _err = await self._run_cmd(["file", "-b", str(file_path)])
            if rc == 0:
                out_lower = out.lower()
                if 'pe32' in out_lower or 'pe64' in out_lower:
                    fmt = 'pe'
                    if 'x86-64' in out_lower:
                        arch = 'x86_64'
                    elif 'intel 80386' in out_lower:
                        arch = 'i386'
                elif 'elf' in out_lower:
                    fmt = 'elf'
                    if 'x86-64' in out_lower:
                        arch = 'x86_64'
                    elif 'intel 80386' in out_lower:
                        arch = 'i386'
                    elif 'aarch64' in out_lower or 'arm64' in out_lower:
                        arch = 'aarch64'
                    elif 'arm' in out_lower:
                        arch = 'arm'
                elif 'mach-o' in out_lower:
                    fmt = 'macho'
                    if 'x86_64' in out_lower:
                        arch = 'x86_64'
                    elif 'arm64' in out_lower:
                        arch = 'aarch64'

        return arch, fmt

    async def _extract_functions(self, file_path: Path) -> list[dict]:
        """Extract function list using objdump/nm"""
        functions = []

        # Try nm first (symbol table)
        if self.has_nm:
            rc, out, err = await self._run_cmd(["nm", "--defined-only", "-C", str(file_path)])
            if rc == 0:
                for line in out.strip().split('\n'):
                    if not line:
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        addr = parts[0]
                        sym_type = parts[1]
                        name = ' '.join(parts[2:])
                        if sym_type.upper() in ('T', 'W'):  # Text/code symbols
                            functions.append({
                                "address": addr,
                                "name": name,
                                "signature": f"/* {sym_type} */ {name}",
                                "size": 0,
                            })

        # Try objdump for disassembly
        if self.has_objdump and not functions:
            rc, out, _err = await self._run_cmd(["objdump", "-t", str(file_path)])
            if rc == 0:
                for line in out.strip().split('\n'):
                    if not line or not line[0].isalnum():
                        continue
                    parts = line.split()
                    if len(parts) >= 5 and parts[1] == 'F':  # Function
                        addr = parts[0]
                        name = parts[-1]
                        functions.append({
                            "address": addr,
                            "name": name,
                            "signature": f"/* func */ {name}",
                            "size": 0,
                        })

        # Limit functions
        return functions[:1000]

    async def _extract_imports_exports(self, file_path: Path) -> tuple[list[str], list[str]]:
        """Extract imported and exported symbols"""
        imports = []
        exports = []

        if self.has_objdump:
            # Get dynamic symbols
            rc, out, _err = await self._run_cmd(["objdump", "-T", str(file_path)])
            if rc == 0:
                for line in out.strip().split('\n'):
                    if not line or 'DYNAMIC SYMBOL TABLE' in line or '*' in line[:10]:
                        continue
                    parts = line.split()
                    if len(parts) >= 5:
                        name = parts[-1]
                        bind = parts[2] if len(parts) > 2 else ''
                        if 'GLOBAL' in bind and 'UND' in parts[1]:
                            imports.append(name)
                        elif 'GLOBAL' in bind:
                            exports.append(name)

        return list(set(imports))[:500], list(set(exports))[:500]

    async def _extract_sections(self, file_path: Path) -> list[dict]:
        """Extract section headers"""
        sections = []

        if self.has_objdump:
            rc, out, _err = await self._run_cmd(["objdump", "-h", str(file_path)])
            if rc == 0:
                for line in out.strip().split('\n'):
                    if not line or line.startswith(' ') or 'Idx' in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 8:
                        try:
                            sections.append({
                                "name": parts[1],
                                "size": parts[2],
                                "vma": parts[3],
                                "lma": parts[4],
                                "file_offset": parts[5],
                                "alignment": parts[6],
                                "flags": parts[7],
                            })
                        except Exception:
                            pass

        return sections

    async def _analyze_with_r2(self, file_path: Path) -> dict:
        """Use radare2 for deeper analysis"""
        results = {"r2_analysis": {}}

        try:
            # Run r2 analysis commands
            cmds = [
                "aaa",  # Analyze all
                "aflj",  # List functions as JSON
                "ij",  # Info as JSON
                "iij",  # Imports as JSON
                "iej",  # Exports as JSON
                "iSj",  # Sections as JSON
            ]

            r2_script = "\n".join(cmds) + "\nq\n"

            rc, out, _err = await self._run_cmd(["r2", "-q", "-c", r2_script, str(file_path)], timeout=120)

            if rc == 0:
                # Parse JSON outputs
                for json_line in out.strip().split('\n'):
                    if json_line.startswith(('[', '{')):
                        try:
                            data = json.loads(json_line)
                            if isinstance(data, list) and data and 'name' in data[0]:
                                # Functions
                                results["r2_analysis"]["functions"] = [
                                    {"address": hex(f.get('offset', 0)), "name": f.get('name', ''),
                                     "size": f.get('size', 0), "type": f.get('type', '')}
                                    for f in data[:500]
                                ]
                            elif isinstance(data, dict):
                                if 'bins' in data:
                                    results["r2_analysis"]["info"] = data['bins'][0] if data['bins'] else {}
                                elif 'imports' in data:
                                    results["r2_analysis"]["imports"] = data['imports'][:200]
                                elif 'exports' in data:
                                    results["r2_analysis"]["exports"] = data['exports'][:200]
                                elif 'sections' in data:
                                    results["r2_analysis"]["sections"] = data['sections']
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"r2 analysis failed: {e}")

        return results

    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        """Decompile specific function using r2 if available"""
        if self.has_r2:
            try:
                cmd = f"aaa\npd {address}\nq\n"
                rc, out, _err = await self._run_cmd(["r2", "-q", "-c", cmd, str(file_path)], timeout=60)
                if rc == 0:
                    return {
                        "address": address,
                        "decompiled": out.strip(),
                        "engine": "builtin-r2",
                    }
            except Exception as e:
                logger.warning(f"r2 decompile failed: {e}")

        # Fallback: return basic info
        return {
            "address": address,
            "decompiled": f"// Decompilation not available for {address}\n// Install radare2 (r2) for built-in decompilation support",
            "engine": "builtin",
        }

    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        """Get all functions"""
        result = await self.analyze(file_path, options)
        return result.get("functions", [])


class GhidraEngine(DecompilerEngine):
    """Ghidra headless analyzer"""

    def __init__(self):
        self.ghidra_path = getattr(settings, 'GHIDRA_PATH', "/opt/ghidra")
        self.ghidra_timeout = getattr(settings, 'DECOMPILER_TIMEOUT_SEC', 300)

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
        except TimeoutError:
            return -1, "", "Ghidra analysis timed out"
        except FileNotFoundError:
            return -1, "", f"Ghidra not found at {self.ghidra_path}. Please install Ghidra and set GHIDRA_PATH in config."
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

            return self._parse_results(output_dir)

    def _get_analysis_script(self) -> str:
        """Get Ghidra analysis script"""
        script_path = Path(self.ghidra_path) / "scripts" / "AnalyzeAll.java"
        if not script_path.exists():
            logger.warning(f"Ghidra analysis script not found at {script_path}. Using placeholder.")
            return "AnalyzeAll.java"
        return str(script_path)

    def _parse_results(self, output_dir: Path) -> dict:
        """Parse Ghidra output"""
        return {
            "status": "completed",
            "engine": "ghidra",
            "functions": [],
            "note": "Ghidra integration requires Ghidra installation and analysis scripts. See docs for setup."
        }

    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        return {
            "address": address,
            "decompiled": "// Ghidra decompilation requires Ghidra installation and scripts. See documentation for setup.",
            "engine": "ghidra",
        }

    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        return []


class RetdecEngine(DecompilerEngine):
    """Retdec decompiler fallback"""

    def __init__(self):
        self.retdec_path = getattr(settings, 'RETDEC_PATH', "/usr/bin/retdec-decompiler")
        self.timeout = getattr(settings, 'DECOMPILER_TIMEOUT_SEC', 180)

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

                decompiled = output_file.read_text() if output_file.exists() else ""

                return {
                    "status": "completed",
                    "engine": "retdec",
                    "decompiled": decompiled,
                    "functions": self._parse_functions(decompiled)
                }
            except TimeoutError:
                raise Exception("Retdec analysis timed out")
            except FileNotFoundError:
                raise Exception(f"Retdec not found at {self.retdec_path}. Please install retdec and set RETDEC_PATH in config.")
            except Exception as e:
                raise Exception(f"Retdec error: {e!s}")

    async def decompile_function(self, file_path: Path, address: str, options: dict) -> dict:
        result = await self.analyze(file_path, options)
        return {
            "address": address,
            "decompiled": result.get("decompiled", ""),
            "note": "Retdec decompiles entire binary; function-level decompilation not separately available.",
            "engine": "retdec",
        }

    async def get_functions(self, file_path: Path, options: dict) -> list[dict]:
        result = await self.analyze(file_path, options)
        return result.get("functions", [])

    def _parse_functions(self, decompiled: str) -> list[dict]:
        functions = []
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
    elif engine_name == "builtin":
        return BuiltinEngine()
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