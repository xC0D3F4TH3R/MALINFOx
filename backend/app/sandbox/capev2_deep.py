"""
MALINFO — CAPEv2 Deep Integration.

Deep integration with CAPEv2 sandbox for dynamic analysis.
Includes: Memory dump analysis (Volatility3), API call monitoring,
behavioral MITRE ATT&CK mapping, process tree visualization,
dropped file auto-extraction, network IOC correlation.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("malinfo.capev2_deep")

# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CapeTask:
    """CAPEv2 task representation."""
    task_id: int
    sample_sha256: str
    sample_path: str
    profile: str
    status: str  # pending, running, completed, failed, reported
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    options: dict = field(default_factory=dict)


@dataclass
class CapeReport:
    """Enhanced CAPEv2 report with MALINFO extensions."""
    task_id: int
    sample_sha256: str
    profile: str
    
    # Basic info
    target: str
    start_time: str
    end_time: str
    duration: int
    
    # Behavioral
    signatures: list[dict] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    behavior_summary: dict = field(default_factory=dict)
    
    # Process tree
    process_tree: list[dict] = field(default_factory=list)
    processes: list[dict] = field(default_factory=list)
    
    # API calls
    api_calls: list[dict] = field(default_factory=list)
    api_call_summary: dict = field(default_factory=dict)
    
    # Network
    network: dict = field(default_factory=dict)
    network_iocs: list[dict] = field(default_factory=list)
    pcap_path: str | None = None
    pcap_size: int = 0
    
    # Memory
    memory_dumps: list[dict] = field(default_factory=list)
    volatility_results: dict = field(default_factory=dict)
    
    # Dropped files
    dropped_files: list[dict] = field(default_factory=list)
    
    # Screenshots
    screenshots: list[dict] = field(default_factory=list)
    
    # Static
    static: dict = field(default_factory=dict)
    
    # MALINFO extensions
    malscore: int = 0
    severity: str = "info"
    tags: list[str] = field(default_factory=list)
    extracted_iocs: list[dict] = field(default_factory=list)
    c2_config: dict = field(default_factory=dict)
    
    # Raw report
    raw_report: dict = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────

class CapeV2Client:
    """
    Enhanced CAPEv2 client with deep analysis capabilities.
    """
    
    def __init__(
        self,
        api_url: str = "http://cape-controller:8000",
        api_token: str = "",
        timeout: int = 600,
        poll_interval: int = 15,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._session = None
    
    async def _get_session(self):
        """Get or create aiohttp session."""
        import aiohttp
        if self._session is None or self._session.closed:
            headers = {}
            if self.api_token:
                headers["Authorization"] = f"Bearer {self.api_token}"
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    # ─── Task Management ───
    
    async def submit_sample(
        self,
        file_path: Path,
        profile: str = "win10-x64-clean",
        options: dict | None = None,
        priority: int = 1,
        tags: list[str] | None = None,
    ) -> CapeTask:
        """Submit a sample for analysis."""
        session = await self._get_session()
        
        # Prepare options
        opts = options or {}
        opts.update({
            "procmemdump": opts.get("procmemdump", True),
            "network": opts.get("network", True),
            "screenshots": opts.get("screenshots", True),
            "enforce_timeout": opts.get("enforce_timeout", True),
            "timeout": opts.get("timeout", 300),
        })
        
        # Read file
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        # Calculate hash
        sha256 = hashlib.sha256(file_data).hexdigest()
        
        # Submit
        data = aiohttp.FormData()
        data.add_field("file", file_data, filename=file_path.name, content_type="application/octet-stream")
        data.add_field("profile", profile)
        data.add_field("options", json.dumps(opts))
        data.add_field("priority", str(priority))
        if tags:
            data.add_field("tags", json.dumps(tags))
        
        async with session.post(f"{self.api_url}/apiv2/tasks/create/file", data=data) as resp:
            if resp.status != 200:
                error = await resp.text()
                raise Exception(f"Task submission failed: {error}")
            result = await resp.json()
        
        task_id = result.get("task_id")
        if not task_id:
            raise Exception("No task_id in response")
        
        return CapeTask(
            task_id=task_id,
            sample_sha256=sha256,
            sample_path=str(file_path),
            profile=profile,
            status="pending",
            created_at=datetime.utcnow(),
            options=opts,
        )
    
    async def get_task_status(self, task_id: int) -> CapeTask:
        """Get task status."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/view/{task_id}") as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get task status: {await resp.text()}")
            result = await resp.json()
        
        task_data = result.get("task", {})
        return CapeTask(
            task_id=task_data.get("id", task_id),
            sample_sha256=task_data.get("sample", {}).get("sha256", ""),
            sample_path=task_data.get("sample", {}).get("path", ""),
            profile=task_data.get("profile", ""),
            status=task_data.get("status", "unknown"),
            created_at=datetime.fromisoformat(task_data.get("added_on", datetime.utcnow().isoformat())),
            started_at=datetime.fromisoformat(task_data["started_on"]) if task_data.get("started_on") else None,
            completed_at=datetime.fromisoformat(task_data["completed_on"]) if task_data.get("completed_on") else None,
            error=task_data.get("error"),
            options=task_data.get("options", {}),
        )
    
    async def wait_for_completion(self, task_id: int, timeout: int | None = None) -> CapeTask:
        """Wait for task to complete."""
        timeout = timeout or self.timeout
        start = time.time()
        
        while time.time() - start < timeout:
            task = await self.get_task_status(task_id)
            if task.status in ("completed", "reported", "failed"):
                return task
            await asyncio.sleep(self.poll_interval)
        
        raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")
    
    async def get_report(self, task_id: int) -> CapeReport:
        """Get full analysis report."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/report/{task_id}") as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get report: {await resp.text()}")
            raw_report = await resp.json()
        
        return self._parse_report(task_id, raw_report)
    
    async def get_pcap(self, task_id: int) -> bytes:
        """Download PCAP file."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/pcap/{task_id}") as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get PCAP: {await resp.text()}")
            return await resp.read()
    
    async def get_memory_dump(self, task_id: int, pid: int) -> bytes:
        """Download memory dump for a process."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/memory/{task_id}/{pid}") as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get memory dump: {await resp.text()}")
            return await resp.read()
    
    async def get_dropped_files(self, task_id: int) -> list[dict]:
        """Get list of dropped files."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/dropped/{task_id}") as resp:
            if resp.status != 200:
                return []
            result = await resp.json()
            return result.get("dropped", [])
    
    async def download_dropped_file(self, task_id: int, sha256: str) -> bytes:
        """Download a dropped file by SHA256."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/dropped/{task_id}/{sha256}") as resp:
            if resp.status != 200:
                raise Exception(f"Failed to download dropped file: {await resp.text()}")
            return await resp.read()
    
    async def get_screenshots(self, task_id: int) -> list[dict]:
        """Get screenshot metadata."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/screenshots/{task_id}") as resp:
            if resp.status != 200:
                return []
            result = await resp.json()
            return result.get("screenshots", [])
    
    async def get_screenshot(self, task_id: int, shot_id: int) -> bytes:
        """Download a screenshot."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/tasks/screenshot/{task_id}/{shot_id}") as resp:
            if resp.status != 200:
                raise Exception(f"Failed to get screenshot: {await resp.text()}")
            return await resp.read()
    
    # ─── Profile Management ───
    
    async def get_profiles(self) -> list[dict]:
        """Get available analysis profiles."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/profiles") as resp:
            if resp.status != 200:
                return []
            result = await resp.json()
            return result.get("profiles", [])
    
    async def get_profile_info(self, profile: str) -> dict:
        """Get profile details."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/profiles/{profile}") as resp:
            if resp.status != 200:
                return {}
            result = await resp.json()
            return result.get("profile", {})
    
    # ─── Machine Management ───
    
    async def get_machines(self) -> list[dict]:
        """Get available machines."""
        session = await self._get_session()
        async with session.get(f"{self.api_url}/apiv2/machines") as resp:
            if resp.status != 200:
                return []
            result = await resp.json()
            return result.get("machines", [])
    
    # ─── Report Parsing ───
    
    def _parse_report(self, task_id: int, raw: dict) -> CapeReport:
        """Parse raw CAPEv2 report into enhanced structure."""
        info = raw.get("info", {})
        target = raw.get("target", {})
        behavior = raw.get("behavior", {})
        network = raw.get("network", {})
        static = raw.get("static", {})
        signatures = raw.get("signatures", [])
        dropped = raw.get("dropped", [])
        
        report = CapeReport(
            task_id=task_id,
            sample_sha256=target.get("file", {}).get("sha256", ""),
            profile=info.get("profile", ""),
            target=target.get("file", {}).get("name", ""),
            start_time=info.get("started", ""),
            end_time=info.get("ended", ""),
            duration=info.get("duration", 0),
            raw_report=raw,
        )
        
        # ─── Signatures & MITRE ───
        report.signatures = signatures
        report.mitre_techniques = self._extract_mitre_from_signatures(signatures)
        report.malscore = info.get("malscore", 0)
        report.severity = self._malscore_to_severity(report.malscore)
        report.tags = info.get("tags", [])
        
        # ─── Behavior Summary ───
        report.behavior_summary = {
            "processes": len(behavior.get("processes", [])),
            "api_calls": sum(len(p.get("calls", [])) for p in behavior.get("processes", [])),
            "modules_loaded": len(set().union(*[set(p.get("modules", [])) for p in behavior.get("processes", [])])),
            "files_accessed": len(set().union(*[set(p.get("files", [])) for p in behavior.get("processes", [])])),
            "registry_keys": len(set().union(*[set(p.get("regkeys", [])) for p in behavior.get("processes", [])])),
        }
        
        # ─── Process Tree ───
        report.process_tree = self._build_process_tree(behavior.get("processes", []))
        report.processes = behavior.get("processes", [])
        
        # ─── API Calls ───
        report.api_calls = self._extract_api_calls(behavior.get("processes", []))
        report.api_call_summary = self._summarize_api_calls(report.api_calls)
        
        # ─── Network ───
        report.network = network
        report.network_iocs = self._extract_network_iocs(network)
        
        # ─── PCAP ───
        report.pcap_path = f"tasks/{task_id}/pcap.pcap"
        
        # ─── Dropped Files ───
        report.dropped_files = dropped
        
        # ─── Screenshots ───
        # Would be populated from separate API call
        
        # ─── Static ───
        report.static = static
        
        # ─── Extracted IOCs ───
        report.extracted_iocs = self._extract_all_iocs(raw)
        
        # ─── C2 Config ───
        report.c2_config = self._extract_c2_config(raw)
        
        return report
    
    def _extract_mitre_from_signatures(self, signatures: list[dict]) -> list[str]:
        """Extract MITRE ATT&CK techniques from signatures."""
        techniques = set()
        for sig in signatures:
            mitre = sig.get("mitre", [])
            if isinstance(mitre, list):
                techniques.update(mitre)
            elif isinstance(mitre, str):
                techniques.add(mitre)
            # Also check for MITRE in description
            desc = sig.get("description", "")
            for match in re.finditer(r"T\d{4}(?:\.\d{3})?", desc):
                techniques.add(match.group())
        return sorted(techniques)
    
    def _malscore_to_severity(self, score: int) -> str:
        if score >= 80: return "critical"
        if score >= 60: return "high"
        if score >= 40: return "medium"
        if score >= 20: return "low"
        return "info"
    
    def _build_process_tree(self, processes: list[dict]) -> list[dict]:
        """Build process tree from flat process list."""
        # Create lookup
        proc_map = {p["pid"]: p for p in processes}
        roots = []
        children_map = {}
        
        for p in processes:
            ppid = p.get("ppid", 0)
            if ppid not in children_map:
                children_map[ppid] = []
            children_map[ppid].append(p["pid"])
        
        def build_tree(pid: int, depth: int = 0) -> dict:
            proc = proc_map.get(pid, {})
            node = {
                "pid": pid,
                "ppid": proc.get("ppid", 0),
                "name": proc.get("process_name", ""),
                "path": proc.get("module_path", ""),
                "cmdline": proc.get("command_line", ""),
                "depth": depth,
                "children": [],
            }
            for child_pid in children_map.get(pid, []):
                node["children"].append(build_tree(child_pid, depth + 1))
            return node
        
        for proc in processes:
            if proc.get("ppid", 0) == 0 or proc.get("ppid") not in proc_map:
                roots.append(build_tree(proc["pid"]))
        
        return roots
    
    def _extract_api_calls(self, processes: list[dict]) -> list[dict]:
        """Extract all API calls from processes."""
        calls = []
        for proc in processes:
            for call in proc.get("calls", []):
                call["process_name"] = proc.get("process_name", "")
                call["pid"] = proc.get("pid", 0)
                calls.append(call)
        return calls
    
    def _summarize_api_calls(self, calls: list[dict]) -> dict:
        """Summarize API calls by category."""
        categories = {}
        for call in calls:
            cat = call.get("category", "Other")
            api = call.get("api", "")
            if cat not in categories:
                categories[cat] = {"count": 0, "apis": {}}
            categories[cat]["count"] += 1
            categories[cat]["apis"][api] = categories[cat]["apis"].get(api, 0) + 1
        return categories
    
    def _extract_network_iocs(self, network: dict) -> list[dict]:
        """Extract IOCs from network section."""
        iocs = []
        
        # HTTP
        for http in network.get("http", []):
            iocs.append({
                "type": "http",
                "url": http.get("url", ""),
                "method": http.get("method", ""),
                "host": http.get("host", ""),
                "user_agent": http.get("user_agent", ""),
            })
        
        # DNS
        for dns in network.get("dns", []):
            iocs.append({
                "type": "dns",
                "query": dns.get("query", ""),
                "type": dns.get("type", "A"),
                "answers": dns.get("answers", []),
            })
        
        # TCP/UDP
        for conn in network.get("tcp", []) + network.get("udp", []):
            iocs.append({
                "type": "connection",
                "dst_ip": conn.get("dst", ""),
                "dst_port": conn.get("dport", 0),
                "src_ip": conn.get("src", ""),
                "src_port": conn.get("sport", 0),
            })
        
        return iocs
    
    def _extract_all_iocs(self, raw: dict) -> list[dict]:
        """Extract all IOCs from raw report."""
        iocs = []
        
        # From network
        iocs.extend(self._extract_network_iocs(raw.get("network", {})))
        
        # From dropped files
        for dropped in raw.get("dropped", []):
            iocs.append({
                "type": "file",
                "sha256": dropped.get("sha256", ""),
                "path": dropped.get("name", ""),
                "size": dropped.get("size", 0),
            })
        
        # From behavior (registry, files, mutexes)
        for proc in raw.get("behavior", {}).get("processes", []):
            for regkey in proc.get("regkeys", []):
                iocs.append({"type": "registry", "key": regkey})
            for filepath in proc.get("files", []):
                iocs.append({"type": "filepath", "path": filepath})
            for mutex in proc.get("mutexes", []):
                iocs.append({"type": "mutex", "name": mutex})
        
        return iocs
    
    def _extract_c2_config(self, raw: dict) -> dict:
        """Extract C2 configuration from report."""
        # This would extract C2 configs from memory dumps or static analysis
        # For now, return empty
        return {}


# ──────────────────────────────────────────────────────────────────────────────
# Memory Analysis with Volatility3
# ──────────────────────────────────────────────────────────────────────────────

class VolatilityAnalyzer:
    """
    Memory analysis using Volatility3 framework.
    """
    
    def __init__(self):
        self._plugins = [
            "windows.pslist",           # Process list
            "windows.pstree",           # Process tree
            "windows.dlllist",          # DLLs loaded
            "windows.handles",          # Open handles
            "windows.malfind",          # Injected code/VAD analysis
            "windows.hollowfind",       # Process hollowing detection
            "windows.cmdline",          # Command lines
            "windows.svcscan",          # Services
            "windows.driverirp",        # Driver IRP hooks
            "windows.etwtamper",        # ETW tampering
            "windows.ldrmodules",       # Unlinked DLLs
            "windows.apihooks",         # API hooks
            "windows.ssdt",             # SSDT hooks
            "windows.filescan",         # File objects
            "windows.mutantscan",       # Mutexes
            "windows.symlinkscan",      # Symbolic links
            "windows.thrdscan",         # Threads
            "windows.vadinfo",          # VAD info
            "windows.vadwalk",          # VAD walk
            "linux.pslist",             # Linux process list
            "linux.pstree",             # Linux process tree
            "linux.lsmod",              # Kernel modules
            "linux.bash",               # Bash history
            "linux.check_creds",        # Credential structures
            "linux.check_modules",      # Module verification
            "linux.enum_files",         # File enumeration
            "linux.hidden_modules",     # Hidden modules
            "linux.malfind",            # Memory analysis
            "linux.psaux",              # Process auxiliary
            "linux.psenv",              # Process environment
        ]
    
    async def analyze_memory_dump(
        self,
        dump_path: Path,
        os_profile: str = "windows",
        plugins: list[str] | None = None,
    ) -> dict:
        """Run Volatility3 plugins on memory dump."""
        plugins = plugins or self._plugins[:10]  # Default to first 10
        results = {}
        
        for plugin in plugins:
            try:
                result = await self._run_plugin(dump_path, os_profile, plugin)
                results[plugin] = result
            except Exception as exc:
                logger.warning(f"Volatility plugin {plugin} failed: {exc}")
                results[plugin] = {"error": str(exc)}
        
        return results
    
    async def _run_plugin(self, dump_path: Path, os_profile: str, plugin: str) -> dict:
        """Run a single Volatility3 plugin."""
        # Use volatility3 CLI
        cmd = [
            "python3", "-m", "volatility3",
            "-f", str(dump_path),
            plugin,
        ]
        
        # Add OS-specific options
        if os_profile == "windows":
            cmd.extend(["--single-file", str(dump_path)])
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            raise Exception(f"Volatility failed: {stderr.decode()}")
        
        # Parse JSON output
        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError:
            # Try to parse text output
            return {"text": stdout.decode(), "parsed": False}
    
    async def detect_injection(self, dump_path: Path) -> list[dict]:
        """Detect code injection using malfind."""
        results = await self._run_plugin(dump_path, "windows", "windows.malfind")
        return results.get("injections", [])
    
    async def detect_hollowing(self, dump_path: Path) -> list[dict]:
        """Detect process hollowing."""
        results = await self._run_plugin(dump_path, "windows", "windows.hollowfind")
        return results.get("hollowed", [])
    
    async def detect_api_hooks(self, dump_path: Path) -> list[dict]:
        """Detect API hooks."""
        results = await self._run_plugin(dump_path, "windows", "windows.apihooks")
        return results.get("hooks", [])
    
    async def get_process_tree(self, dump_path: Path) -> dict:
        """Get process tree."""
        return await self._run_plugin(dump_path, "windows", "windows.pstree")
    
    async def get_dll_list(self, dump_path: Path) -> dict:
        """Get DLL list for all processes."""
        return await self._run_plugin(dump_path, "windows", "windows.dlllist")
    
    async def get_handles(self, dump_path: Path) -> dict:
        """Get open handles."""
        return await self._run_plugin(dump_path, "windows", "windows.handles")
    
    async def get_cmdlines(self, dump_path: Path) -> dict:
        """Get command lines."""
        return await self._run_plugin(dump_path, "windows", "windows.cmdline")


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

class DeepAnalysisOrchestrator:
    """
    Orchestrates deep dynamic analysis combining CAPEv2 and Volatility3.
    """
    
    def __init__(
        self,
        cape_url: str = "http://cape-controller:8000",
        cape_token: str = "",
        enable_memory_analysis: bool = True,
    ):
        self.cape = CapeV2Client(cape_url, cape_token)
        self.volatility = VolatilityAnalyzer() if enable_memory_analysis else None
    
    async def analyze_sample(
        self,
        file_path: Path,
        profile: str = "win10-x64-clean",
        options: dict | None = None,
        memory_plugins: list[str] | None = None,
    ) -> CapeReport:
        """
        Full deep analysis pipeline:
        1. Submit to CAPEv2
        2. Wait for completion
        3. Get report
        4. Download PCAP
        5. Download memory dumps
        6. Run Volatility3 analysis
        7. Download dropped files
        8. Correlate all results
        """
        logger.info(f"Starting deep analysis for {file_path}")
        
        # ─── Submit to CAPEv2 ───
        task = await self.cape.submit_sample(file_path, profile, options)
        logger.info(f"Submitted task {task.task_id}")
        
        # ─── Wait for completion ───
        task = await self.cape.wait_for_completion(task.task_id)
        logger.info(f"Task {task.task_id} completed with status: {task.status}")
        
        if task.status in ("failed", "error"):
            raise Exception(f"Analysis failed: {task.error}")
        
        # ─── Get base report ───
        report = await self.cape.get_report(task.task_id)
        logger.info(f"Retrieved base report for task {task.task_id}")
        
        # ─── Download PCAP ───
        try:
            pcap_data = await self.cape.get_pcap(task.task_id)
            report.pcap_path = f"tasks/{task.task_id}/pcap.pcap"
            # Save PCAP for network forensics
            pcap_dir = Path(f"/opt/malinfo/storage/pcaps/{task.task_id}")
            pcap_dir.mkdir(parents=True, exist_ok=True)
            (pcap_dir / "pcap.pcap").write_bytes(pcap_data)
            report.network["pcap_saved"] = str(pcap_dir / "pcap.pcap")
        except Exception as exc:
            logger.warning(f"PCAP download failed: {exc}")
        
        # ─── Download memory dumps ───
        if self.volatility:
            await self._download_and_analyze_memory(task.task_id, report)
        
        # ─── Download dropped files ───
        await self._download_dropped_files(task.task_id, report)
        
        # ─── Download screenshots ───
        await self._download_screenshots(task.task_id, report)
        
        # ─── Final correlation ───
        report = self._correlate_results(report)
        
        logger.info(f"Deep analysis complete for task {task.task_id}")
        return report
    
    async def _download_and_analyze_memory(self, task_id: int, report: CapeReport):
        """Download memory dumps and run Volatility3."""
        # Get list of processes from report
        processes = report.processes
        
        # Download memory dump for each interesting process
        for proc in processes[:20]:  # Limit to first 20
            pid = proc.get("pid")
            if not pid:
                continue
            
            try:
                dump_data = await self.cape.get_memory_dump(task_id, pid)
                if not dump_data:
                    continue
                
                # Save dump
                dump_dir = Path(f"/opt/malinfo/storage/memory/{task_id}")
                dump_dir.mkdir(parents=True, exist_ok=True)
                dump_path = dump_dir / f"pid_{pid}.dmp"
                dump_path.write_bytes(dump_data)
                
                report.memory_dumps.append({
                    "pid": pid,
                    "process_name": proc.get("process_name", ""),
                    "path": str(dump_path),
                    "size": len(dump_data),
                })
                
                # Run Volatility3 analysis
                vol_results = await self.volatility.analyze_memory_dump(dump_path)
                report.volatility_results[f"pid_{pid}"] = vol_results
                
                # Extract specific findings
                await self._extract_volatility_findings(pid, vol_results, report)
                
            except Exception as exc:
                logger.warning(f"Memory analysis failed for PID {pid}: {exc}")
                report.memory_dumps.append({
                    "pid": pid,
                    "error": str(exc),
                })
    
    async def _extract_volatility_findings(self, pid: int, vol_results: dict, report: CapeReport):
        """Extract key findings from Volatility results."""
        # Malfind - code injection
        malfind = vol_results.get("windows.malfind", {})
        if malfind.get("injections"):
            for inj in malfind["injections"]:
                report.extracted_iocs.append({
                    "type": "memory_injection",
                    "pid": pid,
                    "address": inj.get("address"),
                    "protection": inj.get("protection"),
                    "details": inj,
                })
        
        # Hollowfind - process hollowing
        hollow = vol_results.get("windows.hollowfind", {})
        if hollow.get("hollowed"):
            for h in hollow["hollowed"]:
                report.extracted_iocs.append({
                    "type": "process_hollowing",
                    "pid": pid,
                    "target_pid": h.get("target_pid"),
                    "details": h,
                })
        
        # API hooks
        apihooks = vol_results.get("windows.apihooks", {})
        if apihooks.get("hooks"):
            for hook in apihooks["hooks"]:
                report.extracted_iocs.append({
                    "type": "api_hook",
                    "pid": pid,
                    "function": hook.get("function"),
                    "module": hook.get("module"),
                    "details": hook,
                })
        
        # Suspicious handles
        handles = vol_results.get("windows.handles", {})
        if handles.get("handles"):
            for h in handles["handles"]:
                if any(susp in str(h).lower() for susp in ["mutex", "section", "key", "token"]):
                    report.extracted_iocs.append({
                        "type": "suspicious_handle",
                        "pid": pid,
                        "handle": h,
                    })
    
    async def _download_dropped_files(self, task_id: int, report: CapeReport):
        """Download all dropped files."""
        dropped_list = await self.cape.get_dropped_files(task_id)
        
        drop_dir = Path(f"/opt/malinfo/storage/dropped/{task_id}")
        drop_dir.mkdir(parents=True, exist_ok=True)
        
        for dropped in dropped_list:
            sha256 = dropped.get("sha256")
            if not sha256:
                continue
            
            try:
                file_data = await self.cape.download_dropped_file(task_id, sha256)
                drop_path = drop_dir / f"{sha256}_{dropped.get('name', 'unknown')}"
                drop_path.write_bytes(file_data)
                
                dropped["local_path"] = str(drop_path)
                dropped["downloaded"] = True
                report.dropped_files.append(dropped)
                
            except Exception as exc:
                logger.warning(f"Failed to download dropped file {sha256}: {exc}")
                dropped["download_error"] = str(exc)
                report.dropped_files.append(dropped)
    
    async def _download_screenshots(self, task_id: int, report: CapeReport):
        """Download screenshots."""
        screenshots = await self.cape.get_screenshots(task_id)
        
        shot_dir = Path(f"/opt/malinfo/storage/screenshots/{task_id}")
        shot_dir.mkdir(parents=True, exist_ok=True)
        
        for shot in screenshots:
            shot_id = shot.get("id")
            if not shot_id:
                continue
            
            try:
                img_data = await self.cape.get_screenshot(task_id, shot_id)
                shot_path = shot_dir / f"shot_{shot_id}.png"
                shot_path.write_bytes(img_data)
                
                shot["local_path"] = str(shot_path)
                shot["downloaded"] = True
                report.screenshots.append(shot)
                
            except Exception as exc:
                logger.warning(f"Failed to download screenshot {shot_id}: {exc}")
    
    def _correlate_results(self, report: CapeReport) -> CapeReport:
        """Correlate findings across static, dynamic, network, and memory."""
        # Correlation logic would go here
        # For now, just add a correlation summary
        report.extracted_iocs.append({
            "type": "correlation_summary",
            "static_iocs": len([i for i in report.extracted_iocs if i.get("type") in ["file_hash", "domain", "ip"]]),
            "dynamic_iocs": len([i for i in report.extracted_iocs if i.get("type") in ["process", "registry", "filepath", "mutex"]]),
            "memory_iocs": len([i for i in report.extracted_iocs if i.get("type") in ["memory_injection", "process_hollowing", "api_hook"]]),
            "network_iocs": len(report.network_iocs),
        })
        return report
    
    async def close(self):
        """Close connections."""
        await self.cape.close()


# ──────────────────────────────────────────────────────────────────────────────
# Backward Compatibility
# ──────────────────────────────────────────────────────────────────────────────

async def detonate_sample(file_path: Path, target_os: str = "windows") -> dict:
    """Backward compatible detonation function."""
    # Map target_os to profile
    profile_map = {
        "windows": "win10-x64-clean",
        "linux": "ubuntu22-x64-clean",
        "android": "android13-x86-clean",
    }
    profile = profile_map.get(target_os, "win10-x64-clean")
    
    orchestrator = DeepAnalysisOrchestrator()
    try:
        report = await orchestrator.analyze_sample(file_path, profile)
        await orchestrator.close()
        return report.__dict__ if hasattr(report, "__dict__") else report
    except Exception as exc:
        await orchestrator.close()
        return {"error": str(exc), "available": False}


# Import regex for MITRE extraction
import re