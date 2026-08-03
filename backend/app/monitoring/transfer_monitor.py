"""
Real-time file transfer monitoring and network activity analysis.
Integrates with system-level file monitoring, network taps, and gateway logs
to detect and analyze files being shared/transferred in real-time.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from app.analysis.pipeline import run_static_analysis
from app.analysis.risk_scoring import merge_dynamic_score
from app.config import settings
from app.database import AsyncSessionLocal
from app.models import IOC, AnalysisStatus, Sample, Verdict
from app.network_forensics.pcap_analyzer import analyze_pcap
from app.reporting.report_generator import (
    build_full_report,
    render_html_report,
    save_report,
)
from app.sandbox.orchestrator import detonate_sample

logger = logging.getLogger("malinfo.monitor")

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TransferEvent:
    """Represents a file transfer event detected by the monitor."""
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_path: str = ""
    dest_path: str = ""
    process_name: str = ""
    process_pid: int = 0
    user: str = ""
    file_size: int = 0
    file_hash: str = ""
    transfer_type: str = "copy"  # copy, move, upload, download, share
    network_info: dict = field(default_factory=dict)  # src_ip, dst_ip, protocol, port
    analyzed: bool = False
    verdict: str = "pending"
    risk_score: float = 0.0


@dataclass
class NetworkFlow:
    """Represents a network flow for C2 detection."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: datetime | None = None
    bytes_sent: int = 0
    bytes_recv: int = 0
    packet_count: int = 0
    process_name: str = ""
    process_pid: int = 0


class FileSystemMonitor(FileSystemEventHandler):
    """Monitors filesystem for file creation/modification in watched directories."""

    def __init__(self, watch_paths: list[str], callback: Callable[[TransferEvent], None]):
        self.watch_paths = [Path(p).resolve() for p in watch_paths]
        self.callback = callback
        self.observer = Observer()
        self._recent_events = deque(maxlen=1000)
        self._processing = set()

    def start(self):
        """Start monitoring all watch paths."""
        for path in self.watch_paths:
            if path.exists():
                self.observer.schedule(self, str(path), recursive=True)
                logger.info(f"Monitoring filesystem: {path}")
            else:
                logger.warning(f"Watch path does not exist: {path}")
        self.observer.start()

    def stop(self):
        """Stop monitoring."""
        self.observer.stop()
        self.observer.join()

    def on_created(self, event):
        if not event.is_directory:
            self._handle_event(event, "create")

    def on_modified(self, event):
        if not event.is_directory:
            self._handle_event(event, "modify")

    def _handle_event(self, event, event_type: str):
        """Process filesystem event."""
        src_path = Path(event.src_path).resolve()

        # Check if path is under watched directory
        if not any(src_path.is_relative_to(wp) for wp in self.watch_paths):
            return

        # Debounce rapid events on same file
        event_key = f"{src_path}:{event_type}"
        if event_key in self._processing:
            return
        self._processing.add(event_key)

        # Schedule async processing
        asyncio.create_task(self._process_file_event(src_path, event_type))

        # Clean up processing set after delay
        asyncio.create_task(self._clear_processing(event_key))

    async def _clear_processing(self, event_key: str):
        await asyncio.sleep(2)
        self._processing.discard(event_key)

    async def _process_file_event(self, file_path: Path, event_type: str):
        """Process a file creation/modification event."""
        try:
            # Wait a moment for file to be fully written
            await asyncio.sleep(0.5)

            if not file_path.exists():
                return

            stat = file_path.stat()
            if stat.st_size == 0:
                return

            # Compute hash
            file_hash = self._compute_hash(file_path)

            # Create transfer event
            transfer = TransferEvent(
                source_path=str(file_path),
                dest_path=str(file_path),
                file_size=stat.st_size,
                file_hash=file_hash,
                transfer_type=event_type,
                process_name=self._get_process_for_file(file_path),
                user=self._get_file_owner(file_path),
            )

            self._recent_events.append(transfer)

            # Analyze immediately if enabled
            if settings.MONITOR_AUTO_ANALYZE:
                await self.callback(transfer)

        except Exception as exc:
            logger.error(f"Error processing file event {file_path}: {exc}")

    def _compute_hash(self, file_path: Path) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
        except Exception:
            pass
        return sha256.hexdigest()

    def _get_process_for_file(self, file_path: Path) -> str:
        """Try to determine which process created/modified the file."""
        try:
            # This is a best-effort approach - on Linux we can check /proc
            # For now return unknown
            return "unknown"
        except Exception:
            return "unknown"

    def _get_file_owner(self, file_path: Path) -> str:
        """Get file owner username."""
        try:
            import pwd
            stat = file_path.stat()
            return pwd.getpwuid(stat.st_uid).pw_name
        except Exception:
            return "unknown"


class NetworkMonitor:
    """
    Monitors network traffic for suspicious connections and C2 beaconing.
    Can integrate with Zeek, Suricata, or raw packet capture.
    """

    def __init__(self, interface: str = "any", bpf_filter: str = ""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flows: dict[str, NetworkFlow] = {}
        self._running = False
        self._capture_task: asyncio.Task | None = None

    async def start(self):
        """Start network monitoring."""
        self._running = True
        logger.info(f"Starting network monitor on interface {self.interface}")

        # Try to use scapy for live capture
        try:
            from scapy.all import AsyncSniffer
            self._sniffer = AsyncSniffer(
                iface=self.interface if self.interface != "any" else None,
                filter=self.bpf_filter,
                prn=self._process_packet,
                store=False,
            )
            self._sniffer.start()
        except Exception as exc:
            logger.warning(f"Could not start live packet capture: {exc}")
            logger.info("Network monitor running in log-analysis mode only")

    async def stop(self):
        """Stop network monitoring."""
        self._running = False
        if hasattr(self, "_sniffer") and self._sniffer:
            self._sniffer.stop()
        logger.info("Network monitor stopped")

    def _process_packet(self, pkt):
        """Process captured packet."""
        try:
            from scapy.all import IP, TCP, UDP
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            src_ip, dst_ip = ip_layer.src, ip_layer.dst

            # Skip private/local traffic for C2 detection
            if self._is_private_ip(src_ip) and self._is_private_ip(dst_ip):
                return

            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"
            src_port = pkt[TCP].sport if proto == "TCP" else pkt[UDP].sport if proto == "UDP" else 0
            dst_port = pkt[TCP].dport if proto == "TCP" else pkt[UDP].dport if proto == "UDP" else 0

            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}"
            now = datetime.utcnow()

            if flow_key not in self.flows:
                self.flows[flow_key] = NetworkFlow(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    start_time=now,
                )

            flow = self.flows[flow_key]
            flow.end_time = now
            flow.bytes_sent += len(pkt)
            flow.packet_count += 1

            # Check for beaconing
            self._check_beaconing(flow)

        except Exception as exc:
            logger.debug(f"Packet processing error: {exc}")

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved."""
        private_prefixes = ("10.", "127.", "169.254.", "192.168.")
        if ip.startswith(private_prefixes):
            return True
        if ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
                return 16 <= second <= 31
            except (IndexError, ValueError):
                return False
        return False

    def _check_beaconing(self, flow: NetworkFlow):
        """Check if flow exhibits beaconing behavior."""
        # This is a simplified check - real implementation would track
        # intervals over time and compute coefficient of variation
        if flow.packet_count > 10 and flow.end_time and flow.start_time:
            duration = (flow.end_time - flow.start_time).total_seconds()
            if duration > 0:
                interval = duration / flow.packet_count
                # Flag if very regular intervals (potential beaconing)
                if 10 < interval < 3600:  # 10 seconds to 1 hour
                    logger.warning(
                        f"Potential beaconing detected: {flow.src_ip}:{flow.src_port} -> "
                        f"{flow.dst_ip}:{flow.dst_port} ({flow.protocol}) "
                        f"interval={interval:.1f}s count={flow.packet_count}"
                    )

    def get_suspicious_flows(self, min_packets: int = 5) -> list[NetworkFlow]:
        """Get flows that may indicate C2 communication."""
        return [
            f for f in self.flows.values()
            if f.packet_count >= min_packets and not self._is_private_ip(f.dst_ip)
        ]


class TransferAnalyzer:
    """
    Analyzes transfer events - runs static analysis, triggers sandbox,
    performs network forensics, and generates reports.
    """

    def __init__(self):
        self.pending_queue: asyncio.Queue = asyncio.Queue()
        self.results: dict[str, dict] = {}
        self._worker_task: asyncio.Task | None = None

    async def start(self):
        """Start the analysis worker."""
        self._worker_task = asyncio.create_task(self._worker())
        logger.info("Transfer analyzer started")

    async def stop(self):
        """Stop the analysis worker."""
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Transfer analyzer stopped")

    async def analyze(self, transfer: TransferEvent):
        """Queue a transfer for analysis."""
        await self.pending_queue.put(transfer)

    async def _worker(self):
        """Background worker that processes analysis queue."""
        while True:
            try:
                transfer = await self.pending_queue.get()
                await self._process_transfer(transfer)
                self.pending_queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error(f"Analysis worker error: {exc}")
                await asyncio.sleep(1)

    async def _process_transfer(self, transfer: TransferEvent):
        """Process a single transfer event."""
        logger.info(f"Analyzing transfer: {transfer.source_path} (hash: {transfer.file_hash[:16]}...)")

        try:
            # Check if already analyzed
            async with AsyncSessionLocal() as db:
                from sqlalchemy import select
                result = await db.execute(
                    select(Sample).where(Sample.sha256 == transfer.file_hash)
                )
                existing = result.scalar_one_or_none()

                if existing and existing.status == AnalysisStatus.COMPLETE:
                    transfer.analyzed = True
                    transfer.verdict = existing.verdict.value
                    transfer.risk_score = existing.risk_score
                    self.results[transfer.event_id] = {
                        "sample_id": existing.id,
                        "verdict": existing.verdict.value,
                        "risk_score": existing.risk_score,
                    }
                    logger.info(f"Already analyzed: {existing.id} -> {existing.verdict.value}")
                    return

            # Need to analyze - copy file to analysis directory
            source_path = Path(transfer.source_path)
            if not source_path.exists():
                logger.warning(f"Source file no longer exists: {source_path}")
                return

            # Create analysis directory
            analysis_dir = settings.UPLOAD_DIR / "monitored"
            analysis_dir.mkdir(parents=True, exist_ok=True)

            dest_path = analysis_dir / f"{transfer.event_id}__{source_path.name}"
            import shutil
            shutil.copy2(source_path, dest_path)

            # Run static analysis
            static_report = run_static_analysis(dest_path)

            # Store in database
            async with AsyncSessionLocal() as db:
                sample = Sample(
                    id=transfer.event_id,
                    original_filename=source_path.name,
                    stored_path=str(dest_path),
                    file_size=transfer.file_size,
                    sha256=static_report["hashes"]["sha256"],
                    sha1=static_report["hashes"]["sha1"],
                    md5=static_report["hashes"]["md5"],
                    ssdeep=static_report["hashes"].get("ssdeep"),
                    file_type=static_report["file_type"],
                    mime_type=static_report["mime_type"],
                    target_os=static_report["target_os"],
                    status=AnalysisStatus.STATIC_DONE,
                    verdict=Verdict(static_report["verdict"]),
                    risk_score=static_report["risk_score"],
                    source="monitor_intercept",
                    static_report=static_report,
                )
                db.add(sample)

                for ioc in static_report.get("iocs", []):
                    db.add(IOC(
                        sample_id=sample.id,
                        ioc_type=ioc["ioc_type"],
                        value=ioc["value"],
                        context=ioc.get("context"),
                        confidence=ioc["confidence"],
                    ))
                await db.commit()

            transfer.analyzed = True
            transfer.verdict = static_report["verdict"]
            transfer.risk_score = static_report["risk_score"]

            # Trigger sandbox if malicious/suspicious
            sandbox_report = None
            network_report = None

            if static_report["verdict"] in ("suspicious", "malicious") and settings.SANDBOX_ENABLED:
                sample.status = AnalysisStatus.SANDBOX_RUNNING
                await db.commit()

                sandbox_report = await detonate_sample(dest_path, static_report["target_os"])
                sample.sandbox_report = sandbox_report

                if sandbox_report.get("available") and sandbox_report.get("pcap_path"):
                    sample.status = AnalysisStatus.NETWORK_ANALYSIS
                    await db.commit()

                    network_report = analyze_pcap(Path(sandbox_report["pcap_path"]))
                    sample.network_report = network_report

                # Merge scores
                final_score = merge_dynamic_score(
                    {"risk_score": sample.risk_score, "reasons": static_report["risk_reasons"]},
                    sandbox_report, network_report,
                )
                sample.risk_score = final_score["risk_score"]
                sample.verdict = Verdict(final_score["verdict"])

            # Generate final report
            full_report = build_full_report(sample, static_report, sandbox_report, network_report)
            html = render_html_report(full_report)
            save_report(sample.id, full_report, html)

            sample.status = AnalysisStatus.COMPLETE
            await db.commit()

            # Update transfer with final results
            transfer.verdict = sample.verdict.value
            transfer.risk_score = sample.risk_score

            self.results[transfer.event_id] = {
                "sample_id": sample.id,
                "verdict": sample.verdict.value,
                "risk_score": sample.risk_score,
                "report_path": str(settings.REPORT_DIR / f"{sample.id}.html"),
            }

            # Alert if malicious
            if sample.verdict == Verdict.MALICIOUS:
                await self._alert_malicious(transfer, full_report)

            logger.info(f"Analysis complete: {transfer.event_id} -> {sample.verdict.value} ({sample.risk_score})")

        except Exception as exc:
            logger.exception(f"Failed to analyze transfer {transfer.event_id}: {exc}")
            transfer.verdict = "error"
            self.results[transfer.event_id] = {"error": str(exc)}

    async def _alert_malicious(self, transfer: TransferEvent, report: dict):
        """Send alert for malicious detection."""
        # This would integrate with alerting systems (email, Slack, SIEM, etc.)
        logger.critical(
            f"MALICIOUS FILE DETECTED: {transfer.source_path} "
            f"| Hash: {transfer.file_hash} | Risk: {transfer.risk_score} "
            f"| Report: {settings.REPORT_DIR / f'{transfer.event_id}.html'}"
        )
        # TODO: Integrate with notification systems


class MonitoringService:
    """
    Main monitoring service that coordinates filesystem monitoring,
    network monitoring, and transfer analysis.
    """

    def __init__(self):
        self.fs_monitor: FileSystemMonitor | None = None
        self.net_monitor: NetworkMonitor | None = None
        self.analyzer = TransferAnalyzer()
        self._running = False

    async def start(self):
        """Start all monitoring components."""
        self._running = True

        # Start analyzer
        await self.analyzer.start()

        # Start filesystem monitor
        watch_paths = settings.MONITOR_WATCH_PATHS
        if watch_paths:
            self.fs_monitor = FileSystemMonitor(
                watch_paths,
                callback=self.analyzer.analyze
            )
            self.fs_monitor.start()

        # Start network monitor
        if settings.MONITOR_NETWORK_ENABLED:
            self.net_monitor = NetworkMonitor(
                interface=settings.MONITOR_NETWORK_INTERFACE,
                bpf_filter=settings.MONITOR_NETWORK_FILTER,
            )
            await self.net_monitor.start()

        logger.info("Monitoring service started")

    async def stop(self):
        """Stop all monitoring components."""
        self._running = False

        if self.fs_monitor:
            self.fs_monitor.stop()

        if self.net_monitor:
            await self.net_monitor.stop()

        await self.analyzer.stop()

        logger.info("Monitoring service stopped")

    def get_recent_transfers(self, limit: int = 100) -> list[TransferEvent]:
        """Get recent transfer events."""
        if self.fs_monitor:
            return list(self.fs_monitor._recent_events)[-limit:]
        return []

    def get_analysis_result(self, event_id: str) -> dict | None:
        """Get analysis result for a transfer event."""
        return self.analyzer.results.get(event_id)

    def get_suspicious_network_flows(self) -> list[NetworkFlow]:
        """Get suspicious network flows."""
        if self.net_monitor:
            return self.net_monitor.get_suspicious_flows()
        return []


# Global monitoring service instance
_monitoring_service: MonitoringService | None = None


async def start_monitoring():
    """Start the global monitoring service."""
    global _monitoring_service
    if settings.MONITOR_ENABLED:
        _monitoring_service = MonitoringService()
        await _monitoring_service.start()
        logger.info("Real-time monitoring enabled")
    else:
        logger.info("Real-time monitoring disabled (set MONITOR_ENABLED=true to enable)")


async def stop_monitoring():
    """Stop the global monitoring service."""
    global _monitoring_service
    if _monitoring_service:
        await _monitoring_service.stop()
        _monitoring_service = None


def get_monitoring_service() -> MonitoringService | None:
    """Get the global monitoring service instance."""
    return _monitoring_service