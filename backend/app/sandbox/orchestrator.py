"""
Routes a sample to the correct detonation profile based on its detected
target OS, polls until complete, and normalizes the result shape that the
risk-scoring engine and report generator expect.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from app.config import settings
from app.sandbox.capev2_client import CapeV2Client, SandboxUnavailableError

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger("malinfo.sandbox.orchestrator")

TERMINAL_STATES = {"reported", "completed", "failed_analysis", "failed_processing"}


async def detonate_sample(file_path: Path, target_os: str) -> dict:
    """
    Submits to the sandbox cluster and polls to completion.
    Returns a normalized dict — never raises for expected "not available"
    conditions (iOS, macOS without Apple Silicon hosts, sandbox disabled),
    it returns a clear `available: False` payload instead so the caller can
    surface that plainly in the report rather than crash the pipeline.
    """
    client = CapeV2Client()

    try:
        task_id = client.submit_file(file_path, platform=target_os)
    except SandboxUnavailableError as exc:
        return {"available": False, "reason": str(exc)}
    except Exception as exc:
        logger.exception("Sandbox submission failed")
        return {"available": False, "reason": f"Submission error: {exc}"}

    elapsed = 0
    while elapsed < settings.SANDBOX_TIMEOUT_SEC:
        await asyncio.sleep(settings.SANDBOX_POLL_INTERVAL_SEC)
        elapsed += settings.SANDBOX_POLL_INTERVAL_SEC
        try:
            status = client.get_status(task_id)
        except Exception as exc:
            logger.warning("Status poll failed for task %s: %s", task_id, exc)
            continue

        if status in TERMINAL_STATES:
            break
    else:
        return {"available": False, "reason": f"Sandbox task {task_id} timed out after {elapsed}s", "task_id": task_id}

    try:
        report = client.get_report(task_id)
    except Exception as exc:
        return {"available": False, "reason": f"Failed to retrieve report: {exc}", "task_id": task_id}

    pcap_path = None
    try:
        pcap_path = settings.PCAP_DIR / f"{task_id}.pcap"
        client.get_pcap(task_id, pcap_path)
    except Exception as exc:
        logger.info("No PCAP retrieved for task %s: %s", task_id, exc)
        pcap_path = None

    return {
        "available": True,
        "task_id": task_id,
        "malscore": report.get("info", {}).get("score", 0),
        "signatures": [s.get("description") for s in report.get("signatures", [])],
        "dropped_files": [f.get("name") for f in report.get("dropped", [])],
        "network_summary": report.get("network", {}),
        "pcap_path": str(pcap_path) if pcap_path and pcap_path.exists() else None,
        "screenshots_available": bool(report.get("shots")),
    }
