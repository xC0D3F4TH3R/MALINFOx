"""
Client for a CAPEv2 (or Cuckoo-compatible) sandbox cluster's REST API.

MALINFO does not implement its own hypervisor orchestration — that is a
mature, hard problem (VM snapshot management, network isolation, guest
agents) that CAPEv2 already solves well. This client submits samples to
a CAPEv2 controller and retrieves results; you point SANDBOX_API_URL at
a real CAPEv2 deployment. See sandbox/README.md for how to stand one up
per target OS.

CAPEv2 REST API reference (matches the actual project's `/apiv2/` routes):
  POST /apiv2/tasks/create/file/   — submit a sample
  GET  /apiv2/tasks/view/{id}/     — poll task status
  GET  /apiv2/tasks/report/{id}/   — retrieve the JSON report
"""
from __future__ import annotations

import logging
from pathlib import Path

import requests
from tenacity import retry, stop_after_attempt, wait_fixed

from app.config import settings

logger = logging.getLogger("malinfo.sandbox")


class SandboxUnavailableError(RuntimeError):
    pass


class CapeV2Client:
    def __init__(self, base_url: str | None = None, token: str | None = None):
        self.base_url = (base_url or settings.SANDBOX_API_URL).rstrip("/")
        self.token = token or settings.SANDBOX_API_TOKEN
        self.session = requests.Session()
        if self.token:
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})

    def submit_file(self, file_path: Path, platform: str = "windows", timeout: int = 30) -> str:
        """Submit a sample for detonation. Returns the CAPEv2 task ID."""
        if not settings.SANDBOX_ENABLED:
            raise SandboxUnavailableError(
                "Dynamic sandbox analysis is disabled (SANDBOX_ENABLED=false). "
                "Enable it once a CAPEv2 cluster is deployed and reachable — "
                "see backend/app/sandbox/README.md."
            )

        profile = settings.SANDBOX_PROFILES.get(platform)
        if not profile or "unavailable" in profile or "static-analysis-only" in profile:
            raise SandboxUnavailableError(
                f"No dynamic sandbox profile available for platform '{platform}'. {profile}"
            )

        url = f"{self.base_url}/apiv2/tasks/create/file/"
        with open(file_path, "rb") as fh:
            files = {"file": (file_path.name, fh)}
            data = {"machine": profile, "timeout": settings.SANDBOX_TIMEOUT_SEC}
            resp = self.session.post(url, files=files, data=data, timeout=timeout)
        resp.raise_for_status()
        payload = resp.json()
        task_id = payload.get("data", {}).get("task_ids", [None])[0]
        if task_id is None:
            raise SandboxUnavailableError(f"Unexpected CAPEv2 response: {payload}")
        logger.info("Submitted sample %s to sandbox as task %s (profile=%s)", file_path.name, task_id, profile)
        return str(task_id)

    @retry(wait=wait_fixed(5), stop=stop_after_attempt(3))
    def get_status(self, task_id: str) -> str:
        url = f"{self.base_url}/apiv2/tasks/view/{task_id}/"
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        return resp.json().get("data", {}).get("status", "unknown")

    def get_report(self, task_id: str) -> dict:
        url = f"{self.base_url}/apiv2/tasks/report/{task_id}/"
        resp = self.session.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_pcap(self, task_id: str, save_to: Path) -> Path:
        """Download the network capture recorded during detonation."""
        url = f"{self.base_url}/apiv2/tasks/get/pcap/{task_id}/"
        resp = self.session.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        with open(save_to, "wb") as out:
            out.writelines(resp.iter_content(chunk_size=8192))
        return save_to
