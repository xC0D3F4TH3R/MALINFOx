"""
MALINFO — Central configuration.

All runtime configuration is sourced from environment variables (.env file
in production, real secrets manager for a government deployment — never
commit secrets to source control). See .env.example at the repo root.
"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- General ---------------------------------------------------------
    APP_NAME: str = "MALINFO"
    ENVIRONMENT: str = "development"        # development | staging | production
    DEBUG: bool = True
    API_PREFIX: str = "/api"

    # --- Storage -----------------------------------------------------------
    STORAGE_DIR: Path = BASE_DIR / "storage"
    UPLOAD_DIR: Path = BASE_DIR / "storage" / "uploads"
    REPORT_DIR: Path = BASE_DIR / "storage" / "reports"
    PCAP_DIR: Path = BASE_DIR / "storage" / "pcaps"
    MAX_UPLOAD_SIZE_MB: int = 250

    # --- Database -----------------------------------------------------------
    DATABASE_URL: str = f"sqlite+aiosqlite:///{BASE_DIR / 'storage' / 'malinfo.db'}"

    # --- YARA ----------------------------------------------------------------
    YARA_RULES_DIR: Path = BASE_DIR / "app" / "rules" / "yara"

    # --- VM Orchestrator --------------------------------------------------------
    # Built-in VM orchestration settings (alternative to CAPEv2)
    VM_ORCHESTRATOR_ENABLED: bool = True
    VM_STORAGE_DIR: Path = BASE_DIR / "storage" / "vms"
    VM_ISO_DIR: Path = BASE_DIR / "storage" / "isos"
    VM_AGENT_PORT: int = 9090
    LIBVIRT_URI: str = "qemu:///system"

    # --- Sandbox (CAPEv2 / Cuckoo-compatible REST API) ------------------------
    # Point this at your isolated detonation cluster. NEVER point this at
    # production infrastructure with internet egress unless the sandbox
    # network is deliberately firewalled / uses INetSim or FakeNet-NG for
    # simulated internet. See backend/app/sandbox/README.md
    SANDBOX_ENABLED: bool = False
    SANDBOX_API_URL: str = "http://cape-controller.internal:8000"
    SANDBOX_API_TOKEN: str = ""
    SANDBOX_POLL_INTERVAL_SEC: int = 15
    SANDBOX_TIMEOUT_SEC: int = 600
    SANDBOX_PROFILES: dict = {
        "windows": "win10-x64-clean",
        "linux": "ubuntu22-x64-clean",
        "android": "android13-x86-clean",
        # macOS: requires Apple Silicon host per Apple's virtualization
        # license (macOS SLA §2B). Not available on commodity cloud VMs.
        "macos": "unavailable-requires-apple-silicon-host",
        # iOS: no general dynamic-detonation sandbox exists for arbitrary
        # files without a managed jailbroken device farm. Static/manifest
        # analysis only.
        "ios": "static-analysis-only",
    }

    # --- Threat intel enrichment (optional) -----------------------------------
    VIRUSTOTAL_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    OTX_API_KEY: str | None = None
    MISP_URL: str | None = None
    MISP_API_KEY: str | None = None
    MISP_VERIFY_SSL: bool = True

    # --- Network monitoring / gateway integration -----------------------------
    # MALINFO does not sniff arbitrary third-party traffic. It exposes an
    # ICAP-compatible endpoint so an authorized network gateway (e.g. Squid,
    # a government CERT's secure web gateway, or an email gateway) can hand
    # files to MALINFO for inspection *before* they are delivered to the end
    # user, on infrastructure the deploying authority legally controls.
    ICAP_ENABLED: bool = False
    ICAP_LISTEN_PORT: int = 1344

    # --- Real-time file transfer monitoring -----------------------------------
    MONITOR_ENABLED: bool = False
    MONITOR_WATCH_PATHS: list[str] = []  # e.g. ["/var/mail", "/home/*/Downloads", "/tmp"]
    MONITOR_NETWORK_ENABLED: bool = False
    MONITOR_NETWORK_INTERFACE: str = "any"
    MONITOR_NETWORK_FILTER: str = "tcp or udp"
    MONITOR_AUTO_ANALYZE: bool = True

    # --- WebSocket / Real-time updates ----------------------------------------
    WS_ENABLED: bool = True
    WS_PING_INTERVAL: int = 30

    # --- Auth ------------------------------------------------------------------
    SECRET_KEY: str = "CHANGE_ME_BEFORE_DEPLOYMENT_USE_A_REAL_SECRET"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # --- CORS --------------------------------------------------------------
    ALLOWED_ORIGINS: list[str] = ["http://localhost:8080", "http://127.0.0.1:8080"]

    # --- Rate limiting -------------------------------------------------------
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60  # seconds

    # --- Audit logging -------------------------------------------------------
    AUDIT_LOG_RETENTION_DAYS: int = 365
    AUDIT_LOG_LEVEL: str = "info"  # debug, info, warning, critical


# --- Email / Agency Notification -------------------------------------------
    SMTP_HOST: str | None = None
    SMTP_PORT: int = 587
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_TLS: bool = True
    NOTIFICATION_FROM_EMAIL: str = "noreply@malinfo.gov"
    AGENCY_NOTIFICATION_EMAIL: str = "ary4ntom4r@gmail.com"

# --- Decompiler Integration ----------------------------------------------
    GHIDRA_PATH: str = "/opt/ghidra"
    RETDEC_PATH: str = "/usr/bin/retdec-decompiler"
    DECOMPILER_TIMEOUT_SEC: int = 300


settings = Settings()

# Ensure storage directories exist at import time
for _dir in (settings.UPLOAD_DIR, settings.REPORT_DIR, settings.PCAP_DIR):
    _dir.mkdir(parents=True, exist_ok=True)
