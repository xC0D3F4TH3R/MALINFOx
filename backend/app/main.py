from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from redis.asyncio import Redis

from app.config import settings
from app.database import init_db
from app.gateway.icap_server import start_icap_server, stop_icap_server
from app.monitoring.transfer_monitor import start_monitoring, stop_monitoring
from app.routers import (
    auth,
    decompiler,
    monitoring,
    public_report,
    reports,
    sandbox,
    threat_intel,
    upload,
    vm_orchestrator,
    yara,
)
from app.security_middleware import (
    CSRFMiddleware,
    RateLimitMiddleware,
    RequestValidationMiddleware,
    SecureErrorMiddleware,
    SecurityHeadersMiddleware,
    setup_security_middleware,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("malinfo")

# Global Redis client for rate limiting
redis_client: Redis | None = None

# Prometheus metrics
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total", "Total HTTP requests",
    ["method", "handler", "status"]
)
HTTP_REQUEST_DURATION = Histogram(
    "http_request_duration_seconds", "HTTP request duration",
    ["method", "handler"]
)
ANALYSIS_QUEUE_DEPTH = Gauge("malinfo_analysis_queue_depth", "Static analysis queue depth")
ANALYSIS_COMPLETED = Counter("malinfo_analysis_completed_total", "Completed analyses", ["verdict"])
ANALYSIS_FAILURES = Counter("malinfo_analysis_failures_total", "Failed analyses")
ANALYSIS_DURATION = Histogram("malinfo_analysis_duration_seconds", "Analysis duration")
SANDBOX_SUBMITTED = Counter("malinfo_sandbox_submitted_total", "Sandbox tasks submitted")
SANDBOX_COMPLETED = Counter("malinfo_sandbox_completed_total", "Sandbox tasks completed")
SANDBOX_FAILED = Counter("malinfo_sandbox_failed_total", "Sandbox tasks failed")
SANDBOX_MALSCORE = Histogram("malinfo_sandbox_malscore", "Sandbox malScore")
SANDBOX_AVAILABLE = Gauge("malinfo_sandbox_available", "Sandbox availability (1=available, 0=unavailable)")
YARA_MATCHES = Counter("malinfo_yara_matches_total", "YARA rule matches")
YARA_RULES_TRIGGERED = Counter("malinfo_yara_rules_triggered_total", "YARA rules triggered")
MITRE_TECHNIQUE_DETECTED = Counter("malinfo_mitre_technique_detected_total", "MITRE techniques detected", ["technique"])
TRANSFER_ALERTS = Counter("malinfo_transfer_alerts_total", "File transfer alerts")
AUTH_FAILURES = Counter("malinfo_auth_failures_total", "Authentication failures")
ACCOUNT_LOCKOUTS = Counter("malinfo_account_lockouts_total", "Account lockouts")
THREAT_INTEL_SYNC_STATUS = Gauge("malinfo_threat_intel_last_sync_status", "Threat intel sync status (1=success, 0=failure)", ["feed"])
THREAT_INTEL_LAST_SYNC = Gauge("malinfo_threat_intel_last_sync_timestamp", "Threat intel last sync timestamp", ["feed"])
RATE_LIMIT_HITS = Counter("malinfo_rate_limit_hits_total", "Rate limit hits", ["endpoint"])
CSRF_FAILURES = Counter("malinfo_csrf_failures_total", "CSRF validation failures")

app = FastAPI(
    title="MALINFO",
    description=(
        "National malware analysis & C2 intelligence platform — static analysis, "
        "dynamic sandbox detonation, network forensics, and public threat reporting."
    ),
    version="1.0.0-pilot",
)

# Setup security middleware
setup_security_middleware(app)

# Add rate limiting middleware with Redis
if settings.RATE_LIMIT_ENABLED:
    app.add_middleware(RateLimitMiddleware, redis_client=None)  # Will be set in startup

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
    max_age=3600,
)

# Prometheus metrics middleware
@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    HTTP_REQUESTS_TOTAL.labels(
        method=request.method,
        handler=request.url.path,
        status=response.status_code
    ).inc()
    HTTP_REQUEST_DURATION.labels(
        method=request.method,
        handler=request.url.path
    ).observe(duration)
    
    return response


@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    # Startup
    await init_db()
    logger.info("MALINFO backend started. Environment=%s SandboxEnabled=%s", settings.ENVIRONMENT, settings.SANDBOX_ENABLED)
    
    # Initialize Redis for rate limiting
    if settings.RATE_LIMIT_ENABLED:
        try:
            redis_client = Redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
            await redis_client.ping()
            logger.info("Redis connected for rate limiting")
        except Exception as e:
            logger.warning("Failed to connect to Redis for rate limiting: %s", e)
            redis_client = None
    
    # Start monitoring service if enabled
    if settings.MONITOR_ENABLED:
        await start_monitoring()
    
    # Start ICAP server if enabled
    if settings.ICAP_ENABLED:
        await start_icap_server()
    
    yield
    
    # Shutdown
    if redis_client:
        await redis_client.close()
    await stop_monitoring()
    await stop_icap_server()
    logger.info("MALINFO backend shutdown complete")


app.router.lifespan_context = lifespan


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "app": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "sandbox_enabled": settings.SANDBOX_ENABLED,
        "monitoring_enabled": settings.MONITOR_ENABLED,
        "icap_enabled": settings.ICAP_ENABLED,
    }


# CSRF token endpoint for frontend
@app.get("/api/csrf-token")
async def get_csrf_token(response: Response):
    """Generate and return a CSRF token as a secure cookie."""
    import secrets
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=True,
        secure=settings.ENVIRONMENT == "production",
        samesite="strict",
        max_age=3600,
        path="/"
    )
    return {"csrf_token": csrf_token}


app.include_router(auth.router, prefix=settings.API_PREFIX)
app.include_router(upload.router, prefix=settings.API_PREFIX)
app.include_router(reports.router, prefix=settings.API_PREFIX)
app.include_router(sandbox.router, prefix=settings.API_PREFIX)
app.include_router(public_report.router, prefix=settings.API_PREFIX)
app.include_router(monitoring.router, prefix=settings.API_PREFIX)
app.include_router(threat_intel.router, prefix=settings.API_PREFIX)
app.include_router(yara.router, prefix=settings.API_PREFIX)
app.include_router(vm_orchestrator.router, prefix=settings.API_PREFIX)
app.include_router(decompiler.router, prefix=settings.API_PREFIX)

# Serve the report storage directory read-only for direct HTML report links
app.mount("/reports-static", StaticFiles(directory=str(settings.REPORT_DIR)), name="reports-static")