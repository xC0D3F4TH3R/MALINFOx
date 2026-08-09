"""
Security middleware for MALINFO backend.
Provides comprehensive security headers, CSRF protection, rate limiting,
and request validation.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from redis.asyncio import Redis
    from starlette.types import ASGIApp

from app.config import settings

logger = logging.getLogger("malinfo.security")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Adds comprehensive security headers to all responses.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Strict Transport Security (HSTS)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS Protection (legacy but still useful)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' wss: https:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        # Permissions Policy (formerly Feature Policy)
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        # Cross-Origin policies
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # Remove server header
        response.headers.pop("Server", None)

        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection using double-submit cookie pattern.
    """

    def __init__(self, app: ASGIApp, excluded_paths: list[str] | None = None):
        super().__init__(app)
        self.excluded_paths = excluded_paths or [
            "/api/health",
            "/api/public/report",
            "/metrics",
            "/api/auth/login",
            "/api/auth/refresh",
        ]

    async def dispatch(self, request: Request, call_next):
        # Skip CSRF for safe methods
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await call_next(request)

        # Skip excluded paths
        if any(request.url.path.startswith(path) for path in self.excluded_paths):
            return await call_next(request)

        # Skip if API key authentication (stateless)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer mk_"):
            return await call_next(request)

        # Check CSRF token
        csrf_cookie = request.cookies.get("csrf_token")
        csrf_header = request.headers.get("X-CSRF-Token")

        if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
            logger.warning(
                "CSRF validation failed",
                extra={"path": request.url.path, "client": request.client.host if request.client else "unknown"}
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF token validation failed"}
            )

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Redis-backed rate limiting with configurable windows.
    """

    def __init__(self, app: ASGIApp, redis_client: Redis | None = None):
        super().__init__(app)
        self.redis = redis_client
        self.default_limit = 100
        self.default_window = 60  # seconds

    async def _get_client_key(self, request: Request) -> str:
        """Generate rate limit key from client IP and path."""
        client_ip = request.client.host if request.client else "unknown"
        # Include user ID if authenticated
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            # Hash the token to avoid storing it
            token_hash = hashlib.sha256(auth_header[7:].encode()).hexdigest()[:16]
            return f"ratelimit:{client_ip}:{token_hash}:{request.url.path}"
        return f"ratelimit:{client_ip}:{request.url.path}"

    async def dispatch(self, request: Request, call_next):
        if not settings.RATE_LIMIT_ENABLED or not self.redis:
            return await call_next(request)

        # Skip rate limiting for health checks
        if request.url.path in ("/api/health", "/metrics"):
            return await call_next(request)

        key = await self._get_client_key(request)
        current = await self.redis.get(key)

        if current is None:
            await self.redis.setex(key, self.default_window, 1)
            return await call_next(request)

        count = int(current)
        if count >= self.default_limit:
            retry_after = await self.redis.ttl(key)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_after
                },
                headers={"Retry-After": str(retry_after)}
            )

        await self.redis.incr(key)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.default_limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.default_limit - count - 1))
        response.headers["X-RateLimit-Reset"] = str(await self.redis.ttl(key))
        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """
    Validates and sanitizes incoming requests.
    """

    # Maximum request body size (10MB)
    MAX_BODY_SIZE = 10 * 1024 * 1024

    # Dangerous patterns to detect
    SUSPICIOUS_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # XSS attempts
        r"javascript:",  # javascript: URLs
        r"on\w+\s*=",  # Event handlers
        r"\b(union|select|insert|update|delete|drop|alter|create)\b",  # SQL injection
        r"(\.\./|\.\.\\)",  # Path traversal
        r"<\?php",  # PHP code injection
        r"eval\s*\(",  # eval() attempts
        r"document\.cookie",  # Cookie theft
    ]

    async def dispatch(self, request: Request, call_next):
        # Check content length
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.MAX_BODY_SIZE:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"}
            )

        # For multipart/form-data, we can't easily inspect without consuming
        # The upload endpoint handles its own validation

        # Check for suspicious patterns in query parameters
        query_string = str(request.url.query)
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, query_string, re.IGNORECASE):
                logger.warning(
                    "Suspicious query parameter detected",
                    extra={
                        "pattern": pattern,
                        "query": query_string[:200],
                        "client": request.client.host if request.client else "unknown",
                        "path": request.url.path
                    }
                )
                # Don't block - just log for monitoring
                # In high-security mode, you could return 400

        return await call_next(request)


class SecureErrorMiddleware(BaseHTTPMiddleware):
    """
    Prevents information disclosure in error responses.
    """

    async def dispatch(self, request: Request, call_next):
        try:
            return await call_next(request)
        except HTTPException:
            raise  # Re-raise HTTP exceptions as-is
        except Exception as exc:
            logger.exception("Unhandled exception", extra={"path": request.url.path})
            # Return generic error - never expose stack traces or internal details
            if settings.DEBUG:
                # In debug mode, include error type for developers
                return JSONResponse(
                    status_code=500,
                    content={"detail": "Internal server error", "type": type(exc).__name__}
                )
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"}
            )


def setup_security_middleware(app):
    """Configure all security middleware in the correct order."""
    # Order matters: outermost first

    # 1. Error handling (catches everything)
    app.add_middleware(SecureErrorMiddleware)

    # 2. Request validation
    app.add_middleware(RequestValidationMiddleware)

    # 3. Rate limiting (after validation, before auth)
    # Note: RateLimitMiddleware needs Redis client - initialize in main.py

    # 4. CSRF protection
    app.add_middleware(CSRFMiddleware)

    # 5. Security headers (outermost - applies to all responses)
    app.add_middleware(SecurityHeadersMiddleware)