#!/usr/bin/env python3
"""
MALINFO — Health Check Script
Comprehensive health checks for all system components
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Any
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

import psycopg2
import redis


@dataclass
class HealthCheck:
    name: str
    status: str  # healthy, degraded, unhealthy
    message: str
    latency_ms: float | None = None
    details: dict | None = None


class HealthChecker:
    def __init__(self, base_url: str = "https://localhost", timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.checks: list[HealthCheck] = []

    def _record(self, name: str, status: str, message: str, latency_ms: float | None = None, details: dict | None = None):
        self.checks.append(HealthCheck(name, status, message, latency_ms, details))

    def _http_get(self, path: str, expected_status: int = 200) -> tuple[bool, float, dict | None]:
        """Make HTTP GET request, return (success, latency_ms, response_data)"""
        url = f"{self.base_url}{path}"
        start = time.time()
        try:
            req = Request(url, headers={"User-Agent": "MALINFO-HealthCheck/1.0"})
            with urlopen(req, timeout=self.timeout) as resp:
                latency = (time.time() - start) * 1000
                data = json.loads(resp.read().decode()) if resp.headers.get("content-type", "").startswith("application/json") else {}
                return resp.status == expected_status, latency, data
        except HTTPError as e:
            latency = (time.time() - start) * 1000
            return False, latency, {"error": f"HTTP {e.code}", "body": e.read().decode()[:200]}
        except URLError as e:
            latency = (time.time() - start) * 1000
            return False, latency, {"error": str(e)}
        except Exception as e:
            latency = (time.time() - start) * 1000
            return False, latency, {"error": str(e)}

    def check_api_health(self) -> HealthCheck:
        """Check main API health endpoint"""
        success, latency, data = self._http_get("/api/health")
        if success:
            components = data.get("components", {})
            unhealthy = [k for k, v in components.items() if v != "ok"]
            if unhealthy:
                self._record("api_health", "degraded", f"Components unhealthy: {unhealthy}", latency, data)
            else:
                self._record("api_health", "healthy", "All components operational", latency, data)
        else:
            self._record("api_health", "unhealthy", f"API health check failed: {data.get('error', 'unknown')}", latency, data)
        return self.checks[-1]

    def check_database(self, dsn: str) -> HealthCheck:
        """Check PostgreSQL connectivity"""
        start = time.time()
        try:
            conn = psycopg2.connect(dsn, connect_timeout=self.timeout)
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
            latency = (time.time() - start) * 1000
            conn.close()
            self._record("database", "healthy", "PostgreSQL connection successful", latency)
        except Exception as e:
            latency = (time.time() - start) * 1000
            self._record("database", "unhealthy", f"PostgreSQL connection failed: {e}", latency)
        return self.checks[-1]

    def check_redis(self, url: str) -> HealthCheck:
        """Check Redis connectivity"""
        start = time.time()
        try:
            r = redis.from_url(url, socket_timeout=self.timeout, socket_connect_timeout=self.timeout)
            r.ping()
            latency = (time.time() - start) * 1000
            self._record("redis", "healthy", "Redis connection successful", latency)
        except Exception as e:
            latency = (time.time() - start) * 1000
            self._record("redis", "unhealthy", f"Redis connection failed: {e}", latency)
        return self.checks[-1]

    def check_sandbox(self) -> HealthCheck:
        """Check CAPEv2 sandbox availability"""
        success, latency, data = self._http_get("/api/sandbox/profiles")
        if success:
            profiles = data if isinstance(data, list) else data.get("profiles", [])
            self._record("sandbox", "healthy", f"Sandbox available ({len(profiles)} profiles)", latency, {"profiles": profiles})
        else:
            self._record("sandbox", "degraded", f"Sandbox unavailable: {data.get('error', 'unknown')}", latency, data)
        return self.checks[-1]

    def check_monitoring(self) -> HealthCheck:
        """Check monitoring service"""
        success, latency, data = self._http_get("/api/monitoring/status")
        if success:
            enabled = data.get("enabled", False)
            if enabled:
                self._record("monitoring", "healthy", "Monitoring service operational", latency, data)
            else:
                self._record("monitoring", "degraded", "Monitoring service disabled", latency, data)
        else:
            self._record("monitoring", "unhealthy", f"Monitoring check failed: {data.get('error', 'unknown')}", latency, data)
        return self.checks[-1]

    def check_threat_intel(self) -> HealthCheck:
        """Check threat intelligence providers"""
        success, latency, data = self._http_get("/api/threat-intel/providers")
        if success:
            providers = data if isinstance(data, list) else data.get("providers", [])
            configured = [p for p in providers if p.get("configured")]
            self._record("threat_intel", "healthy" if configured else "degraded",
                        f"Threat intel: {len(configured)}/{len(providers)} providers configured", latency, {"providers": providers})
        else:
            self._record("threat_intel", "unhealthy", f"Threat intel check failed: {data.get('error', 'unknown')}", latency, data)
        return self.checks[-1]

    def check_yara(self) -> HealthCheck:
        """Check YARA ruleset"""
        success, latency, data = self._http_get("/api/yara/stats")
        if success:
            rulesets = data.get("total_rulesets", 0)
            rules = data.get("total_rules", 0)
            self._record("yara", "healthy", f"YARA: {rulesets} rulesets, {rules} rules", latency, data)
        else:
            self._record("yara", "degraded", f"YARA check failed: {data.get('error', 'unknown')}", latency, data)
        return self.checks[-1]

    def check_icap(self) -> HealthCheck:
        """Check ICAP gateway"""
        # ICAP doesn't have HTTP health endpoint, check via API
        success, latency, data = self._http_get("/api/health")
        if success:
            icap_enabled = data.get("icap_enabled", False)
            if icap_enabled:
                self._record("icap", "healthy", "ICAP gateway enabled", latency)
            else:
                self._record("icap", "degraded", "ICAP gateway disabled", latency)
        else:
            self._record("icap", "unhealthy", f"ICAP health check failed: {data.get('error', 'unknown')}", latency, data)
        return self.checks[-1]

    def check_storage(self) -> HealthCheck:
        """Check storage availability via API"""
        success, latency, data = self._http_get("/api/health")
        if success:
            # Storage is implicitly checked if API works
            self._record("storage", "healthy", "Storage accessible via API", latency)
        else:
            self._record("storage", "unhealthy", "Storage check failed (API unreachable)", latency)
        return self.checks[-1]

    def check_cert_expiry(self) -> HealthCheck:
        """Check TLS certificate expiry"""
        import ssl
        import socket
        from datetime import datetime
        
        # Extract host from base_url
        host = self.base_url.replace("https://", "").replace("http://", "").split(":")[0]
        port = 443
        
        start = time.time()
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    latency = (time.time() - start) * 1000
                    
                    if days_left < 0:
                        self._record("tls_cert", "unhealthy", f"Certificate EXPIRED {abs(days_left)} days ago", latency, {"days_left": days_left})
                    elif days_left < 30:
                        self._record("tls_cert", "degraded", f"Certificate expires in {days_left} days", latency, {"days_left": days_left})
                    else:
                        self._record("tls_cert", "healthy", f"Certificate valid for {days_left} days", latency, {"days_left": days_left})
        except Exception as e:
            latency = (time.time() - start) * 1000
            self._record("tls_cert", "unhealthy", f"Certificate check failed: {e}", latency)
        return self.checks[-1]

    def run_all(self, db_dsn: str = None, redis_url: str = None, skip: list[str] = None) -> list[HealthCheck]:
        """Run all health checks"""
        skip = skip or []
        
        # Always run API health first
        if "api" not in skip:
            self.check_api_health()
        
        # Database
        if "database" not in skip and db_dsn:
            self.check_database(db_dsn)
        
        # Redis
        if "redis" not in skip and redis_url:
            self.check_redis(redis_url)
        
        # Other API-dependent checks
        if "sandbox" not in skip:
            self.check_sandbox()
        if "monitoring" not in skip:
            self.check_monitoring()
        if "threat_intel" not in skip:
            self.check_threat_intel()
        if "yara" not in skip:
            self.check_yara()
        if "icap" not in skip:
            self.check_icap()
        if "storage" not in skip:
            self.check_storage()
        if "tls_cert" not in skip:
            self.check_cert_expiry()
        
        return self.checks

    def summary(self) -> dict:
        """Generate summary"""
        total = len(self.checks)
        healthy = sum(1 for c in self.checks if c.status == "healthy")
        degraded = sum(1 for c in self.checks if c.status == "degraded")
        unhealthy = sum(1 for c in self.checks if c.status == "unhealthy")
        
        overall = "healthy"
        if unhealthy > 0:
            overall = "unhealthy"
        elif degraded > 0:
            overall = "degraded"
        
        return {
            "overall": overall,
            "total": total,
            "healthy": healthy,
            "degraded": degraded,
            "unhealthy": unhealthy,
            "checks": [asdict(c) for c in self.checks]
        }


def main():
    parser = argparse.ArgumentParser(description="MALINFO Health Check")
    parser.add_argument("--url", default="https://localhost", help="Base URL for API")
    parser.add_argument("--db-dsn", help="PostgreSQL DSN")
    parser.add_argument("--redis-url", help="Redis URL")
    parser.add_argument("--skip", nargs="+", help="Checks to skip")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--nagios", action="store_true", help="Nagios-compatible output")
    args = parser.parse_args()

    checker = HealthChecker(args.url, args.timeout)
    checker.run_all(args.db_dsn, args.redis_url, args.skip)
    summary = checker.summary()

    if args.json:
        print(json.dumps(summary, indent=2))
    elif args.nagios:
        # Nagios format: OK/WARNING/CRITICAL
        status_map = {"healthy": "OK", "degraded": "WARNING", "unhealthy": "CRITICAL"}
        overall_status = status_map[summary["overall"]]
        print(f"MALINFO {overall_status} - {summary['healthy']} healthy, {summary['degraded']} degraded, {summary['unhealthy']} unhealthy | "
              f"total={summary['total']} healthy={summary['healthy']} degraded={summary['degraded']} unhealthy={summary['unhealthy']}")
        for check in summary["checks"]:
            print(f"  {check['name']}: {status_map[check['status']]} - {check['message']}")
    else:
        # Human readable
        status_icons = {"healthy": "✅", "degraded": "⚠️", "unhealthy": "❌"}
        print(f"\nMALINFO Health Check - Overall: {status_icons[summary['overall']]} {summary['overall'].upper()}")
        print(f"Checks: {summary['total']} total, {summary['healthy']} healthy, {summary['degraded']} degraded, {summary['unhealthy']} unhealthy\n")
        for check in summary["checks"]:
            print(f"  {status_icons[check['status']]} {check['name']}: {check['message']}")
            if check.get("latency_ms"):
                print(f"      Latency: {check['latency_ms']:.1f}ms")
    
    # Exit code for monitoring systems
    exit_codes = {"healthy": 0, "degraded": 1, "unhealthy": 2}
    sys.exit(exit_codes[summary["overall"]])


if __name__ == "__main__":
    main()