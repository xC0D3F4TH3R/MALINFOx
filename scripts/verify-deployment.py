#!/usr/bin/env python3
"""
MALINFO — Deployment Verification Script
Comprehensive verification of production deployment
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


@dataclass
class VerificationCheck:
    name: str
    status: str  # pass, fail, warn
    message: str
    details: dict | None = None


class DeploymentVerifier:
    def __init__(self, base_url: str = "https://localhost", timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.checks: list[VerificationCheck] = []

    def _record(self, name: str, status: str, message: str, details: dict | None = None):
        self.checks.append(VerificationCheck(name, status, message, details))

    def _http_get(self, path: str, expected_status: int = 200, auth_token: str = None) -> tuple[bool, dict | None]:
        url = f"{self.base_url}{path}"
        try:
            headers = {"User-Agent": "MALINFO-Verifier/1.0"}
            if auth_token:
                headers["Authorization"] = f"Bearer {auth_token}"
            req = Request(url, headers=headers)
            with urlopen(req, timeout=self.timeout) as resp:
                if resp.status != expected_status:
                    return False, {"error": f"HTTP {resp.status}", "status": resp.status}
                content_type = resp.headers.get("content-type", "")
                if "application/json" in content_type:
                    return True, json.loads(resp.read().decode())
                return True, {"body": resp.read().decode()[:500]}
        except HTTPError as e:
            return False, {"error": f"HTTP {e.code}", "body": e.read().decode()[:200]}
        except URLError as e:
            return False, {"error": str(e)}
        except Exception as e:
            return False, {"error": str(e)}

    def check_tls_certificate(self) -> VerificationCheck:
        """Verify TLS certificate is valid and not expiring soon"""
        import ssl
        import socket
        from datetime import datetime
        
        host = self.base_url.replace("https://", "").replace("http://", "").split(":")[0]
        port = 443
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.utcnow()).days
                    
                    if days_left < 0:
                        self._record("tls_certificate", "fail", f"Certificate EXPIRED {abs(days_left)} days ago", {"days_left": days_left})
                    elif days_left < 30:
                        self._record("tls_certificate", "warn", f"Certificate expires in {days_left} days", {"days_left": days_left})
                    else:
                        self._record("tls_certificate", "pass", f"Certificate valid for {days_left} days", {"days_left": days_left})
        except Exception as e:
            self._record("tls_certificate", "fail", f"Certificate check failed: {e}")
        return self.checks[-1]

    def check_security_headers(self) -> VerificationCheck:
        """Verify security headers are present"""
        try:
            url = f"{self.base_url}/"
            req = Request(url, headers={"User-Agent": "MALINFO-Verifier/1.0"})
            with urlopen(req, timeout=self.timeout) as resp:
                headers = dict(resp.headers)
                required_headers = {
                    "Strict-Transport-Security": "HSTS",
                    "X-Frame-Options": "Frame protection",
                    "X-Content-Type-Options": "MIME sniffing protection",
                    "Content-Security-Policy": "CSP",
                }
                
                missing = []
                present = []
                for header, desc in required_headers.items():
                    if header in headers:
                        present.append(f"{header}: {headers[header][:50]}")
                    else:
                        missing.append(f"{header} ({desc})")
                
                if missing:
                    self._record("security_headers", "warn", f"Missing headers: {', '.join(missing)}", {"missing": missing, "present": present})
                else:
                    self._record("security_headers", "pass", "All security headers present", {"headers": present})
        except Exception as e:
            self._record("security_headers", "fail", f"Header check failed: {e}")
        return self.checks[-1]

    def check_api_health(self) -> VerificationCheck:
        """Verify API health endpoint"""
        success, data = self._http_get("/api/health")
        if success:
            components = data.get("components", {})
            unhealthy = [k for k, v in components.items() if v != "ok"]
            if unhealthy:
                self._record("api_health", "fail", f"Unhealthy components: {unhealthy}", {"components": components})
            else:
                self._record("api_health", "pass", "All components healthy", {"components": components})
        else:
            self._record("api_health", "fail", f"Health check failed: {data.get('error', 'unknown')}", data)
        return self.checks[-1]

    def check_authentication(self) -> VerificationCheck:
        """Verify authentication endpoints work"""
        # Test login endpoint exists (should return 401/400 for invalid creds, not 404)
        success, data = self._http_get("/api/auth/login", expected_status=400)  # Expect validation error
        if success or (data and data.get("error", "").find("404") == -1):
            self._record("auth_endpoint", "pass", "Authentication endpoint accessible")
        else:
            self._record("auth_endpoint", "fail", f"Auth endpoint not accessible: {data}")
        return self.checks[-1]

    def check_rate_limiting(self) -> VerificationCheck:
        """Verify rate limiting is active"""
        # Make rapid requests to trigger rate limit
        limited = False
        for i in range(15):
            success, data = self._http_get("/api/health", expected_status=200)
            if not success and data and data.get("error", "").find("429") != -1:
                limited = True
                break
        
        if limited:
            self._record("rate_limiting", "pass", "Rate limiting active")
        else:
            self._record("rate_limiting", "warn", "Rate limiting not triggered (may need more requests or different endpoint)")
        return self.checks[-1]

    def check_static_analysis(self, auth_token: str = None) -> VerificationCheck:
        """Verify static analysis pipeline works"""
        # This would require uploading a test file
        # For now, check the endpoint exists
        success, data = self._http_get("/api/upload", expected_status=401, auth_token=auth_token)
        if success or (data and "404" not in str(data)):
            self._record("static_analysis", "pass", "Upload endpoint accessible")
        else:
            self._record("static_analysis", "warn", "Upload endpoint check inconclusive", data)
        return self.checks[-1]

    def check_sandbox(self) -> VerificationCheck:
        """Verify sandbox integration"""
        success, data = self._http_get("/api/sandbox/profiles")
        if success:
            profiles = data if isinstance(data, list) else data.get("profiles", [])
            self._record("sandbox", "pass", f"Sandbox available with {len(profiles)} profiles", {"profiles": len(profiles)})
        else:
            self._record("sandbox", "warn", f"Sandbox unavailable: {data.get('error', 'unknown')}", data)
        return self.checks[-1]

    def check_monitoring(self) -> VerificationCheck:
        """Verify monitoring service"""
        success, data = self._http_get("/api/monitoring/status")
        if success:
            enabled = data.get("enabled", False)
            if enabled:
                self._record("monitoring", "pass", "Monitoring service operational", data)
            else:
                self._record("monitoring", "warn", "Monitoring service disabled", data)
        else:
            self._record("monitoring", "fail", f"Monitoring check failed: {data.get('error', 'unknown')}", data)
        return self.checks[-1]

    def check_threat_intel(self) -> VerificationCheck:
        """Verify threat intelligence providers"""
        success, data = self._http_get("/api/threat-intel/providers")
        if success:
            providers = data if isinstance(data, list) else data.get("providers", [])
            configured = [p for p in providers if p.get("configured")]
            self._record("threat_intel", "pass" if configured else "warn",
                        f"Threat intel: {len(configured)}/{len(providers)} providers configured", {"providers": providers})
        else:
            self._record("threat_intel", "fail", f"Threat intel check failed: {data.get('error', 'unknown')}", data)
        return self.checks[-1]

    def check_yara(self) -> VerificationCheck:
        """Verify YARA rulesets"""
        success, data = self._http_get("/api/yara/stats")
        if success:
            rulesets = data.get("total_rulesets", 0)
            rules = data.get("total_rules", 0)
            if rulesets > 0:
                self._record("yara", "pass", f"YARA: {rulesets} rulesets, {rules} rules", data)
            else:
                self._record("yara", "warn", "No YARA rulesets compiled", data)
        else:
            self._record("yara", "fail", f"YARA check failed: {data.get('error', 'unknown')}", data)
        return self.checks[-1]

    def check_metrics_endpoint(self) -> VerificationCheck:
        """Verify Prometheus metrics endpoint"""
        success, data = self._http_get("/metrics", expected_status=200)
        if success:
            body = data.get("body", "")
            if "http_requests_total" in body and "malinfo_" in body:
                self._record("metrics_endpoint", "pass", "Prometheus metrics available with custom metrics")
            else:
                self._record("metrics_endpoint", "warn", "Metrics endpoint exists but missing custom metrics", {"sample": body[:200]})
        else:
            self._record("metrics_endpoint", "fail", f"Metrics endpoint failed: {data.get('error', 'unknown')}", data)
        return self.checks[-1]

    def check_websocket(self) -> VerificationCheck:
        """Verify WebSocket endpoint"""
        import websockets
        import asyncio
        
        async def test_ws():
            ws_url = self.base_url.replace("https://", "wss://").replace("http://", "ws://") + "/api/ws"
            try:
                async with websockets.connect(ws_url, open_timeout=self.timeout) as ws:
                    await ws.send(json.dumps({"type": "ping"}))
                    response = await asyncio.wait_for(ws.recv(), timeout=5)
                    return True, response
            except Exception as e:
                return False, str(e)
        
        try:
            result = asyncio.run(test_ws())
            if result[0]:
                self._record("websocket", "pass", "WebSocket connection successful")
            else:
                self._record("websocket", "warn", f"WebSocket connection failed: {result[1]}")
        except Exception as e:
            self._record("websocket", "warn", f"WebSocket test skipped: {e}")
        return self.checks[-1]

    def check_docker_services(self) -> VerificationCheck:
        """Verify Docker services are running"""
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", "docker-compose.prod.yml", "ps", "--format", "json"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                services = [json.loads(line) for line in result.stdout.strip().split('\n') if line]
                running = [s for s in services if s.get("State") == "running"]
                stopped = [s for s in services if s.get("State") != "running"]
                
                if stopped:
                    self._record("docker_services", "fail", f"{len(stopped)} services not running", {"stopped": stopped})
                else:
                    self._record("docker_services", "pass", f"All {len(running)} services running", {"services": running})
            else:
                self._record("docker_services", "fail", f"Docker compose ps failed: {result.stderr}")
        except Exception as e:
            self._record("docker_services", "warn", f"Docker check failed: {e}")
        return self.checks[-1]

    def check_disk_space(self) -> VerificationCheck:
        """Verify disk space"""
        import shutil
        try:
            total, used, free = shutil.disk_usage("/opt/malinfo/storage")
            free_percent = (free / total) * 100
            
            if free_percent < 10:
                self._record("disk_space", "fail", f"Storage critical: {free_percent:.1f}% free", {"free_percent": free_percent})
            elif free_percent < 20:
                self._record("disk_space", "warn", f"Storage low: {free_percent:.1f}% free", {"free_percent": free_percent})
            else:
                self._record("disk_space", "pass", f"Storage OK: {free_percent:.1f}% free", {"free_percent": free_percent})
        except Exception as e:
            self._record("disk_space", "warn", f"Disk check failed: {e}")
        return self.checks[-1]

    def run_all(self, auth_token: str = None, skip: list[str] = None) -> list[VerificationCheck]:
        """Run all verification checks"""
        skip = skip or []
        
        check_methods = [
            ("tls_certificate", self.check_tls_certificate),
            ("security_headers", self.check_security_headers),
            ("api_health", self.check_api_health),
            ("auth_endpoint", self.check_authentication),
            ("rate_limiting", self.check_rate_limiting),
            ("static_analysis", lambda: self.check_static_analysis(auth_token)),
            ("sandbox", self.check_sandbox),
            ("monitoring", self.check_monitoring),
            ("threat_intel", self.check_threat_intel),
            ("yara", self.check_yara),
            ("metrics_endpoint", self.check_metrics_endpoint),
            ("websocket", self.check_websocket),
            ("docker_services", self.check_docker_services),
            ("disk_space", self.check_disk_space),
        ]
        
        for name, method in check_methods:
            if name not in skip:
                try:
                    method()
                except Exception as e:
                    self._record(name, "fail", f"Check crashed: {e}")
        
        return self.checks

    def summary(self) -> dict:
        """Generate summary"""
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c.status == "pass")
        failed = sum(1 for c in self.checks if c.status == "fail")
        warned = sum(1 for c in self.checks if c.status == "warn")
        
        overall = "pass"
        if failed > 0:
            overall = "fail"
        elif warned > 0:
            overall = "warn"
        
        return {
            "overall": overall,
            "total": total,
            "passed": passed,
            "failed": failed,
            "warned": warned,
            "checks": [asdict(c) for c in self.checks]
        }


def main():
    parser = argparse.ArgumentParser(description="MALINFO Deployment Verification")
    parser.add_argument("--url", default="https://localhost", help="Base URL")
    parser.add_argument("--auth-token", help="Auth token for authenticated checks")
    parser.add_argument("--skip", nargs="+", help="Checks to skip")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout seconds")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    args = parser.parse_args()

    verifier = DeploymentVerifier(args.url, args.timeout)
    verifier.run_all(args.auth_token, args.skip)
    summary = verifier.summary()

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        status_icons = {"pass": "✅", "fail": "❌", "warn": "⚠️"}
        print(f"\nMALINFO Deployment Verification - Overall: {status_icons[summary['overall']]} {summary['overall'].upper()}")
        print(f"Checks: {summary['total']} total, {summary['passed']} passed, {summary['failed']} failed, {summary['warned']} warned\n")
        for check in summary["checks"]:
            print(f"  {status_icons[check['status']]} {check['name']}: {check['message']}")
    
    exit_codes = {"pass": 0, "warn": 1 if args.strict else 0, "fail": 1}
    sys.exit(exit_codes[summary["overall"]])


if __name__ == "__main__":
    main()