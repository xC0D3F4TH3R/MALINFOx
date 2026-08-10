"""
ICAP (Internet Content Adaptation Protocol) server for MALINFO.
Allows authorized network gateways (Squid, CERT secure web gateway, email gateway)
to stream files to MALINFO for pre-delivery analysis.

This runs on infrastructure the deploying authority LEGALLY CONTROLS — never
as a general capability to intercept arbitrary citizens' traffic.

RFC 3507 ICAP implementation with REQMOD (request modification) and RESPMOD
(response modification) support for file inspection before delivery.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from app.analysis.pipeline import run_static_analysis
from app.config import settings
from app.network_forensics.pcap_analyzer import analyze_pcap
from app.sandbox.orchestrator import detonate_sample

logger = logging.getLogger("malinfo.icap")

# ICAP protocol constants
ICAP_VERSION = "ICAP/1.0"
ICAP_CRLF = b"\r\n"
ICAP_METHODS = {"REQMOD", "RESPMOD", "OPTIONS"}


@dataclass
class ICAPRequest:
    method: str
    uri: str
    version: str
    headers: dict
    body: bytes
    preview: bytes = b""
    has_body: bool = False


@dataclass
class ICAPResponse:
    version: str = ICAP_VERSION
    status_code: int = 200
    reason_phrase: str = "OK"
    headers: dict = None
    body: bytes = b""
    encapsulated: list = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.encapsulated is None:
            self.encapsulated = []


class ICAPProtocolError(Exception):
    """Raised when ICAP protocol violations are detected."""


class ICAPServer:
    """
    Async ICAP server for malware inspection integration with network gateways.

    Typical deployment:
    - Squid proxy: icap_service service_req reqmod_precache bypass=off icap://malinfo:1344/reqmod
    - Squid proxy: icap_service service_resp respmod_precache bypass=off icap://malinfo:1344/respmod
    - Email gateway: Configure ICAP client to forward attachments

    The gateway MUST be on infrastructure the deploying authority controls.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 1344):
        self.host = host
        self.port = port
        self.server: asyncio.Server | None = None
        self._running = False
        self.max_body_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    async def start(self):
        """Start the ICAP server."""
        self.server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        self._running = True
        logger.info(f"ICAP server started on {self.host}:{self.port}")

        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        """Stop the ICAP server."""
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        logger.info("ICAP server stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming ICAP client connection."""
        peer = writer.get_extra_info("peername")
        logger.debug(f"ICAP connection from {peer}")

        try:
            while self._running:
                request = await self._read_request(reader)
                if request is None:
                    break

                response = await self._process_request(request, peer)
                await self._write_response(writer, response)

                # Check if connection should be kept alive
                if request.headers.get("Connection", "").lower() == "close":
                    break

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.exception(f"ICAP client error from {peer}: {exc}")
        finally:
            writer.close()
            await writer.wait_closed()
            logger.debug(f"ICAP connection closed from {peer}")

    async def _read_request(self, reader: asyncio.StreamReader) -> ICAPRequest | None:
        """Read and parse an ICAP request."""
        # Read request line
        line = await reader.readline()
        if not line:
            return None

        try:
            method, uri, version = line.decode().strip().split(" ", 2)
        except ValueError as e:
            raise ICAPProtocolError("Invalid request line") from e

        if method not in ICAP_METHODS:
            raise ICAPProtocolError(f"Unsupported method: {method}")

        # Read headers
        headers = {}
        while True:
            line = await reader.readline()
            if not line or line == ICAP_CRLF:
                break
            header_line = line.decode().rstrip("\r\n")
            if ":" in header_line:
                key, value = header_line.split(":", 1)
                headers[key.strip()] = value.strip()

        # Parse encapsulated sections
        self._parse_encapsulated(headers.get("Encapsulated", ""))

        # Read body if present
        body = b""
        preview = b""
        has_body = False

        content_length = int(headers.get("Content-Length", "0"))
        preview_length = int(headers.get("Preview", "0"))

        if content_length > 0:
            has_body = True
            # Read preview first
            if preview_length > 0:
                preview = await reader.readexactly(min(preview_length, content_length))
                body = preview
                remaining = content_length - len(preview)
                if remaining > 0:
                    body += await reader.readexactly(remaining)
            else:
                body = await reader.readexactly(content_length)

        # Read IEOF (end of message)
        await reader.readline()  # consume final CRLF

        return ICAPRequest(
            method=method,
            uri=uri,
            version=version,
            headers=headers,
            body=body,
            preview=preview,
            has_body=has_body,
        )

    def _parse_encapsulated(self, encapsulated_header: str) -> list:
        """Parse the Encapsulated header into ordered sections."""
        if not encapsulated_header:
            return []
        sections = []
        for part in encapsulated_header.split(","):
            part = part.strip()
            if "=" in part:
                name, pos = part.split("=", 1)
                sections.append((name.strip(), int(pos)))
        sections.sort(key=lambda x: x[1])
        return [name for name, _ in sections]

    async def _process_request(self, request: ICAPRequest, peer) -> ICAPResponse:
        """Process an ICAP request and return response."""
        logger.info(f"ICAP {request.method} from {peer} for {request.uri}")

        if request.method == "OPTIONS":
            return self._handle_options(request)
        elif request.method == "REQMOD":
            return await self._handle_reqmod(request, peer)
        elif request.method == "RESPMOD":
            return await self._handle_respmod(request, peer)
        else:
            return ICAPResponse(status_code=501, reason_phrase="Not Implemented")

    def _handle_options(self, request: ICAPRequest) -> ICAPResponse:
        """Handle OPTIONS request - advertise capabilities."""
        return ICAPResponse(
            status_code=200,
            reason_phrase="OK",
            headers={
                "Methods": "REQMOD, RESPMOD",
                "Service": "MALINFO Malware Analysis Platform",
                "ISTag": "MALINFO-1.0",
                "Preview": str(settings.MAX_UPLOAD_SIZE_MB * 1024),  # Preview size in bytes
                "Transfer-Preview": "*",
                "Options-TTL": "3600",
                "Max-Connections": "100",
            },
        )

    async def _handle_reqmod(self, request: ICAPRequest, peer) -> ICAPResponse:
        """
        Handle REQMOD (request modification) - inspect file being uploaded/transferred.
        The gateway sends the HTTP request with file content; we analyze and either
        allow (204) or block (403 with modified response).
        """
        if not request.has_body or not request.body:
            return ICAPResponse(status_code=204, reason_phrase="No Content")

        # Extract file from multipart/form-data or raw body
        file_content, filename = self._extract_file_from_body(request.body, request.headers)
        if not file_content:
            return ICAPResponse(status_code=204, reason_phrase="No file to analyze")

        # Analyze the file
        analysis_result = await self._analyze_streaming_file(file_content, filename, peer)

        if analysis_result["verdict"] == "malicious":
            # Block the transfer - return modified response
            return ICAPResponse(
                status_code=403,
                reason_phrase="Forbidden - Malicious Content Detected",
                headers={
                    "Encapsulated": "res-hdr=0, res-body=100",
                    "Content-Type": "application/json",
                },
                body=self._build_block_response(analysis_result).encode(),
            )

        # Allow transfer - return 204 (no modification needed)
        return ICAPResponse(status_code=204, reason_phrase="No Content")

    async def _handle_respmod(self, request: ICAPRequest, peer) -> ICAPResponse:
        """
        Handle RESPMOD (response modification) - inspect file being downloaded.
        The gateway sends the HTTP response with file content; we analyze and either
        allow or block the download.
        """
        if not request.has_body or not request.body:
            return ICAPResponse(status_code=204, reason_phrase="No Content")

        # Extract file from response body
        content_type = request.headers.get("Content-Type", "")
        file_content = request.body
        filename = f"download_{uuid.uuid4().hex[:8]}"

        # If it's a multipart response, extract the file part
        if "multipart" in content_type:
            file_content, filename = self._extract_file_from_body(file_content, request.headers)

        if not file_content:
            return ICAPResponse(status_code=204, reason_phrase="No file to analyze")

        # Analyze the file
        analysis_result = await self._analyze_streaming_file(file_content, filename, peer)

        if analysis_result["verdict"] == "malicious":
            return ICAPResponse(
                status_code=403,
                reason_phrase="Forbidden - Malicious Content Detected",
                headers={
                    "Encapsulated": "res-hdr=0, res-body=100",
                    "Content-Type": "application/json",
                },
                body=self._build_block_response(analysis_result).encode(),
            )

        return ICAPResponse(status_code=204, reason_phrase="No Content")

    def _extract_file_from_body(self, body: bytes, headers: dict) -> tuple[bytes, str]:
        """Extract file content from multipart/form-data or raw body."""
        content_type = headers.get("Content-Type", "")

        if "multipart/form-data" in content_type:
            boundary = self._get_boundary(content_type)
            if boundary:
                return self._parse_multipart(body, boundary)
        elif "application/octet-stream" in content_type or not content_type:
            # Raw binary content
            content_disposition = headers.get("Content-Disposition", "")
            filename = self._extract_filename(content_disposition) or "unknown.bin"
            return body, filename

        return body, "unknown.bin"

    def _get_boundary(self, content_type: str) -> bytes | None:
        """Extract boundary from multipart Content-Type."""
        import re
        match = re.search(r'boundary=([^;]+)', content_type)
        if match:
            boundary = match.group(1).strip('"')
            return f"--{boundary}".encode()
        return None

    def _parse_multipart(self, body: bytes, boundary: bytes) -> tuple[bytes, str]:
        """Parse multipart/form-data and return first file part."""
        parts = body.split(boundary)
        for part in parts:
            if b"Content-Disposition:" in part and b"filename=" in part:
                # Find the blank line separating headers from body
                header_end = part.find(b"\r\n\r\n")
                if header_end != -1:
                    headers_section = part[:header_end].decode(errors="ignore")
                    file_content = part[header_end + 4:].rstrip(b"\r\n--")
                    filename = self._extract_filename(headers_section) or "upload.bin"
                    return file_content, filename
        return b"", "unknown.bin"

    def _extract_filename(self, content_disposition: str) -> str | None:
        """Extract filename from Content-Disposition header."""
        import re
        match = re.search(r'filename\*?=([^;]+)', content_disposition, re.IGNORECASE)
        if match:
            filename = match.group(1).strip().strip('"')
            # Handle RFC 5987 encoding (filename*=UTF-8''encoded)
            if filename.lower().startswith("utf-8''"):
                import urllib.parse
                filename = urllib.parse.unquote(filename[7:])
            return filename
        return None

    async def _analyze_streaming_file(self, file_content: bytes, filename: str, peer) -> dict:
        """Analyze a file received via ICAP - streaming analysis without full download."""
        import tempfile

        # Write to temporary file for analysis
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"__{filename}") as tmp:
            tmp.write(file_content)
            tmp_path = Path(tmp.name)

        try:
            # Run static analysis
            static_report = run_static_analysis(tmp_path)

            # Quick verdict based on static analysis
            verdict = static_report.get("verdict", "unknown")
            risk_score = static_report.get("risk_score", 0)

            # If highly suspicious, trigger sandbox analysis asynchronously
            if verdict in ("suspicious", "malicious") and settings.SANDBOX_ENABLED:
                # Fire and forget - sandbox runs async
                asyncio.create_task(self._run_async_sandbox(tmp_path, static_report["target_os"]))

            return {
                "verdict": verdict,
                "risk_score": risk_score,
                "static_report": static_report,
                "filename": filename,
                "source_ip": peer[0] if peer else "unknown",
            }

        finally:
            # Clean up temp file
            try:
                tmp_path.unlink()
            except Exception:
                pass

    async def _run_async_sandbox(self, file_path: Path, target_os: str):
        """Run sandbox analysis asynchronously."""
        try:
            sandbox_report = await detonate_sample(file_path, target_os)
            if sandbox_report.get("available") and sandbox_report.get("pcap_path"):
                analyze_pcap(Path(sandbox_report["pcap_path"]))
                logger.info(f"Async sandbox completed for {file_path.name}: {sandbox_report.get('malscore', 0)}")
        except Exception as exc:
            logger.exception(f"Async sandbox failed: {exc}")

    def _build_block_response(self, analysis_result: dict) -> str:
        """Build JSON response for blocked content."""
        import json
        return json.dumps({
            "blocked": True,
            "reason": "Malicious content detected by MALINFO",
            "verdict": analysis_result["verdict"],
            "risk_score": analysis_result["risk_score"],
            "filename": analysis_result["filename"],
            "threat_details": {
                "iocs": analysis_result["static_report"].get("iocs", [])[:10],
                "yara_matches": [m["rule"] for m in analysis_result["static_report"].get("yara", {}).get("matches", [])],
                "suspicious_imports": analysis_result["static_report"].get("format_specific", {}).get("pe", {}).get("suspicious_api_calls", []),
            },
            "reference_id": f"MALINFO-{uuid.uuid4().hex[:12].upper()}",
        }, indent=2)

    async def _write_response(self, writer: asyncio.StreamWriter, response: ICAPResponse):
        """Write ICAP response to client."""
        # Build status line
        status_line = f"{response.version} {response.status_code} {response.reason_phrase}{ICAP_CRLF.decode()}"
        writer.write(status_line.encode())

        # Write headers
        for key, value in response.headers.items():
            writer.write(f"{key}: {value}{ICAP_CRLF.decode()}".encode())

        # Write encapsulated header if needed
        if response.encapsulated:
            encapsulated_str = ", ".join(f"{name}={pos}" for name, pos in enumerate(response.encapsulated))
            writer.write(f"Encapsulated: {encapsulated_str}{ICAP_CRLF.decode()}".encode())

        writer.write(ICAP_CRLF)

        # Write body
        if response.body:
            writer.write(response.body)
            writer.write(ICAP_CRLF)

        await writer.drain()


# Global server instance for lifecycle management
_icap_server: ICAPServer | None = None


async def start_icap_server():
    """Start the ICAP server if enabled in config."""
    global _icap_server
    if settings.ICAP_ENABLED:
        _icap_server = ICAPServer(port=settings.ICAP_LISTEN_PORT)
        asyncio.create_task(_icap_server.start())
        logger.info("ICAP gateway integration enabled")
    else:
        logger.info("ICAP gateway integration disabled (set ICAP_ENABLED=true to enable)")


async def stop_icap_server():
    """Stop the ICAP server."""
    global _icap_server
    if _icap_server:
        await _icap_server.stop()
        _icap_server = None