"""
Threat Intelligence Integration for MALINFO.
Integrates with VirusTotal, OTX (AlienVault), AbuseIPDB, MISP, and custom feeds
for IOC enrichment, reputation scoring, and threat attribution.
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import aiohttp

from app.config import settings

logger = logging.getLogger("malinfo.threat_intel")


class ThreatLevel(Enum):
    """Threat severity levels."""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence lookup."""
    source: str
    indicator: str
    indicator_type: str  # ip, domain, url, hash
    malicious: bool = False
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: float = 0.0
    tags: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)
    queried_at: datetime = field(default_factory=datetime.utcnow)
    error: str | None = None


@dataclass
class EnrichedIOC:
    """IOC enriched with threat intelligence."""
    ioc_type: str
    value: str
    original_confidence: float
    intel_results: list[ThreatIntelResult] = field(default_factory=list)
    aggregated_threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    aggregated_confidence: float = 0.0
    consensus_malicious: bool = False


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    def __init__(self, name: str, api_key: str | None = None, rate_limit: float = 1.0):
        self.name = name
        self.api_key = api_key
        self.rate_limit = rate_limit  # requests per second
        self._last_request = 0.0
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                headers={"User-Agent": "MALINFO/1.0 ThreatIntel"},
            )
        return self._session

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _rate_limit(self):
        """Enforce rate limiting."""
        now = time.time()
        elapsed = now - self._last_request
        min_interval = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_request = time.time()

    @abstractmethod
    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        """Look up a file hash."""

    @abstractmethod
    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        """Look up an IP address."""

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        """Look up a domain."""

    @abstractmethod
    async def lookup_url(self, url: str) -> ThreatIntelResult:
        """Look up a URL."""

    def _create_result(
        self,
        indicator: str,
        indicator_type: str,
        malicious: bool = False,
        threat_level: ThreatLevel = ThreatLevel.UNKNOWN,
        confidence: float = 0.0,
        tags: list[str] | None = None,
        families: list[str] | None = None,
        references: list[str] | None = None,
        raw_data: dict | None = None,
        error: str | None = None,
    ) -> ThreatIntelResult:
        """Create a standardized threat intel result."""
        return ThreatIntelResult(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            malicious=malicious,
            threat_level=threat_level,
            confidence=confidence,
            tags=tags or [],
            families=families or [],
            references=references or [],
            raw_data=raw_data or {},
            error=error,
        )


class VirusTotalProvider(ThreatIntelProvider):
    """VirusTotal API v3 integration."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        super().__init__("VirusTotal", api_key, rate_limit=4.0)  # 4 req/s for standard API

    def _headers(self) -> dict:
        return {"x-apikey": self.api_key}

    async def _request(self, endpoint: str) -> dict:
        """Make authenticated request to VirusTotal."""
        await self._rate_limit()
        session = await self._get_session()
        url = f"{self.BASE_URL}{endpoint}"
        async with session.get(url, headers=self._headers()) as resp:
            if resp.status == 404:
                return {"not_found": True}
            if resp.status == 429:
                raise Exception("Rate limited")
            resp.raise_for_status()
            return await resp.json()

    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/files/{hash_value}")
            if data.get("not_found"):
                return self._create_result(hash_value, "hash", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.8)

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total = sum(stats.values())

            is_malicious = malicious_count > 0
            threat_level = ThreatLevel.HIGH if malicious_count > 5 else ThreatLevel.MEDIUM if malicious_count > 0 else ThreatLevel.LOW
            confidence = min(0.95, (malicious_count + suspicious_count * 0.5) / max(total, 1))

            return self._create_result(
                indicator=hash_value,
                indicator_type="hash",
                malicious=is_malicious,
                threat_level=threat_level,
                confidence=confidence,
                tags=attrs.get("tags", []),
                families=[attrs.get("meaningful_name", "")] if attrs.get("meaningful_name") else [],
                references=[f"https://www.virustotal.com/gui/file/{hash_value}"],
                raw_data=attrs,
            )
        except Exception as exc:
            return self._create_result(hash_value, "hash", error=str(exc))

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/ip_addresses/{ip}")
            if data.get("not_found"):
                return self._create_result(ip, "ip", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            return self._create_result(
                indicator=ip,
                indicator_type="ip",
                malicious=malicious_count > 0,
                threat_level=ThreatLevel.HIGH if malicious_count > 3 else ThreatLevel.MEDIUM if malicious_count > 0 else ThreatLevel.LOW,
                confidence=min(0.9, malicious_count / 10),
                tags=attrs.get("tags", []),
                references=[f"https://www.virustotal.com/gui/ip-address/{ip}"],
                raw_data=attrs,
            )
        except Exception as exc:
            return self._create_result(ip, "ip", error=str(exc))

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/domains/{domain}")
            if data.get("not_found"):
                return self._create_result(domain, "domain", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            return self._create_result(
                indicator=domain,
                indicator_type="domain",
                malicious=malicious_count > 0,
                threat_level=ThreatLevel.HIGH if malicious_count > 3 else ThreatLevel.MEDIUM if malicious_count > 0 else ThreatLevel.LOW,
                confidence=min(0.9, malicious_count / 10),
                tags=attrs.get("tags", []),
                references=[f"https://www.virustotal.com/gui/domain/{domain}"],
                raw_data=attrs,
            )
        except Exception as exc:
            return self._create_result(domain, "domain", error=str(exc))

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        # VT requires URL ID (base64 encoded URL without padding)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            data = await self._request(f"/urls/{url_id}")
            if data.get("not_found"):
                # Submit for analysis
                await self._rate_limit()
                session = await self._get_session()
                async with session.post(
                    f"{self.BASE_URL}/urls",
                    headers=self._headers(),
                    data={"url": url},
                ) as resp:
                    if resp.status == 200:
                        submit_data = await resp.json()
                        analysis_id = submit_data.get("data", {}).get("id")
                        if analysis_id:
                            # Wait for analysis
                            await asyncio.sleep(5)
                            return await self.lookup_url(url)
                return self._create_result(url, "url", malicious=False, threat_level=ThreatLevel.UNKNOWN, confidence=0.3)

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)

            return self._create_result(
                indicator=url,
                indicator_type="url",
                malicious=malicious_count > 0,
                threat_level=ThreatLevel.HIGH if malicious_count > 3 else ThreatLevel.MEDIUM if malicious_count > 0 else ThreatLevel.LOW,
                confidence=min(0.9, malicious_count / 10),
                tags=attrs.get("tags", []),
                references=[f"https://www.virustotal.com/gui/url/{url_id}"],
                raw_data=attrs,
            )
        except Exception as exc:
            return self._create_result(url, "url", error=str(exc))


class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX (Open Threat Exchange) integration."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        super().__init__("OTX", api_key, rate_limit=2.0)

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key}

    async def _request(self, endpoint: str) -> dict:
        await self._rate_limit()
        session = await self._get_session()
        url = f"{self.BASE_URL}{endpoint}"
        async with session.get(url, headers=self._headers()) as resp:
            if resp.status == 404:
                return {"not_found": True}
            resp.raise_for_status()
            return await resp.json()

    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/indicators/file/{hash_value}/general")
            if data.get("not_found") or not data.get("pulse_info", {}).get("pulses"):
                return self._create_result(hash_value, "hash", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            pulses = data["pulse_info"]["pulses"]
            tags = set()
            families = set()
            references = []
            for pulse in pulses[:10]:  # Limit to 10 pulses
                tags.update(pulse.get("tags", []))
                families.update(pulse.get("malware_families", []))
                references.append(pulse.get("id", ""))

            return self._create_result(
                indicator=hash_value,
                indicator_type="hash",
                malicious=len(pulses) > 0,
                threat_level=ThreatLevel.HIGH if len(pulses) > 5 else ThreatLevel.MEDIUM if len(pulses) > 0 else ThreatLevel.LOW,
                confidence=min(0.9, len(pulses) / 10),
                tags=list(tags),
                families=list(families),
                references=references,
                raw_data=data,
            )
        except Exception as exc:
            return self._create_result(hash_value, "hash", error=str(exc))

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/indicators/IPv4/{ip}/general")
            pulses = data.get("pulse_info", {}).get("pulses", [])
            if not pulses:
                return self._create_result(ip, "ip", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            references = []
            for pulse in pulses[:10]:
                tags.update(pulse.get("tags", []))
                references.append(pulse.get("id", ""))

            return self._create_result(
                indicator=ip,
                indicator_type="ip",
                malicious=len(pulses) > 0,
                threat_level=ThreatLevel.HIGH if len(pulses) > 5 else ThreatLevel.MEDIUM if len(pulses) > 0 else ThreatLevel.LOW,
                confidence=min(0.9, len(pulses) / 10),
                tags=list(tags),
                references=references,
                raw_data=data,
            )
        except Exception as exc:
            return self._create_result(ip, "ip", error=str(exc))

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/indicators/domain/{domain}/general")
            pulses = data.get("pulse_info", {}).get("pulses", [])
            if not pulses:
                return self._create_result(domain, "domain", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            references = []
            for pulse in pulses[:10]:
                tags.update(pulse.get("tags", []))
                references.append(pulse.get("id", ""))

            return self._create_result(
                indicator=domain,
                indicator_type="domain",
                malicious=len(pulses) > 0,
                threat_level=ThreatLevel.HIGH if len(pulses) > 5 else ThreatLevel.MEDIUM if len(pulses) > 0 else ThreatLevel.LOW,
                confidence=min(0.9, len(pulses) / 10),
                tags=list(tags),
                references=references,
                raw_data=data,
            )
        except Exception as exc:
            return self._create_result(domain, "domain", error=str(exc))

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        try:
            data = await self._request(f"/indicators/url/{url}/general")
            pulses = data.get("pulse_info", {}).get("pulses", [])
            if not pulses:
                return self._create_result(url, "url", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            references = []
            for pulse in pulses[:10]:
                tags.update(pulse.get("tags", []))
                references.append(pulse.get("id", ""))

            return self._create_result(
                indicator=url,
                indicator_type="url",
                malicious=len(pulses) > 0,
                threat_level=ThreatLevel.HIGH if len(pulses) > 5 else ThreatLevel.MEDIUM if len(pulses) > 0 else ThreatLevel.LOW,
                confidence=min(0.9, len(pulses) / 10),
                tags=list(tags),
                references=references,
                raw_data=data,
            )
        except Exception as exc:
            return self._create_result(url, "url", error=str(exc))


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB integration for IP reputation."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        super().__init__("AbuseIPDB", api_key, rate_limit=1.0)  # Conservative rate limit

    def _headers(self) -> dict:
        return {"Key": self.api_key, "Accept": "application/json"}

    async def _request(self, endpoint: str, params: dict | None = None) -> dict:
        await self._rate_limit()
        session = await self._get_session()
        url = f"{self.BASE_URL}{endpoint}"
        async with session.get(url, headers=self._headers(), params=params) as resp:
            if resp.status == 429:
                raise Exception("Rate limited")
            resp.raise_for_status()
            return await resp.json()

    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        return self._create_result(hash_value, "hash", error="AbuseIPDB does not support hash lookups")

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        try:
            data = await self._request("/check", {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True})
            ip_data = data.get("data", {})
            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            ip_data.get("totalReports", 0)

            is_malicious = abuse_score > 50
            threat_level = ThreatLevel.CRITICAL if abuse_score > 90 else ThreatLevel.HIGH if abuse_score > 50 else ThreatLevel.MEDIUM if abuse_score > 25 else ThreatLevel.LOW

            return self._create_result(
                indicator=ip,
                indicator_type="ip",
                malicious=is_malicious,
                threat_level=threat_level,
                confidence=min(0.95, abuse_score / 100),
                tags=ip_data.get("tags", []),
                references=[f"https://www.abuseipdb.com/check/{ip}"],
                raw_data=ip_data,
            )
        except Exception as exc:
            return self._create_result(ip, "ip", error=str(exc))

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        return self._create_result(domain, "domain", error="AbuseIPDB does not support domain lookups directly")

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        return self._create_result(url, "url", error="AbuseIPDB does not support URL lookups directly")


class MISPProvider(ThreatIntelProvider):
    """MISP (Malware Information Sharing Platform) integration."""

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        super().__init__("MISP", api_key, rate_limit=5.0)
        self.misp_url = url.rstrip("/")
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict:
        return {"Authorization": self.api_key, "Accept": "application/json", "Content-Type": "application/json"}

    async def _search(self, endpoint: str, value: str) -> dict:
        await self._rate_limit()
        session = await self._get_session()
        url = f"{self.misp_url}{endpoint}"
        payload = {"value": value, "type": "attribute", "includeContext": True}
        async with session.post(url, headers=self._headers(), json=payload, ssl=self.verify_ssl) as resp:
            if resp.status == 404:
                return {"not_found": True}
            resp.raise_for_status()
            return await resp.json()

    async def lookup_hash(self, hash_value: str) -> ThreatIntelResult:
        try:
            data = await self._search("/attributes/restSearch", hash_value)
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                return self._create_result(hash_value, "hash", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            for attr in attrs:
                tags.update(tag.get("name", "") for tag in attr.get("Tag", []))

            return self._create_result(
                indicator=hash_value,
                indicator_type="hash",
                malicious=True,
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                tags=list(tags),
                references=[f"{self.misp_url}/events/view/{attr.get('event_id')}" for attr in attrs[:5]],
                raw_data={"attributes": attrs},
            )
        except Exception as exc:
            return self._create_result(hash_value, "hash", error=str(exc))

    async def lookup_ip(self, ip: str) -> ThreatIntelResult:
        try:
            data = await self._search("/attributes/restSearch", ip)
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                return self._create_result(ip, "ip", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            for attr in attrs:
                tags.update(tag.get("name", "") for tag in attr.get("Tag", []))

            return self._create_result(
                indicator=ip,
                indicator_type="ip",
                malicious=True,
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                tags=list(tags),
                references=[f"{self.misp_url}/events/view/{attr.get('event_id')}" for attr in attrs[:5]],
                raw_data={"attributes": attrs},
            )
        except Exception as exc:
            return self._create_result(ip, "ip", error=str(exc))

    async def lookup_domain(self, domain: str) -> ThreatIntelResult:
        try:
            data = await self._search("/attributes/restSearch", domain)
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                return self._create_result(domain, "domain", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            for attr in attrs:
                tags.update(tag.get("name", "") for tag in attr.get("Tag", []))

            return self._create_result(
                indicator=domain,
                indicator_type="domain",
                malicious=True,
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                tags=list(tags),
                references=[f"{self.misp_url}/events/view/{attr.get('event_id')}" for attr in attrs[:5]],
                raw_data={"attributes": attrs},
            )
        except Exception as exc:
            return self._create_result(domain, "domain", error=str(exc))

    async def lookup_url(self, url: str) -> ThreatIntelResult:
        try:
            data = await self._search("/attributes/restSearch", url)
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                return self._create_result(url, "url", malicious=False, threat_level=ThreatLevel.LOW, confidence=0.7)

            tags = set()
            for attr in attrs:
                tags.update(tag.get("name", "") for tag in attr.get("Tag", []))

            return self._create_result(
                indicator=url,
                indicator_type="url",
                malicious=True,
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                tags=list(tags),
                references=[f"{self.misp_url}/events/view/{attr.get('event_id')}" for attr in attrs[:5]],
                raw_data={"attributes": attrs},
            )
        except Exception as exc:
            return self._create_result(url, "url", error=str(exc))


class ThreatIntelAggregator:
    """
    Aggregates threat intelligence from multiple providers.
    Provides consensus scoring and unified enrichment.
    """

    def __init__(self):
        self.providers: list[ThreatIntelProvider] = []
        self._init_providers()

    def _init_providers(self):
        """Initialize enabled providers from config."""
        if settings.VIRUSTOTAL_API_KEY:
            self.providers.append(VirusTotalProvider(settings.VIRUSTOTAL_API_KEY))
            logger.info("VirusTotal provider enabled")

        if settings.OTX_API_KEY:
            self.providers.append(OTXProvider(settings.OTX_API_KEY))
            logger.info("OTX provider enabled")

        if settings.ABUSEIPDB_API_KEY:
            self.providers.append(AbuseIPDBProvider(settings.ABUSEIPDB_API_KEY))
            logger.info("AbuseIPDB provider enabled")

        if settings.MISP_URL and settings.MISP_API_KEY:
            self.providers.append(MISPProvider(settings.MISP_URL, settings.MISP_API_KEY, settings.MISP_VERIFY_SSL))
            logger.info("MISP provider enabled")

        if not self.providers:
            logger.warning("No threat intelligence providers configured")

    async def enrich_ioc(self, ioc_type: str, value: str, original_confidence: float = 0.5) -> EnrichedIOC:
        """Enrich a single IOC with all available providers."""
        results = []

        # Run lookups in parallel
        tasks = []
        for provider in self.providers:
            if ioc_type == "hash" or ioc_type in ("md5", "sha1", "sha256", "ssdeep"):
                tasks.append(provider.lookup_hash(value))
            elif ioc_type == "ip":
                tasks.append(provider.lookup_ip(value))
            elif ioc_type == "domain":
                tasks.append(provider.lookup_domain(value))
            elif ioc_type == "url":
                tasks.append(provider.lookup_url(value))

        provider_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in provider_results:
            if isinstance(result, ThreatIntelResult):
                results.append(result)
            elif isinstance(result, Exception):
                logger.error(f"Threat intel provider error: {result}")

        # Aggregate results
        enriched = EnrichedIOC(
            ioc_type=ioc_type,
            value=value,
            original_confidence=original_confidence,
            intel_results=results,
        )

        enriched.aggregated_threat_level, enriched.aggregated_confidence, enriched.consensus_malicious = self._aggregate(results)

        return enriched

    async def enrich_iocs(self, iocs: list[dict]) -> list[EnrichedIOC]:
        """Enrich multiple IOCs in parallel."""
        tasks = [self.enrich_ioc(ioc["ioc_type"], ioc["value"], ioc.get("confidence", 0.5)) for ioc in iocs]
        return await asyncio.gather(*tasks)

    def _aggregate(self, results: list[ThreatIntelResult]) -> tuple[ThreatLevel, float, bool]:
        """Aggregate results from multiple providers."""
        if not results:
            return ThreatLevel.UNKNOWN, 0.0, False

        # Filter out errors
        valid_results = [r for r in results if not r.error]
        if not valid_results:
            return ThreatLevel.UNKNOWN, 0.0, False

        # Count malicious verdicts
        malicious_count = sum(1 for r in valid_results if r.malicious)
        total_count = len(valid_results)

        # Weighted confidence average
        total_confidence = sum(r.confidence for r in valid_results)
        avg_confidence = total_confidence / total_count

        # Consensus: majority says malicious
        consensus_malicious = malicious_count > total_count / 2

        # Determine threat level
        max_level = max(r.threat_level.value for r in valid_results)
        if consensus_malicious and avg_confidence > 0.7:
            threat_level = ThreatLevel(max_level)
        elif consensus_malicious:
            threat_level = ThreatLevel.MEDIUM
        elif malicious_count > 0:
            threat_level = ThreatLevel.LOW
        else:
            threat_level = ThreatLevel.LOW

        return threat_level, avg_confidence, consensus_malicious

    async def close(self):
        """Close all provider sessions."""
        await asyncio.gather(*[p.close() for p in self.providers], return_exceptions=True)


# Global aggregator instance
_threat_intel: ThreatIntelAggregator | None = None


def get_threat_intel() -> ThreatIntelAggregator:
    """Get the global threat intelligence aggregator."""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelAggregator()
    return _threat_intel


async def enrich_sample_iocs(sample_id: str, iocs: list[dict]) -> list[EnrichedIOC]:
    """Convenience function to enrich IOCs for a sample."""
    aggregator = get_threat_intel()
    return await aggregator.enrich_iocs(iocs)