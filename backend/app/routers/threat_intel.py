"""
Threat Intelligence API routes.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.auth.rbac import User, require_analyst
from app.threat_intel.integration import (
    EnrichedIOC,
    enrich_sample_iocs,
    get_threat_intel,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intelligence"])


@router.get("/providers")
async def list_providers(current_user: User = Depends(require_analyst)):
    """List configured threat intelligence providers."""
    intel = get_threat_intel()
    return {
        "providers": [
            {
                "name": p.name,
                "rate_limit": p.rate_limit,
                "has_api_key": p.api_key is not None,
            }
            for p in intel.providers
        ],
        "total": len(intel.providers),
    }


@router.post("/lookup/hash/{hash_value}")
async def lookup_hash(
    hash_value: str,
    current_user: User = Depends(require_analyst),
):
    """Look up a file hash across all providers."""
    intel = get_threat_intel()
    if not intel.providers:
        raise HTTPException(status_code=503, detail="No threat intelligence providers configured")
    
    enriched = await intel.enrich_ioc("hash", hash_value)
    return format_enriched_ioc(enriched)


@router.post("/lookup/ip/{ip}")
async def lookup_ip(
    ip: str,
    current_user: User = Depends(require_analyst),
):
    """Look up an IP address across all providers."""
    intel = get_threat_intel()
    if not intel.providers:
        raise HTTPException(status_code=503, detail="No threat intelligence providers configured")
    
    enriched = await intel.enrich_ioc("ip", ip)
    return format_enriched_ioc(enriched)


@router.post("/lookup/domain/{domain}")
async def lookup_domain(
    domain: str,
    current_user: User = Depends(require_analyst),
):
    """Look up a domain across all providers."""
    intel = get_threat_intel()
    if not intel.providers:
        raise HTTPException(status_code=503, detail="No threat intelligence providers configured")
    
    enriched = await intel.enrich_ioc("domain", domain)
    return format_enriched_ioc(enriched)


@router.post("/lookup/url")
async def lookup_url(
    url: str,
    current_user: User = Depends(require_analyst),
):
    """Look up a URL across all providers."""
    intel = get_threat_intel()
    if not intel.providers:
        raise HTTPException(status_code=503, detail="No threat intelligence providers configured")
    
    enriched = await intel.enrich_ioc("url", url)
    return format_enriched_ioc(enriched)


@router.post("/enrich/sample/{sample_id}")
async def enrich_sample(
    sample_id: str,
    current_user: User = Depends(require_analyst),
):
    """Enrich all IOCs for a sample with threat intelligence."""
    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models import IOC, Sample
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Sample).where(Sample.id == sample_id))
        sample = result.scalar_one_or_none()
        
        if not sample:
            raise HTTPException(status_code=404, detail="Sample not found")
        
        # Get IOCs from sample
        result = await db.execute(select(IOC).where(IOC.sample_id == sample_id))
        iocs = result.scalars().all()
        
        ioc_dicts = [
            {
                "ioc_type": ioc.ioc_type,
                "value": ioc.value,
                "confidence": ioc.confidence,
            }
            for ioc in iocs
        ]
        
        if not ioc_dicts:
            return {"message": "No IOCs found for this sample", "enriched": []}
        
        enriched = await enrich_sample_iocs(sample_id, ioc_dicts)
        return {
            "sample_id": sample_id,
            "enriched": [format_enriched_ioc(e) for e in enriched],
        }


@router.post("/enrich/bulk")
async def enrich_bulk(
    iocs: list[dict],
    current_user: User = Depends(require_analyst),
):
    """Enrich multiple IOCs in one request."""
    if not iocs:
        return {"enriched": []}
    
    if len(iocs) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 IOCs per request")
    
    intel = get_threat_intel()
    enriched = await intel.enrich_iocs(iocs)
    return {
        "enriched": [format_enriched_ioc(e) for e in enriched],
    }


def format_enriched_ioc(enriched: EnrichedIOC) -> dict:
    """Format enriched IOC for API response."""
    return {
        "ioc_type": enriched.ioc_type,
        "value": enriched.value,
        "original_confidence": enriched.original_confidence,
        "aggregated_threat_level": enriched.aggregated_threat_level.name,
        "aggregated_confidence": enriched.aggregated_confidence,
        "consensus_malicious": enriched.consensus_malicious,
        "sources": [
            {
                "source": r.source,
                "malicious": r.malicious,
                "threat_level": r.threat_level.name,
                "confidence": r.confidence,
                "tags": r.tags,
                "families": r.families,
                "references": r.references,
                "error": r.error,
            }
            for r in enriched.intel_results
        ],
    }


@router.get("/stats")
async def threat_intel_stats(current_user: User = Depends(require_analyst)):
    """Get threat intelligence usage statistics."""
    intel = get_threat_intel()
    return {
        "providers_configured": len(intel.providers),
        "providers": [p.name for p in intel.providers],
    }