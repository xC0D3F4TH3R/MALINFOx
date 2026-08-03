"""
MALINFO — YARA Rule Management API Router
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl

from app.analysis.yara_manager import YaraManager

logger = logging.getLogger("malinfo.yara_api")

router = APIRouter(prefix="/api/yara", tags=["yara"])

# Global YARA manager instance
_yara_manager: YaraManager | None = None


def get_yara_manager() -> YaraManager:
    global _yara_manager
    if _yara_manager is None:
        _yara_manager = YaraManager()
    return _yara_manager


# ── Schemas ──

class RulesetCreate(BaseModel):
    name: str
    description: str = ""
    source_rules: list[str] = []  # Rule IDs or file paths


class RulesetResponse(BaseModel):
    ruleset_id: str
    name: str
    description: str
    rule_count: int
    enabled_rule_count: int
    compiled_path: str | None
    compilation_time_ms: float
    version: int
    created_at: str
    updated_at: str


class FeedCreate(BaseModel):
    name: str
    url: HttpUrl
    auth_type: str = "none"
    auth_config: dict = {}
    schedule: str = "daily"
    filters: dict = {}
    enabled: bool = True


class FeedResponse(BaseModel):
    feed_id: str
    name: str
    url: str
    auth_type: str
    schedule: str
    enabled: bool
    last_sync: str | None
    last_sync_status: str
    rules_imported: int


class CompileRequest(BaseModel):
    ruleset_id: str


class TestRequest(BaseModel):
    ruleset_id: str
    sample_path: str


class RuleValidateRequest(BaseModel):
    content: str


# ── Endpoints ──

@router.get("/rulesets", response_model=list[RulesetResponse])
async def list_rulesets():
    """List all available YARA rulesets with metadata."""
    manager = get_yara_manager()
    rulesets = []
    for ruleset in manager._ruleset_cache.values():
        rulesets.append(RulesetResponse(
            ruleset_id=ruleset.ruleset_id,
            name=ruleset.name,
            description=ruleset.description,
            rule_count=ruleset.rule_count,
            enabled_rule_count=ruleset.enabled_rule_count,
            compiled_path=ruleset.compiled_path,
            compilation_time_ms=ruleset.compilation_time_ms,
            version=ruleset.version,
            created_at=ruleset.created_at.isoformat(),
            updated_at=ruleset.updated_at.isoformat(),
        ))
    return rulesets


@router.post("/rulesets", response_model=RulesetResponse, status_code=status.HTTP_201_CREATED)
async def create_ruleset(ruleset_data: RulesetCreate, background_tasks: BackgroundTasks):
    """Create a new YARA ruleset from source rules."""
    manager = get_yara_manager()
    ruleset = await manager.create_ruleset(
        name=ruleset_data.name,
        description=ruleset_data.description,
        source_rules=ruleset_data.source_rules,
    )
    # Trigger compilation in background
    background_tasks.add_task(manager.compile_ruleset, ruleset.ruleset_id)
    return RulesetResponse(
        ruleset_id=ruleset.ruleset_id,
        name=ruleset.name,
        description=ruleset.description,
        rule_count=ruleset.rule_count,
        enabled_rule_count=ruleset.enabled_rule_count,
        compiled_path=ruleset.compiled_path,
        compilation_time_ms=ruleset.compilation_time_ms,
        version=ruleset.version,
        created_at=ruleset.created_at.isoformat(),
        updated_at=ruleset.updated_at.isoformat(),
    )


@router.post("/rulesets/{ruleset_id}/compile")
async def compile_ruleset(ruleset_id: str, background_tasks: BackgroundTasks):
    """Trigger compilation of a ruleset."""
    manager = get_yara_manager()
    background_tasks.add_task(manager.compile_ruleset, ruleset_id)
    return {"message": "Compilation started", "ruleset_id": ruleset_id}


@router.get("/rulesets/{ruleset_id}/performance")
async def get_ruleset_performance(ruleset_id: str):
    """Get performance statistics for a ruleset."""
    manager = get_yara_manager()
    stats = await manager.get_performance_stats(ruleset_id)
    return stats


@router.post("/rulesets/{ruleset_id}/test")
async def test_ruleset(ruleset_id: str, test_request: TestRequest):
    """Run a ruleset against a test sample."""
    manager = get_yara_manager()
    results = await manager.test_ruleset(ruleset_id, Path(test_request.sample_path))
    return results


@router.post("/rules/validate")
async def validate_rule(rule_request: RuleValidateRequest):
    """Validate YARA rule syntax before committing."""
    manager = get_yara_manager()
    is_valid, errors = manager.validate_rule_syntax(rule_request.content)
    return {"valid": is_valid, "errors": errors}


@router.get("/feeds", response_model=list[FeedResponse])
async def list_feeds():
    """List configured YARA feeds."""
    manager = get_yara_manager()
    feeds = []
    for feed in manager.feeds.values():
        feeds.append(FeedResponse(
            feed_id=feed.feed_id,
            name=feed.name,
            url=feed.url,
            auth_type=feed.auth_type,
            schedule=feed.schedule,
            enabled=feed.enabled,
            last_sync=feed.last_sync.isoformat() if feed.last_sync else None,
            last_sync_status=feed.last_sync_status,
            rules_imported=feed.rules_imported,
        ))
    return feeds


@router.post("/feeds", response_model=FeedResponse, status_code=status.HTTP_201_CREATED)
async def create_feed(feed_data: FeedCreate):
    """Add a new YARA feed."""
    manager = get_yara_manager()
    feed = await manager.add_feed(
        name=feed_data.name,
        url=str(feed_data.url),
        auth_type=feed_data.auth_type,
        auth_config=feed_data.auth_config,
        schedule=feed_data.schedule,
        filters=feed_data.filters,
        enabled=feed_data.enabled,
    )
    return FeedResponse(
        feed_id=feed.feed_id,
        name=feed.name,
        url=feed.url,
        auth_type=feed.auth_type,
        schedule=feed.schedule,
        enabled=feed.enabled,
        last_sync=feed.last_sync.isoformat() if feed.last_sync else None,
        last_sync_status=feed.last_sync_status,
        rules_imported=feed.rules_imported,
    )


@router.post("/feeds/sync")
async def sync_feeds(background_tasks: BackgroundTasks, feed_id: str | None = None):
    """Synchronize all feeds or a specific feed."""
    manager = get_yara_manager()
    if feed_id:
        background_tasks.add_task(manager.sync_feed, feed_id)
        return {"message": f"Sync started for feed {feed_id}"}
    else:
        background_tasks.add_task(manager.sync_all_feeds)
        return {"message": "Sync started for all feeds"}


@router.post("/rules/upload")
async def upload_rules_file(file: UploadFile = File(...)):
    """Upload a YARA rule file."""
    manager = get_yara_manager()
    content = await file.read()
    ruleset = await manager.import_rules_file(content, file.filename)
    return {
        "message": "Rules imported",
        "ruleset_id": ruleset.ruleset_id,
        "rules_imported": ruleset.rule_count,
    }


@router.get("/compiled/{ruleset_id}")
async def download_compiled_ruleset(ruleset_id: str):
    """Download compiled ruleset (.yarac file)."""
    manager = get_yara_manager()
    ruleset = manager._ruleset_cache.get(ruleset_id)
    if not ruleset or not ruleset.compiled_path:
        raise HTTPException(status_code=404, detail="Compiled ruleset not found")
    return FileResponse(
        ruleset.compiled_path,
        media_type="application/octet-stream",
        filename=f"{ruleset.name}.yarac",
    )


@router.get("/stats")
async def get_yara_stats():
    """Get overall YARA system statistics."""
    manager = get_yara_manager()
    return {
        "total_rulesets": len(manager._ruleset_cache),
        "total_rules": sum(r.rule_count for r in manager._ruleset_cache.values()),
        "total_feeds": len(manager.feeds),
        "enabled_feeds": sum(1 for f in manager.feeds.values() if f.enabled),
        "compiled_rulesets": sum(1 for r in manager._ruleset_cache.values() if r.compiled_path),
    }