from __future__ import annotations

import datetime as dt
from typing import Any

from pydantic import BaseModel, Field


class IOCOut(BaseModel):
    ioc_type: str
    value: str
    context: str | None = None
    confidence: float

    model_config = {"from_attributes": True}


class SampleSummary(BaseModel):
    id: str
    original_filename: str
    file_size: int
    sha256: str
    file_type: str
    target_os: str
    status: str
    verdict: str
    risk_score: float
    created_at: dt.datetime

    model_config = {"from_attributes": True}


class SampleDetail(SampleSummary):
    sha1: str
    md5: str
    ssdeep: str | None = None
    mime_type: str
    static_report: dict[str, Any] | None = None
    sandbox_report: dict[str, Any] | None = None
    network_report: dict[str, Any] | None = None
    iocs: list[IOCOut] = []

    model_config = {"from_attributes": True}


class UploadResponse(BaseModel):
    sample_id: str
    status: str
    message: str


class CitizenReportIn(BaseModel):
    reporter_name: str | None = Field(None, description="Leave blank to report anonymously")
    reporter_contact: str | None = Field(None, description="Email or phone, optional")
    report_type: str = Field(..., pattern="^(file|url|ip|app)$")
    description: str = Field(..., min_length=10, max_length=5000)
    submitted_value: str | None = Field(None, description="URL / IP / app package id, if not a file")


class CitizenReportOut(BaseModel):
    id: str
    report_type: str
    status: str
    created_at: dt.datetime
    reference_code: str

    model_config = {"from_attributes": True}
