from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from app.core.url_validation import parse_scan_url


InputType = Literal["url", "email", "message"]
RiskLevel = Literal["Low", "Medium", "High"]
FeedbackLabel = Literal["Correct", "False Positive", "False Negative"]


class ScanCreate(BaseModel):
    input_type: InputType
    raw_content: str = Field(..., min_length=4, max_length=5000)
    save_scan: bool = False
    retention_days: int | None = Field(default=None, ge=1, le=365)

    @model_validator(mode="after")
    def validate_url_input(self) -> "ScanCreate":
        if self.input_type == "url":
            parse_scan_url(self.raw_content)
        return self


class ScanFinding(BaseModel):
    category: str
    severity: RiskLevel
    message: str
    matched_text: str | None = None


class ScanFeedbackUpdate(BaseModel):
    feedback: FeedbackLabel
    feedback_note: str | None = Field(default=None, max_length=1000)


class ScanStorageUpdate(BaseModel):
    save_scan: bool
    retention_days: int | None = Field(default=None, ge=1, le=365)


class CategoryCount(BaseModel):
    name: str
    count: int


class InputTypeCount(BaseModel):
    input_type: InputType
    count: int


class FeedbackCount(BaseModel):
    label: FeedbackLabel
    count: int


class ScanAnalyticsComparison(BaseModel):
    previous_total_scans: int
    previous_high_risk_count: int
    previous_average_risk_score: int
    scan_volume_change: int
    high_risk_change: int
    average_risk_score_change: int


class ScanAnalyticsSummary(BaseModel):
    total_scans: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    feedback_count: int
    needs_review_count: int
    high_risk_needing_feedback_count: int
    average_risk_score: int
    average_confidence_score: int
    latest_high_risk_created_at: datetime | None
    input_type_counts: list[InputTypeCount]
    feedback_breakdown: list[FeedbackCount]
    common_categories: list[CategoryCount]
    comparison: ScanAnalyticsComparison | None


class ScanResult(BaseModel):
    id: int
    input_type: InputType
    raw_content: str
    risk_score: int = Field(..., ge=0, le=100)
    confidence_score: int = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    summary: str
    recommendation: str
    detected_categories: list[str]
    findings: list[str]
    finding_details: list[ScanFinding]
    feedback: FeedbackLabel | None = None
    feedback_note: str | None = None
    is_saved: bool = False
    expires_at: datetime | None = None
    created_at: datetime


def build_timestamp() -> datetime:
    return datetime.now(timezone.utc)
