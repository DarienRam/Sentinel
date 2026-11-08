from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import and_, false, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.api.auth import get_optional_current_user
from app.core.anonymous_sessions import get_anonymous_session_id
from app.core.config import settings
from app.core.database import get_db
from app.core.resource_protection import actor_rules, request_group
from app.models.scan import (
    Scan as ScanModel,
    ScanCategory as ScanCategoryModel,
    ScanFeedback as ScanFeedbackModel,
    ScanFinding as ScanFindingModel,
)
from app.models.user import User
from app.schemas.scan import (
    CategoryCount,
    FeedbackCount,
    InputTypeCount,
    ScanAnalyticsComparison,
    ScanAnalyticsSummary,
    ScanCreate,
    ScanFeedbackUpdate,
    ScanFinding,
    ScanResult,
    ScanStorageUpdate,
)
from app.services.scan_engine import analyze_scan
from app.services.retention import purge_expired_batch


def enforce_scan_budget(
    request: Request,
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
):
    actor = "user:" + str(current_user.id) if current_user else anonymous_session_id
    if actor:
        group = request_group(request.method, request.url.path)
        request.app.state.security_store.check(actor_rules(group, actor, current_user is not None))


router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(enforce_scan_budget)])
TEMP_SCAN_RETENTION_DAYS = 7
ALLOWED_RETENTION_DAYS = {7, 14, 30}


@router.post("", response_model=ScanResult)
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
) -> ScanResult:
    save_scan = payload.save_scan
    if current_user is None and not anonymous_session_id:
        raise HTTPException(
            status_code=400,
            detail="Anonymous scans require a browser session identifier.",
        )
    if current_user is None and save_scan:
        raise HTTPException(
            status_code=403,
            detail="Log in to save a scan permanently to account history.",
        )
    retention_days = payload.retention_days or TEMP_SCAN_RETENTION_DAYS
    if retention_days not in ALLOWED_RETENTION_DAYS:
        raise HTTPException(
            status_code=422,
            detail="Temporary scans must use a 7, 14, or 30 day retention window.",
        )
    _purge_expired_scans(db)
    analyzed_scan = analyze_scan(payload, scan_id=0)
    expires_at = None if save_scan else analyzed_scan.created_at + timedelta(days=retention_days)

    scan = ScanModel(
        user_id=current_user.id if current_user else None,
        anonymous_session_id=anonymous_session_id if current_user is None else None,
        input_type=analyzed_scan.input_type,
        raw_content=analyzed_scan.raw_content,
        risk_score=analyzed_scan.risk_score,
        confidence_score=analyzed_scan.confidence_score,
        risk_level=analyzed_scan.risk_level,
        summary=analyzed_scan.summary,
        recommendation=analyzed_scan.recommendation,
        is_saved=save_scan,
        expires_at=expires_at,
        created_at=analyzed_scan.created_at,
        findings=[
            ScanFindingModel(
                category=finding.category,
                severity=finding.severity,
                message=finding.message,
                matched_text=finding.matched_text,
            )
            for finding in analyzed_scan.finding_details
        ],
        categories=[
            ScanCategoryModel(name=category)
            for category in analyzed_scan.detected_categories
        ],
    )

    db.add(scan)
    db.commit()
    return _get_scan_or_404(scan.id, db, current_user, anonymous_session_id)


@router.get("", response_model=list[ScanResult])
def list_scans(
    limit: int | None = Query(default=None, ge=1, le=100),
    days: int | None = Query(default=None, ge=1, le=3650),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
    risk_level: Annotated[str | None, Query(pattern="^(Low|Medium|High)$")] = None,
    feedback_status: Annotated[str | None, Query(pattern="^(pending|reviewed)$")] = None,
) -> list[ScanResult]:
    _purge_expired_scans(db)
    query = (
        select(ScanModel)
        .where(_owner_filter(current_user, anonymous_session_id))
        .where(_created_after_filter(days))
        .where(_risk_level_filter(risk_level))
        .where(_feedback_status_filter(feedback_status))
        .options(
            selectinload(ScanModel.findings),
            selectinload(ScanModel.categories),
            selectinload(ScanModel.feedback),
        )
        .order_by(ScanModel.created_at.desc(), ScanModel.id.desc())
    )

    query = query.limit(limit if isinstance(limit, int) else settings.history_default_limit)

    scans = db.scalars(query).all()

    return [_scan_to_schema(scan) for scan in scans]


@router.get("/analytics/summary", response_model=ScanAnalyticsSummary)
def get_scan_analytics_summary(
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    days: int | None = Query(default=None, ge=1, le=3650),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
    risk_level: Annotated[str | None, Query(pattern="^(Low|Medium|High)$")] = None,
    feedback_status: Annotated[str | None, Query(pattern="^(pending|reviewed)$")] = None,
) -> ScanAnalyticsSummary:
    _purge_expired_scans(db)
    scans = db.scalars(
        _analytics_query(current_user, anonymous_session_id, limit)
        .where(_created_after_filter(days))
        .where(_risk_level_filter(risk_level))
        .where(_feedback_status_filter(feedback_status))
    ).all()
    previous_period_scans = (
        db.scalars(
            _analytics_query(current_user, anonymous_session_id, limit)
            .where(_created_within_previous_window_filter(days))
            .where(_risk_level_filter(risk_level))
            .where(_feedback_status_filter(feedback_status))
        ).all()
        if days is not None
        else []
    )

    category_counts: dict[str, int] = {}
    for scan in scans:
        for category in scan.categories:
            category_counts[category.name] = category_counts.get(category.name, 0) + 1

    common_categories = [
        CategoryCount(name=name, count=count)
        for name, count in sorted(
            category_counts.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:6]
    ]

    input_type_order = ("url", "email", "message")
    input_type_counts = [
        InputTypeCount(
            input_type=input_type,
            count=sum(1 for scan in scans if scan.input_type == input_type),
        )
        for input_type in input_type_order
    ]

    feedback_order = ("Correct", "False Positive", "False Negative")
    feedback_breakdown = [
        FeedbackCount(
            label=label,
            count=sum(
                1
                for scan in scans
                if scan.feedback is not None and scan.feedback.label == label
            ),
        )
        for label in feedback_order
    ]

    high_risk_scans = [scan for scan in scans if scan.risk_level == "High"]
    feedback_count = sum(1 for scan in scans if scan.feedback is not None)
    needs_review_count = len(scans) - feedback_count
    high_risk_needing_feedback_count = sum(
        1
        for scan in high_risk_scans
        if scan.feedback is None
    )
    comparison = _build_analytics_comparison(scans, previous_period_scans, days)

    return ScanAnalyticsSummary(
        total_scans=len(scans),
        high_risk_count=sum(1 for scan in scans if scan.risk_level == "High"),
        medium_risk_count=sum(1 for scan in scans if scan.risk_level == "Medium"),
        low_risk_count=sum(1 for scan in scans if scan.risk_level == "Low"),
        feedback_count=feedback_count,
        needs_review_count=needs_review_count,
        high_risk_needing_feedback_count=high_risk_needing_feedback_count,
        average_risk_score=round(
            sum(scan.risk_score for scan in scans) / len(scans)
        ) if scans else 0,
        average_confidence_score=round(
            sum(scan.confidence_score for scan in scans) / len(scans)
        ) if scans else 0,
        latest_high_risk_created_at=max(
            (scan.created_at for scan in high_risk_scans),
            default=None,
        ),
        input_type_counts=input_type_counts,
        feedback_breakdown=feedback_breakdown,
        common_categories=common_categories,
        comparison=comparison,
    )


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
) -> ScanResult:
    _purge_expired_scans(db)
    return _get_scan_or_404(scan_id, db, current_user, anonymous_session_id)


@router.post("/{scan_id}/feedback", response_model=ScanResult)
def update_scan_feedback(
    scan_id: int,
    payload: ScanFeedbackUpdate,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
) -> ScanResult:
    _purge_expired_scans(db)
    scan = _get_scan_model_or_404(scan_id, db, current_user, anonymous_session_id)
    if scan.feedback is None:
        scan.feedback = ScanFeedbackModel(
            label=payload.feedback,
            note=payload.feedback_note,
        )
    else:
        scan.feedback.label = payload.feedback
        scan.feedback.note = payload.feedback_note

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Feedback changed concurrently. Retry the operation.") from None
    return _get_scan_or_404(scan_id, db, current_user, anonymous_session_id)


@router.patch("/{scan_id}/storage", response_model=ScanResult)
def update_scan_storage(
    scan_id: int,
    payload: ScanStorageUpdate,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
) -> ScanResult:
    _purge_expired_scans(db)
    scan = _get_scan_model_or_404(scan_id, db, current_user, anonymous_session_id)

    if payload.save_scan:
        if current_user is None:
            raise HTTPException(
                status_code=403,
                detail="Log in to save a scan permanently to account history.",
            )
        scan.is_saved = True
        scan.expires_at = None
    else:
        retention_days = payload.retention_days or TEMP_SCAN_RETENTION_DAYS
        if retention_days not in ALLOWED_RETENTION_DAYS:
            raise HTTPException(
                status_code=422,
                detail="Temporary scans must use a 7, 14, or 30 day retention window.",
            )
        scan.is_saved = False
        scan.expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

    db.commit()
    return _get_scan_or_404(scan_id, db, current_user, anonymous_session_id)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
    anonymous_session_id: str | None = Depends(get_anonymous_session_id),
) -> Response:
    _purge_expired_scans(db)
    scan = _get_scan_model_or_404(scan_id, db, current_user, anonymous_session_id)
    db.delete(scan)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _get_scan_or_404(
    scan_id: int,
    db: Session,
    current_user: User | None,
    anonymous_session_id: str | None,
) -> ScanResult:
    return _scan_to_schema(
        _get_scan_model_or_404(scan_id, db, current_user, anonymous_session_id)
    )


def _get_scan_model_or_404(
    scan_id: int,
    db: Session,
    current_user: User | None,
    anonymous_session_id: str | None,
) -> ScanModel:
    scan = db.scalar(
        select(ScanModel)
        .where(ScanModel.id == scan_id)
        .where(_owner_filter(current_user, anonymous_session_id))
        .options(
            selectinload(ScanModel.findings),
            selectinload(ScanModel.categories),
            selectinload(ScanModel.feedback),
        )
    )

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")

    return scan


def _owner_filter(current_user: User | None, anonymous_session_id: str | None):
    if current_user is None:
        if not anonymous_session_id:
            return false()
        owner = and_(ScanModel.user_id.is_(None),
                     ScanModel.anonymous_session_id == anonymous_session_id)
    else:
        owner = ScanModel.user_id == current_user.id
    # Batched housekeeping must never make expired rows temporarily accessible.
    return and_(owner, or_(ScanModel.expires_at.is_(None),
                          ScanModel.expires_at > datetime.now(timezone.utc)))


def _purge_expired_scans(db: Session) -> None:
    purge_expired_batch(db)


def _created_after_filter(days: int | None):
    if days is None:
        return True

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    return ScanModel.created_at >= cutoff


def _created_within_previous_window_filter(days: int | None):
    if days is None:
        return False

    current_cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    previous_cutoff = current_cutoff - timedelta(days=days)
    return and_(
        ScanModel.created_at >= previous_cutoff,
        ScanModel.created_at < current_cutoff,
    )


def _analytics_query(
    current_user: User | None,
    anonymous_session_id: str | None,
    limit: int | None = None,
):
    query = (
        select(ScanModel)
        .where(_owner_filter(current_user, anonymous_session_id))
        .options(
            selectinload(ScanModel.categories),
            selectinload(ScanModel.feedback),
        )
        .order_by(ScanModel.created_at.desc(), ScanModel.id.desc())
    )

    query = query.limit(limit if isinstance(limit, int) else settings.history_default_limit)

    return query


def _risk_level_filter(risk_level: str | None):
    if risk_level is None:
        return True

    return ScanModel.risk_level == risk_level


def _feedback_status_filter(feedback_status: str | None):
    if feedback_status is None:
        return True

    if feedback_status == "pending":
        return ~ScanModel.feedback.has()

    return ScanModel.feedback.has()


def _build_analytics_comparison(
    scans: list[ScanModel],
    previous_period_scans: list[ScanModel],
    days: int | None,
) -> ScanAnalyticsComparison | None:
    if days is None:
        return None

    current_average_risk = round(
        sum(scan.risk_score for scan in scans) / len(scans)
    ) if scans else 0
    previous_average_risk = round(
        sum(scan.risk_score for scan in previous_period_scans) / len(previous_period_scans)
    ) if previous_period_scans else 0
    current_high_risk_count = sum(1 for scan in scans if scan.risk_level == "High")
    previous_high_risk_count = sum(
        1 for scan in previous_period_scans if scan.risk_level == "High"
    )

    return ScanAnalyticsComparison(
        previous_total_scans=len(previous_period_scans),
        previous_high_risk_count=previous_high_risk_count,
        previous_average_risk_score=previous_average_risk,
        scan_volume_change=len(scans) - len(previous_period_scans),
        high_risk_change=current_high_risk_count - previous_high_risk_count,
        average_risk_score_change=current_average_risk - previous_average_risk,
    )


def _scan_to_schema(scan: ScanModel) -> ScanResult:
    finding_details = [
        ScanFinding(
            category=finding.category,
            severity=finding.severity,
            message=finding.message,
            matched_text=finding.matched_text,
        )
        for finding in scan.findings
    ]
    finding_messages = [
        finding.message
        for finding in scan.findings
    ] or ["No obvious phishing indicators were detected by the starter rules."]

    return ScanResult(
        id=scan.id,
        input_type=scan.input_type,
        raw_content=scan.raw_content,
        risk_score=scan.risk_score,
        confidence_score=scan.confidence_score,
        risk_level=scan.risk_level,
        summary=scan.summary,
        recommendation=scan.recommendation,
        detected_categories=[category.name for category in scan.categories],
        findings=finding_messages,
        finding_details=finding_details,
        feedback=scan.feedback.label if scan.feedback else None,
        feedback_note=scan.feedback.note if scan.feedback else None,
        is_saved=scan.is_saved,
        expires_at=scan.expires_at,
        created_at=scan.created_at,
    )
