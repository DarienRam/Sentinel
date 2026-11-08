from sqlalchemy.orm import Session

from app.api.scans import (
    create_scan,
    get_scan,
    get_scan_analytics_summary,
    list_scans,
    update_scan_feedback,
)
from app.schemas.scan import ScanCreate, ScanFeedbackUpdate


ANONYMOUS_SESSION_ID = "test-anonymous-session"


def test_scan_is_created_and_returned_from_database(db_session: Session) -> None:
    created_scan = create_scan(
        ScanCreate(
            input_type="url",
            raw_content="http://verify-bank-login.ru/account-suspended",
        ),
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )

    assert created_scan.id == 1
    assert created_scan.risk_level in {"Medium", "High"}
    assert created_scan.finding_details
    assert created_scan.detected_categories

    scans = list_scans(
        limit=None,
        days=None,
        db=db_session,
        current_user=None,
        anonymous_session_id=ANONYMOUS_SESSION_ID,
    )

    assert len(scans) == 1
    assert scans[0].id == created_scan.id


def test_feedback_is_saved_on_existing_scan(db_session: Session) -> None:
    created_scan = create_scan(
        ScanCreate(
            input_type="message",
            raw_content="Are you available? Send me the OTP code immediately.",
        ),
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )

    updated_scan = update_scan_feedback(
        created_scan.id,
        ScanFeedbackUpdate(
            feedback="Correct",
            feedback_note="Good catch on the OTP request.",
        ),
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )

    assert updated_scan.feedback == "Correct"
    assert updated_scan.feedback_note == "Good catch on the OTP request."

    scan_detail = get_scan(
        created_scan.id,
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )

    assert scan_detail.feedback == "Correct"
    assert scan_detail.feedback_note == "Good catch on the OTP request."


def test_analytics_summary_uses_persisted_scans_and_feedback(
    db_session: Session,
) -> None:
    first_scan = create_scan(
        ScanCreate(
            input_type="email",
            raw_content="Dear customer, verify your password within 24 hours.",
        ),
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )
    create_scan(
        ScanCreate(
            input_type="message",
            raw_content="Friendly reminder about our team lunch tomorrow.",
        ),
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )
    update_scan_feedback(
        first_scan.id,
        ScanFeedbackUpdate(feedback="Correct", feedback_note=None),
        db_session,
        None,
        ANONYMOUS_SESSION_ID,
    )

    summary = get_scan_analytics_summary(
        days=None,
        db=db_session,
        current_user=None,
        anonymous_session_id=ANONYMOUS_SESSION_ID,
    )

    assert summary.total_scans == 2
    assert summary.feedback_count == 1
    assert summary.common_categories
