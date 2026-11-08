from app.schemas.scan import ScanCreate
from app.services.scan_engine import analyze_scan


def test_scan_engine_flags_credential_harvesting_link() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "Security alert: your mailbox upgrade is pending. "
                "Sign in here to reset your password immediately: https://portal-example.com"
            ),
        )
    )

    assert result.risk_level == "High"
    assert "Credential Harvesting" in result.detected_categories
    assert any(
        finding.category == "Credential Harvesting"
        for finding in result.finding_details
    )
    assert any(
        finding.category == "Credential Harvesting" and finding.matched_text
        for finding in result.finding_details
    )
    assert "credential" in result.summary.lower() or "account takeover" in result.summary.lower()
    assert "credentials" in result.recommendation.lower() or "codes" in result.recommendation.lower()


def test_scan_engine_flags_payment_rerouting_and_bec_language() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "Hi, this is the CEO. Keep this between us and update the bank account "
                "for the attached invoice with the new banking details today."
            ),
        )
    )

    assert result.risk_level == "High"
    assert "Payment Scam" in result.detected_categories
    assert "Business Email Compromise" in result.detected_categories
    assert "Secrecy Pressure" in result.detected_categories
    assert "payment fraud" in result.summary.lower() or "business email compromise" in result.summary.lower()
    assert "money" in result.recommendation.lower() or "banking" in result.recommendation.lower()


def test_scan_engine_flags_accounts_payable_routing_change_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Hi, this is Jordan from Accounts Payable. We need to update the "
                "bank details for the attached invoice before today's payment run "
                "closes. Please use the new routing and account information below "
                "and keep this between us while we finalize the vendor update. "
                "If the payment is sent to the old account, it may be delayed. "
                "Reply once the transfer has been changed."
            ),
        )
    )

    assert result.risk_level == "High"
    assert result.risk_score >= 65
    assert "Payment Scam" in result.detected_categories
    assert "Business Email Compromise" in result.detected_categories
    assert "Attack Chain" in result.detected_categories


def test_scan_engine_flags_impersonation_style_text_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Quick favor, I'm in a meeting and can't talk. "
                "Send me the OTP code and keep this between us."
            ),
        )
    )

    assert result.risk_level == "High"
    assert "Impersonation" in result.detected_categories
    assert "Credential Request" in result.detected_categories
    assert "Secrecy Pressure" in result.detected_categories


def test_scan_engine_flags_punycode_and_sensitive_url_path() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="url",
            raw_content=(
                "http://xn--paypa1-security-check-9v2d.com/account/verify/login"
                "?session=urgent-review&redirect=portal-update"
            ),
        )
    )

    assert result.risk_level == "High"
    assert "Domain Reputation" in result.detected_categories
    assert "Credential Harvesting" in result.detected_categories
    assert "URL Structure" in result.detected_categories
    assert "link" in result.recommendation.lower() or "destination" in result.recommendation.lower()


def test_scan_engine_flags_gift_card_pressure_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Quick task, buy gift cards for the client dinner and send the card numbers "
                "to me privately today."
            ),
        )
    )

    assert result.risk_level == "High"
    assert "Payment Scam" in result.detected_categories
    assert "Secrecy Pressure" in result.detected_categories
    assert "Impersonation" in result.detected_categories


def test_scan_engine_keeps_benign_confirmation_language_low_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "Hi team, please review the Q3 budget draft and confirm any edits by Friday."
            ),
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score == 0
    assert result.confidence_score == 82
    assert "Credential Request" not in result.detected_categories


def test_scan_engine_keeps_benign_verification_language_low_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content="Can you verify the meeting room booking for Monday?",
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score == 0
    assert result.confidence_score == 82
    assert "Credential Request" not in result.detected_categories


def test_scan_engine_still_flags_contextual_account_verification_language() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "Please verify your account information and confirm your login details today."
            ),
        )
    )

    assert result.risk_level in {"Medium", "High"}
    assert "Credential Request" in result.detected_categories


def test_scan_engine_flags_security_code_reply_variant() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Are you free? Reply with the security code from your phone right away."
            ),
        )
    )

    assert result.risk_level in {"Medium", "High"}
    assert "Credential Request" in result.detected_categories


def test_scan_engine_flags_verification_code_account_variant() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "I am traveling and cannot speak. Please send me the verification "
                "code for the account."
            ),
        )
    )

    assert result.risk_level in {"Medium", "High"}
    assert "Credential Request" in result.detected_categories
    assert "Impersonation" in result.detected_categories


def test_scan_engine_keeps_benign_room_code_request_low_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content="Please text me the room code for the conference space.",
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score == 0
    assert result.confidence_score == 82
    assert "Credential Request" not in result.detected_categories


def test_scan_engine_dials_back_training_portal_sign_in_language() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Hi team, please click the training portal below and sign in with "
                "your employee account before Friday so we can confirm course completion."
            ),
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score < 35
    assert "Attack Chain" not in result.detected_categories
    assert any(
        finding.category == "Credential Harvesting"
        and finding.matched_text == "sign in"
        for finding in result.finding_details
    )


def test_scan_engine_keeps_job_board_login_prompt_low_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "Indeed found a role that matches your profile. Sign in to your "
                "Indeed account to review the job details and submit an application."
            ),
        )
    )

    assert result.risk_level == "Low"
    assert "Attack Chain" not in result.detected_categories


def test_scan_engine_flags_fake_remote_job_text_scam() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Hi! I'm Taylor from the Amazon hiring team. Your background caught our "
                "attention for a relaxed, remote collaborator role. It's very light work—just "
                "60-90 minutes of your time, 4 days a week, on your own schedule. "
                "Compensation ranges from $250 to $500 daily. If you're interested, please "
                "text 12025550123 to get started."
            ),
        )
    )

    assert result.risk_level == "High"
    assert result.risk_score >= 55
    assert "Employment Scam" in result.detected_categories
    assert any(
        finding.category == "Employment Scam" and "text 12025550123" in (finding.matched_text or "")
        for finding in result.finding_details
    )
    assert "official careers site" in result.recommendation.lower()


def test_scan_engine_keeps_normal_remote_job_update_low_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Thanks for applying. The interview for the remote support role is scheduled "
                "for Tuesday at 2 PM. Please use the calendar invitation in your applicant portal."
            ),
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score == 0
    assert "Employment Scam" not in result.detected_categories


def test_scan_engine_returns_zero_risk_with_higher_confidence_when_no_signals_exist() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content="Do you want to play video games later tonight?",
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score == 0
    assert result.confidence_score == 82
    assert result.finding_details == []


def test_scan_engine_flags_paraphrased_account_activity_lure_as_medium_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "We noticed unusual activity connected to your profile earlier today. "
                "To avoid interruption, review the recent sign-in attempt here."
            ),
        )
    )

    assert result.risk_level == "Medium"
    assert result.risk_score >= 30
    assert "Account Pressure" in result.detected_categories
    assert any(
        finding.category == "Account Pressure"
        for finding in result.finding_details
    )


def test_scan_engine_keeps_benign_profile_review_notice_low_risk() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Your profile review for the community directory is ready. "
                "Please check the draft and confirm any spelling updates this week."
            ),
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score == 0
    assert "Account Pressure" not in result.detected_categories


def test_scan_engine_uses_caution_recommendation_for_low_risk_signals() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "A device enrollment was added to your profile late tonight. "
                "Access will remain limited until the activity record is reviewed through the member page."
            ),
        )
    )

    assert result.risk_level == "Low"
    assert result.risk_score > 0
    assert result.recommendation.startswith("Limited caution signals")


def test_scan_engine_flags_gray_risk_message_about_device_enrollment() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "A device enrollment was added to your profile late tonight. "
                "Access to some features will remain limited until the activity record is reviewed through the member page."
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_score < 30
    assert result.risk_level == "Low"
    assert "Account Pressure" in result.detected_categories


def test_scan_engine_flags_gray_risk_email_about_document_release_delay() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="email",
            raw_content=(
                "Subject: Document release pending\n\n"
                "Your year-end document is ready, but release has been delayed because part "
                "of the identity record could not be matched. Complete the review shown in "
                "the attached notice to restore access. Records Team"
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_score < 30
    assert result.risk_level == "Low"
    assert "Account Pressure" in result.detected_categories


def test_scan_engine_flags_low_sim_request_review_pressure() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "A replacement SIM request tied to this number is still pending. "
                "Use the support form in the notice to stop transfer completion if you did not request it."
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_score < 30
    assert result.risk_level == "Low"


def test_scan_engine_adds_small_weight_for_overnight_change_language() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "A change to your billing profile is scheduled to take effect overnight. "
                "Review the request details now if this was not submitted by you."
            ),
        )
    )

    assert result.risk_score > 18
    assert result.risk_level == "Low"


def test_scan_engine_flags_recovery_access_review_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "There was an attempt to move recovery access on your account this morning. "
                "Use the review page below to stop the change before the request finishes processing."
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_level in {"Low", "Medium"}
    assert "Account Pressure" in result.detected_categories


def test_scan_engine_flags_payee_and_transfer_queue_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "A new payee profile was added for outgoing funds. If this was not you, "
                "open the case summary now so the transfer queue can be stopped."
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_level in {"Low", "Medium"}


def test_scan_engine_flags_mailbox_settings_altered_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "Your mailbox security settings were altered from a device not normally tied "
                "to this profile. Reconfirm the access record through the member portal to prevent further changes."
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_level in {"Low", "Medium"}


def test_scan_engine_flags_incoming_payments_approval_message() -> None:
    result = analyze_scan(
        ScanCreate(
            input_type="message",
            raw_content=(
                "A request to redirect incoming payments is waiting for final approval. "
                "Review the authorization note now if you did not submit this change."
            ),
        )
    )

    assert result.risk_score > 0
    assert result.risk_level in {"Low", "Medium"}
