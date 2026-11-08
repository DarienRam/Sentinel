import re
from urllib.parse import urlparse

from app.schemas.scan import ScanCreate, ScanFinding, ScanResult, build_timestamp


KEYWORD_RULES: tuple[tuple[str, int, str, str, str], ...] = (
    ("urgent", 14, "Urgency", "Medium", "Uses urgency language often seen in phishing attempts."),
    ("password", 18, "Credential Request", "High", "Mentions passwords or account credentials."),
    ("login", 15, "Credential Request", "Medium", "References login activity or account access."),
    ("bank", 12, "Financial Context", "Medium", "Mentions banking or financial context."),
    ("click", 8, "Call To Action", "Low", "Encourages a direct click action."),
    ("suspended", 20, "Account Pressure", "High", "Uses account suspension pressure tactics."),
    ("gift card", 22, "Payment Scam", "High", "Contains gift card language associated with scams."),
    ("wire transfer", 25, "Payment Scam", "High", "References wire transfers, a common fraud indicator."),
)

IMPERSONATION_OPENERS = (
    "are you available",
    "are you free",
    "do you have a minute",
    "quick favor",
    "quick task",
)

SECRECY_PHRASES = (
    "keep this between us",
    "do not tell anyone",
    "confidential",
    "discreet",
    "privately",
)

CREDENTIAL_HARVEST_PHRASES = (
    "reset your password",
    "sign in",
    "log in",
    "verify your account",
    "account is locked",
    "security alert",
    "mailbox upgrade",
)

BENIGN_SIGN_IN_CONTEXT_TERMS = (
    "training",
    "training portal",
    "course completion",
    "employee account",
    "job",
    "job board",
    "application",
    "apply",
    "indeed",
    "linkedin",
    "recruiter",
    "onboarding",
)

PAYMENT_REROUTE_PHRASES = (
    "update your direct deposit",
    "change bank account",
    "update the bank details",
    "update bank details",
    "bank details",
    "new banking details",
    "new routing",
    "routing and account information",
    "routing and account details",
    "new account information",
    "payment instructions",
    "invoice attached",
    "routing number",
)

BUSINESS_PAYMENT_ROLE_TERMS = (
    "ceo",
    "cfo",
    "finance team",
    "payroll",
    "executive",
    "accounts payable",
    "accounts receivable",
    "accounting",
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}

SENSITIVE_PATH_TERMS = (
    "login",
    "verify",
    "account",
    "secure",
    "password",
    "update",
    "signin",
)

FINANCIAL_PRESSURE_PHRASES = (
    "purchase gift cards",
    "buy gift cards",
    "send the card numbers",
    "send the codes",
    "payment today",
    "process this payment",
)

CREDENTIAL_CONTEXT_TERMS = (
    "account",
    "identity",
    "password",
    "credentials",
    "credential",
    "login",
    "log in",
    "sign in",
    "security",
    "bank",
    "banking",
    "mailbox",
    "otp",
    "code",
)

AUTH_CODE_REQUEST_ACTIONS = (
    "send me",
    "text me",
    "reply with",
    "share",
    "forward",
)

AUTH_CODE_TERMS = (
    "otp",
    "one-time password",
    "verification code",
    "security code",
    "login code",
    "auth code",
)

AVAILABILITY_EXCUSE_PHRASES = (
    "can't talk",
    "cannot talk",
    "cannot speak",
    "in a meeting",
    "from my phone",
    "traveling",
)

ACCOUNT_CONTEXT_TERMS = (
    "account",
    "profile",
    "sign-in",
    "signin",
    "login",
    "log in",
    "device",
    "mailbox",
    "subscription",
    "billing",
    "payment",
    "delivery",
    "security",
    "access",
    "settings",
    "recovery",
    "protection",
    "payee",
    "funds",
    "payments",
    "authorization",
)

SUSPICIOUS_ACTIVITY_PHRASES = (
    "unusual activity",
    "recent sign-in attempt",
    "sign-in attempt",
    "access attempt",
    "change request",
    "recent activity",
    "activity connected to",
    "problem validating",
    "unable to complete",
    "could not be completed",
    "could not be verified",
    "does not match our records",
    "pending review",
    "temporary hold",
    "security concern",
    "attempt to move",
    "was altered",
    "redirect incoming payments",
    "final approval",
    "waiting for final approval",
    "recovery access",
)

CONSEQUENCE_PRESSURE_PHRASES = (
    "avoid interruption",
    "prevent cancellation",
    "may stop coming through",
    "may pause",
    "may be restricted",
    "has been limited",
    "to keep service active",
    "to prevent transfer",
    "to avoid return processing",
    "before processing closes",
    "until verification is finished",
    "until identity details are confirmed",
    "before the request finishes processing",
    "so the transfer queue can be stopped",
    "to prevent further changes",
)

ACCOUNT_ACTION_TERMS = (
    "review",
    "confirm",
    "check",
    "update",
    "validate",
    "finish",
    "continue",
    "resubmit",
    "restore",
    "follow the steps",
    "open the portal",
    "open the notice",
    "use the secure form",
    "support form",
    "reconfirm",
    "open the case summary",
    "review the authorization note",
    "review page",
)

ADMINISTRATIVE_CONTEXT_TERMS = (
    "profile",
    "device",
    "access",
    "record",
    "enrollment",
    "destination",
    "funds",
    "payment",
    "billing",
    "mailbox",
    "benefits",
    "document",
    "tax",
    "identity",
    "shipment",
    "delivery",
    "sim",
    "routing",
    "payout",
    "payee",
    "protections",
    "recovery",
    "authorization",
)

ADMINISTRATIVE_CHANGE_PHRASES = (
    "was added",
    "was changed",
    "was updated",
    "was adjusted",
    "is on hold",
    "is still pending",
    "could not be matched",
    "could not be associated",
    "was not fully processed",
    "has been delayed",
    "is scheduled to take effect",
    "release has been delayed",
    "access event",
    "replacement sim request",
    "review is attached",
    "was altered",
    "waiting for final approval",
    "attempt to move",
    "recovery path was updated",
    "recovery access",
)

ACCOUNT_CENTRIC_ADMIN_CONTEXT_TERMS = (
    "profile",
    "device",
    "access",
    "mailbox",
    "identity",
    "recovery",
    "protections",
)

UNRECOGNIZED_SOURCE_PHRASES = (
    "unrecognized",
    "do not recognize",
    "was not made by you",
    "not associate with your usual activity",
    "late tonight",
    "overnight",
)

USER_DENIAL_PHRASES = (
    "if you did not request it",
    "if this was not submitted by you",
    "if this update was not made by you",
    "if this change was not submitted by you",
    "if this wasn't you",
)

RECRUITMENT_CLAIM_PHRASES = (
    "hiring team",
    "recruiting team",
    "talent acquisition",
    "we are hiring",
)

REMOTE_WORK_PHRASES = (
    "remote",
    "work from home",
    "own schedule",
    "flexible schedule",
)


def analyze_scan(payload: ScanCreate, scan_id: int = 1) -> ScanResult:
    normalized = payload.raw_content.strip()
    lowered = normalized.lower()

    score = 0
    findings: list[str] = []
    finding_details: list[ScanFinding] = []

    score = _apply_keyword_rules(lowered, findings, finding_details, score)

    if payload.input_type == "url":
        score = _score_url(lowered, findings, finding_details, score)
    elif payload.input_type == "email":
        score = _score_email(lowered, findings, finding_details, score)
    else:
        score = _score_message(lowered, findings, finding_details, score)

    score = _score_cross_channel_patterns(lowered, findings, finding_details, score)
    score = _score_high_risk_combinations(findings, finding_details, score)

    score = min(score, 100)
    confidence_score = _confidence_from_findings(score, findings)
    risk_level = _risk_level_from_score(score)
    detected_categories = _detected_categories(finding_details)
    summary = _build_summary(risk_level, detected_categories, findings)
    recommendation = _build_recommendation(risk_level, detected_categories)

    return ScanResult(
        id=scan_id,
        input_type=payload.input_type,
        raw_content=normalized,
        risk_score=score,
        confidence_score=confidence_score,
        risk_level=risk_level,
        summary=summary,
        recommendation=recommendation,
        detected_categories=detected_categories,
        findings=findings or ["No obvious phishing indicators were detected by the starter rules."],
        finding_details=finding_details,
        created_at=build_timestamp(),
    )


def _apply_keyword_rules(
    lowered: str,
    findings: list[str],
    finding_details: list[ScanFinding],
    score: int,
) -> int:
    for keyword, weight, category, severity, message in KEYWORD_RULES:
        if keyword in lowered:
            score += weight
            _add_finding(
                findings,
                finding_details,
                category,
                severity,
                message,
                matched_text=keyword,
            )

    return score


def _score_url(
    lowered: str,
    findings: list[str],
    finding_details: list[ScanFinding],
    score: int,
) -> int:
    parsed_url = urlparse(lowered)
    hostname = parsed_url.hostname or ""

    if lowered.startswith("http://"):
        score += 18
        _add_finding(
            findings,
            finding_details,
            "URL Structure",
            "High",
            "Uses plain HTTP instead of HTTPS.",
            matched_text="http://",
        )

    suspicious_tlds = (".ru", ".tk", ".zip", ".click")
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        matched_tld = next(
            (tld for tld in suspicious_tlds if hostname.endswith(tld)),
            None,
        )
        score += 20
        _add_finding(
            findings,
            finding_details,
            "Domain Reputation",
            "High",
            "Uses a domain ending often associated with higher-risk links.",
            matched_text=matched_tld,
        )

    if "@" in lowered:
        score += 20
        _add_finding(
            findings,
            finding_details,
            "URL Obfuscation",
            "High",
            "Contains an @ symbol, which can hide the true destination in a URL.",
            matched_text="@",
        )

    if lowered.count("-") >= 2:
        score += 8
        _add_finding(
            findings,
            finding_details,
            "Domain Structure",
            "Low",
            "Contains repeated hyphenated segments, which can appear in spoofed domains.",
            matched_text=hostname or lowered,
        )

    if hostname in SHORTENER_DOMAINS:
        score += 18
        _add_finding(
            findings,
            finding_details,
            "URL Obfuscation",
            "Medium",
            "Uses a known URL shortener, which can hide the final destination.",
            matched_text=hostname,
        )

    if _looks_like_ip_address(hostname):
        score += 20
        _add_finding(
            findings,
            finding_details,
            "URL Structure",
            "High",
            "Uses an IP address instead of a recognizable domain name.",
            matched_text=hostname,
        )

    if _subdomain_count(hostname) >= 3:
        score += 10
        _add_finding(
            findings,
            finding_details,
            "Domain Structure",
            "Medium",
            "Uses several subdomains, which can make a destination harder to inspect.",
            matched_text=hostname,
        )

    if _special_character_count(lowered) >= 6:
        score += 8
        _add_finding(
            findings,
            finding_details,
            "URL Obfuscation",
            "Low",
            "Contains a high number of special characters for a URL.",
            matched_text=lowered,
        )

    if "xn--" in hostname:
        score += 22
        _add_finding(
            findings,
            finding_details,
            "Domain Reputation",
            "High",
            "Uses punycode-style domain formatting, which can appear in spoofed lookalike links.",
            matched_text="xn--",
        )

    suspicious_path_term = _matching_suspicious_path_term(parsed_url.path)
    if suspicious_path_term:
        score += 12
        _add_finding(
            findings,
            finding_details,
            "Credential Harvesting",
            "Medium",
            "Uses sensitive account or login terms in the URL path.",
            matched_text=suspicious_path_term,
        )

    if len(lowered) >= 120:
        score += 10
        _add_finding(
            findings,
            finding_details,
            "URL Obfuscation",
            "Medium",
            "Uses an unusually long URL, which can hide suspicious path details.",
            matched_text=lowered[:80],
        )

    return score


def _score_email(
    lowered: str,
    findings: list[str],
    finding_details: list[ScanFinding],
    score: int,
) -> int:
    if "dear customer" in lowered or "dear user" in lowered:
        matched_text = "dear customer" if "dear customer" in lowered else "dear user"
        score += 12
        _add_finding(
            findings,
            finding_details,
            "Impersonal Language",
            "Medium",
            "Uses a generic greeting instead of a real name.",
            matched_text=matched_text,
        )

    if "within 24 hours" in lowered or "immediately" in lowered:
        matched_text = "within 24 hours" if "within 24 hours" in lowered else "immediately"
        score += 14
        _add_finding(
            findings,
            finding_details,
            "Urgency",
            "Medium",
            "Applies time pressure to push a fast response.",
            matched_text=matched_text,
        )

    if _has_availability_excuse(lowered):
        matched_text = _first_matching_phrase(lowered, AVAILABILITY_EXCUSE_PHRASES)
        score += 14
        _add_finding(
            findings,
            finding_details,
            "Impersonation",
            "Medium",
            "Uses executive-style urgency or availability excuses often seen in impersonation attempts.",
            matched_text=matched_text,
        )

    return score


def _score_message(
    lowered: str,
    findings: list[str],
    finding_details: list[ScanFinding],
    score: int,
) -> int:
    if _requests_auth_code(lowered):
        matched_text = _first_matching_phrase(lowered, AUTH_CODE_TERMS)
        score += 24
        _add_finding(
            findings,
            finding_details,
            "Credential Request",
            "High",
            "Requests a code or one-time password, which is a strong social engineering signal.",
            matched_text=matched_text,
        )

    if any(opener in lowered for opener in IMPERSONATION_OPENERS):
        matched_text = _first_matching_phrase(lowered, IMPERSONATION_OPENERS)
        score += 10
        _add_finding(
            findings,
            finding_details,
            "Impersonation",
            "Medium",
            "Uses a casual opener commonly seen in impersonation-style scam messages.",
            matched_text=matched_text,
        )

    if _has_availability_excuse(lowered):
        matched_text = _first_matching_phrase(lowered, AVAILABILITY_EXCUSE_PHRASES)
        score += 14
        _add_finding(
            findings,
            finding_details,
            "Impersonation",
            "Medium",
            "Uses availability excuses that often appear in impersonation-style scam messages.",
            matched_text=matched_text,
        )

    return score


def _score_cross_channel_patterns(
    lowered: str,
    findings: list[str],
    finding_details: list[ScanFinding],
    score: int,
) -> int:
    if _requests_auth_code(lowered) and not _has_category(
        finding_details,
        "Credential Request",
    ):
        matched_text = _first_matching_phrase(lowered, AUTH_CODE_TERMS)
        score += 24
        _add_finding(
            findings,
            finding_details,
            "Credential Request",
            "High",
            "Requests a code or one-time password, which is a strong social engineering signal.",
            matched_text=matched_text,
        )

    contextual_credential_match = _extract_contextual_credential_match(lowered)
    if contextual_credential_match:
        score += 18
        _add_finding(
            findings,
            finding_details,
            "Credential Request",
            "Medium",
            "Requests account, identity, or credential-related verification.",
            matched_text=contextual_credential_match,
        )

    secrecy_phrase = _first_matching_phrase(lowered, SECRECY_PHRASES)
    if secrecy_phrase:
        score += 12
        _add_finding(
            findings,
            finding_details,
            "Secrecy Pressure",
            "Medium",
            "Asks for secrecy or discretion, which is a common social engineering tactic.",
            matched_text=secrecy_phrase,
        )

    credential_harvest_phrase = _first_matching_phrase(
        lowered,
        CREDENTIAL_HARVEST_PHRASES,
    )
    if credential_harvest_phrase and _has_link_lure(lowered):
        is_benign_sign_in_context = _has_benign_sign_in_context(lowered)
        score += 8 if is_benign_sign_in_context else 18
        _add_finding(
            findings,
            finding_details,
            "Credential Harvesting",
            "Medium" if is_benign_sign_in_context else "High",
            (
                "Prompts a sign-in or account-access action through a linked destination."
                if is_benign_sign_in_context
                else "Pushes the user toward signing in or resetting credentials through a linked destination."
            ),
            matched_text=credential_harvest_phrase,
        )

    payment_reroute_phrase = _first_matching_phrase(lowered, PAYMENT_REROUTE_PHRASES)
    if payment_reroute_phrase:
        score += 18
        _add_finding(
            findings,
            finding_details,
            "Payment Scam",
            "High",
            "Includes language about rerouting payments or banking details, which is common in fraud attempts.",
            matched_text=payment_reroute_phrase,
        )

    financial_pressure_phrase = _first_matching_phrase(lowered, FINANCIAL_PRESSURE_PHRASES)
    if financial_pressure_phrase:
        score += 18
        _add_finding(
            findings,
            finding_details,
            "Payment Scam",
            "High",
            "Pressures the recipient to move money or gift card value quickly.",
            matched_text=financial_pressure_phrase,
        )

    employment_scam_match = _extract_employment_scam_match(lowered)
    if employment_scam_match:
        score += 65 if employment_scam_match.signal_count == 4 else 35
        _add_finding(
            findings,
            finding_details,
            "Employment Scam",
            "High" if employment_scam_match.signal_count == 4 else "Medium",
            (
                "Combines a recruiter claim, remote-work framing, unusually high daily pay, "
                "and a request to move the conversation to a phone number."
                if employment_scam_match.signal_count == 4
                else "Combines several common fake-job signals, including recruiter framing, "
                "unusually high daily pay, or an off-platform text handoff."
            ),
            matched_text=employment_scam_match.text,
        )

    suspicious_account_pressure_match = _extract_suspicious_account_pressure_match(lowered)
    if suspicious_account_pressure_match:
        score += 24
        _add_finding(
            findings,
            finding_details,
            "Account Pressure",
            "Medium",
            "Describes account or access trouble and pushes the recipient to review or confirm recent activity.",
            matched_text=suspicious_account_pressure_match,
        )

        if _has_link_lure(lowered):
            score += 12
            _add_finding(
                findings,
                finding_details,
                "Credential Harvesting",
                "Medium",
                "Pairs account-activity pressure with a prompt to review details through a linked or portal-style destination.",
                matched_text=suspicious_account_pressure_match,
            )

    administrative_review_match = _extract_administrative_review_match(lowered)
    administrative_context_term = _first_matching_phrase(
        lowered,
        ADMINISTRATIVE_CONTEXT_TERMS,
    )
    if (
        suspicious_account_pressure_match
        and administrative_context_term in ACCOUNT_CENTRIC_ADMIN_CONTEXT_TERMS
    ):
        administrative_review_match = None

    if administrative_review_match:
        score += 18
        _add_finding(
            findings,
            finding_details,
            "Account Pressure",
            "Medium",
            "Describes an account, billing, or identity-related change and pushes the recipient to review a pending update.",
            matched_text=administrative_review_match,
        )

        if _first_matching_phrase(lowered, UNRECOGNIZED_SOURCE_PHRASES):
            score += 6
            _add_finding(
                findings,
                finding_details,
                "Administrative Change",
                "Low",
                "Frames the change as coming from an unfamiliar source, location, or timing context.",
                matched_text=_first_matching_phrase(lowered, UNRECOGNIZED_SOURCE_PHRASES),
            )

        denial_phrase = _first_matching_phrase(lowered, USER_DENIAL_PHRASES)
        if denial_phrase:
            score += 5
            _add_finding(
                findings,
                finding_details,
                "Verification Prompt",
                "Low",
                "Tells the recipient to challenge the change if they did not initiate it, a common review-pressure pattern.",
                matched_text=denial_phrase,
            )

    if (
        any(role in lowered for role in BUSINESS_PAYMENT_ROLE_TERMS)
        and any(
            payment_term in lowered
            for payment_term in ("gift card", "wire transfer", "invoice", "payment", "bank account")
        )
    ):
        matched_role = _first_matching_phrase(
            lowered,
            BUSINESS_PAYMENT_ROLE_TERMS,
        )
        score += 16
        _add_finding(
            findings,
            finding_details,
            "Business Email Compromise",
            "High",
            "Combines executive or finance language with payment requests, a pattern often seen in BEC scams.",
            matched_text=matched_role,
        )

    return score


def _score_high_risk_combinations(
    findings: list[str],
    finding_details: list[ScanFinding],
    score: int,
) -> int:
    categories = {finding.category for finding in finding_details}
    benign_sign_in_context = (
        "Credential Harvesting" in categories
        and "Credential Request" not in categories
        and _has_finding_match(finding_details, "Credential Harvesting", "sign in")
        and not any(
            category in categories
            for category in ("Impersonation", "Secrecy Pressure", "Urgency")
        )
    )

    if {"Credential Harvesting", "Credential Request"}.issubset(categories) and not benign_sign_in_context:
        score += 15
        _add_finding(
            findings,
            finding_details,
            "Attack Chain",
            "High",
            "Combines credential-themed language with a sign-in or reset lure, increasing phishing risk.",
            matched_text="Credential Harvesting + Credential Request",
        )

    if {"Payment Scam", "Business Email Compromise"}.issubset(categories):
        score += 20
        _add_finding(
            findings,
            finding_details,
            "Attack Chain",
            "High",
            "Combines executive-style payment pressure with banking changes, which is a strong fraud pattern.",
            matched_text="Payment Scam + Business Email Compromise",
        )

    if (
        {"Impersonation", "Credential Request"}.issubset(categories)
        and "Secrecy Pressure" in categories
    ):
        score += 14
        _add_finding(
            findings,
            finding_details,
            "Attack Chain",
            "High",
            "Combines impersonation, secrecy, and credential requests in a classic social engineering pattern.",
            matched_text="Impersonation + Secrecy Pressure + Credential Request",
        )

    if (
        {"Impersonation", "Payment Scam"}.issubset(categories)
        and "Secrecy Pressure" in categories
    ):
        score += 16
        _add_finding(
            findings,
            finding_details,
            "Attack Chain",
            "High",
            "Combines impersonation, secrecy, and payment pressure in a classic scam pattern.",
            matched_text="Impersonation + Secrecy Pressure + Payment Scam",
        )

    return score


def _add_finding(
    findings: list[str],
    finding_details: list[ScanFinding],
    category: str,
    severity: str,
    message: str,
    matched_text: str | None = None,
) -> None:
    findings.append(message)
    finding_details.append(
        ScanFinding(
            category=category,
            severity=severity,
            message=message,
            matched_text=matched_text,
        )
    )


def _risk_level_from_score(score: int) -> str:
    if score >= 65:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def _confidence_from_findings(score: int, findings: list[str]) -> int:
    if not findings:
        return 82

    confidence = 58 + (len(findings) * 8) + (score // 10)
    return min(confidence, 98)


def _build_recommendation(risk_level: str, categories: list[str]) -> str:
    if "Employment Scam" in categories:
        if risk_level == "High":
            return "Do not reply or move the conversation to text. Verify the job through the company's official careers site or a trusted contact."
        return "Verify the job through the company's official careers site before sharing contact, identity, or payment information."

    if "Payment Scam" in categories or "Business Email Compromise" in categories:
        if risk_level == "High":
            return "Do not send money, change banking details, or continue the conversation until the request is independently verified."
        return "Verify any payment or banking request through a trusted channel before taking action."

    if "Credential Harvesting" in categories or "Credential Request" in categories:
        if risk_level == "High":
            return "Do not enter credentials, share codes, or follow the requested sign-in flow until the sender and destination are independently verified."
        return "Verify the sender and destination before sharing any credentials, codes, or account details."

    if any(
        category in categories
        for category in ("URL Structure", "URL Obfuscation", "Domain Reputation")
    ):
        if risk_level == "High":
            return "Do not open the link until the destination has been independently verified."
        return "Inspect the destination carefully before opening the link or trusting the site."

    if risk_level == "High":
        return "Do not click links, enter credentials, or reply until the sender and destination are independently verified."
    if risk_level == "Medium":
        return "Review the sender, destination, and requested action carefully before trusting this content."
    if categories:
        return "Limited caution signals were detected. Verify unexpected requests through the official app, website, or a trusted contact before taking action."
    return "No immediate red flags were found, but verify unexpected requests before taking action."


def _detected_categories(finding_details: list[ScanFinding]) -> list[str]:
    return sorted({finding.category for finding in finding_details})


def _looks_like_ip_address(hostname: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname))


def _subdomain_count(hostname: str) -> int:
    parts = [part for part in hostname.split(".") if part]
    return max(len(parts) - 2, 0)


def _special_character_count(value: str) -> int:
    return sum(1 for character in value if character in "-_@?=&%")


def _extract_contextual_credential_match(lowered: str) -> str | None:
    patterns = (
        r"(verify(?:\W+\w+){0,4}\W+(?:account|identity|password|credentials|credential|login|security|bank|mailbox|otp|code))",
        r"(confirm(?:\W+\w+){0,4}\W+(?:account|identity|password|credentials|credential|login|security|bank|mailbox|otp|code))",
        r"((?:account|identity|password|credentials|credential|login|security|bank|mailbox|otp|code)(?:\W+\w+){0,4}\W+(?:verify|confirm))",
    )

    for pattern in patterns:
        match = re.search(pattern, lowered)
        if match:
            return match.group(1)

    return None


def _extract_suspicious_account_pressure_match(lowered: str) -> str | None:
    account_context_term = _first_matching_phrase(lowered, ACCOUNT_CONTEXT_TERMS)
    action_term = _first_matching_phrase(lowered, ACCOUNT_ACTION_TERMS)
    activity_phrase = _first_matching_phrase(lowered, SUSPICIOUS_ACTIVITY_PHRASES)
    consequence_phrase = _first_matching_phrase(lowered, CONSEQUENCE_PRESSURE_PHRASES)

    if not account_context_term or not action_term:
        return None

    if not activity_phrase and not consequence_phrase:
        return None

    matched_parts = [part for part in (activity_phrase, consequence_phrase, action_term) if part]
    return " | ".join(matched_parts)


def _extract_administrative_review_match(lowered: str) -> str | None:
    context_term = _first_matching_phrase(lowered, ADMINISTRATIVE_CONTEXT_TERMS)
    change_phrase = _first_matching_phrase(lowered, ADMINISTRATIVE_CHANGE_PHRASES)
    action_term = _first_matching_phrase(lowered, ACCOUNT_ACTION_TERMS)
    consequence_phrase = _first_matching_phrase(lowered, CONSEQUENCE_PRESSURE_PHRASES)

    if not context_term or not change_phrase:
        return None

    if not action_term and not consequence_phrase:
        return None

    matched_parts = [
        part for part in (context_term, change_phrase, consequence_phrase, action_term) if part
    ]
    return " | ".join(matched_parts)


class _EmploymentScamMatch:
    def __init__(self, text: str, signal_count: int) -> None:
        self.text = text
        self.signal_count = signal_count


def _extract_employment_scam_match(lowered: str) -> _EmploymentScamMatch | None:
    recruiter_claim = _first_matching_phrase(lowered, RECRUITMENT_CLAIM_PHRASES)
    remote_work = _first_matching_phrase(lowered, REMOTE_WORK_PHRASES)
    high_daily_pay = re.search(
        r"\$(?:[2-9]\d{2}|[1-9]\d{3,})\s*(?:-|to)\s*\$?(?:[2-9]\d{2}|[1-9]\d{3,})\s*(?:daily|a day|per day)|\$(?:[2-9]\d{2}|[1-9]\d{3,})\s*(?:daily|a day|per day)",
        lowered,
    )
    text_handoff = re.search(
        r"\btext\s+(?:me\s+)?(?:at\s+)?\+?\d[\d\s().-]{8,}\d\b",
        lowered,
    )

    matched_parts = [
        part
        for part in (
            recruiter_claim,
            remote_work,
            high_daily_pay.group(0) if high_daily_pay else None,
            text_handoff.group(0) if text_handoff else None,
        )
        if part
    ]
    if len(matched_parts) < 3:
        return None

    return _EmploymentScamMatch(" | ".join(matched_parts), len(matched_parts))


def _requests_auth_code(lowered: str) -> bool:
    return any(action in lowered for action in AUTH_CODE_REQUEST_ACTIONS) and any(
        code_term in lowered for code_term in AUTH_CODE_TERMS
    )


def _has_availability_excuse(lowered: str) -> bool:
    return any(phrase in lowered for phrase in AVAILABILITY_EXCUSE_PHRASES)


def _has_category(finding_details: list[ScanFinding], category: str) -> bool:
    return any(finding.category == category for finding in finding_details)


def _has_suspicious_path_terms(path: str) -> bool:
    lowered_path = path.lower()
    return any(term in lowered_path for term in SENSITIVE_PATH_TERMS)


def _matching_suspicious_path_term(path: str) -> str | None:
    lowered_path = path.lower()
    return next((term for term in SENSITIVE_PATH_TERMS if term in lowered_path), None)


def _first_matching_phrase(lowered: str, phrases: tuple[str, ...]) -> str | None:
    return next((phrase for phrase in phrases if phrase in lowered), None)


def _has_link_lure(lowered: str) -> bool:
    return any(token in lowered for token in ("link", "portal", "http://", "https://", "here"))


def _has_benign_sign_in_context(lowered: str) -> bool:
    if not any(term in lowered for term in BENIGN_SIGN_IN_CONTEXT_TERMS):
        return False

    malicious_anchors = (
        "password",
        "otp",
        "one-time password",
        "verification code",
        "security code",
        "bank",
        "security alert",
        "account is locked",
        "suspended",
        "keep this between us",
        "urgent",
        "immediately",
    )
    return not any(anchor in lowered for anchor in malicious_anchors)


def _has_finding_match(
    finding_details: list[ScanFinding],
    category: str,
    matched_text: str,
) -> bool:
    return any(
        finding.category == category and finding.matched_text == matched_text
        for finding in finding_details
    )


def _build_summary(risk_level: str, categories: list[str], findings: list[str]) -> str:
    if not findings:
        return "Low-risk result with no obvious phishing indicators from the starter rules."

    if "Payment Scam" in categories or "Business Email Compromise" in categories:
        if risk_level == "High":
            return "High-risk result with strong payment fraud or business email compromise indicators."
        if risk_level == "Medium":
            return "Medium-risk result with some payment fraud or business email compromise signals."

    if "Credential Harvesting" in categories or "Credential Request" in categories:
        if risk_level == "High":
            return "High-risk result with strong credential theft or account takeover indicators."
        if risk_level == "Medium":
            return "Medium-risk result with possible credential theft or account verification pressure."

    if "Account Pressure" in categories:
        if risk_level == "High":
            return "High-risk result with strong account-activity pressure and suspicious follow-up instructions."
        if risk_level == "Medium":
            return "Medium-risk result with account-activity pressure that may be trying to drive an unsafe response."

    if "Employment Scam" in categories:
        if risk_level == "High":
            return "High-risk result with a fake-job or recruiter-scam pattern."
        if risk_level == "Medium":
            return "Medium-risk result with several signals commonly seen in fake-job scams."

    if any(
        category in categories
        for category in ("URL Structure", "URL Obfuscation", "Domain Reputation")
    ):
        if risk_level == "High":
            return "High-risk result with multiple suspicious link or destination indicators."
        if risk_level == "Medium":
            return "Medium-risk result with several suspicious link or destination signals."

    if "Impersonation" in categories or "Secrecy Pressure" in categories:
        if risk_level == "High":
            return "High-risk result with strong impersonation or secrecy-based social engineering indicators."
        if risk_level == "Medium":
            return "Medium-risk result with impersonation or secrecy-based social engineering signals."

    if risk_level == "High":
        return "High-risk result triggered by multiple phishing or social engineering indicators."
    if risk_level == "Medium":
        return "Moderate-risk result with several suspicious signals worth reviewing carefully."
    return "Low-risk result with only limited suspicious signals from the starter rules."
