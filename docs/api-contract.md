# Sentinel API Contract

This guide summarizes the current FastAPI routes and Pydantic schemas. Request examples are synthetic; illustrative values are not detection benchmarks. Source contracts live in `backend/app/api/{auth,scans}.py` and `backend/app/schemas/{auth,scan}.py`.

## Identity and common errors

Browser accounts use an HttpOnly session cookie; API clients can use `Authorization: Bearer <access_token>`. Both require an unexpired server-side session. Anonymous requests use a server-issued, host-only HttpOnly cookie and server-side session state; arbitrary `X-Anonymous-Session` identifiers are no longer accepted. Account ownership takes precedence when a valid bearer token is supplied. An invalid supplied token returns 401 rather than silently switching to anonymous access. No guest-to-account or legacy-header history migration is performed.

### Anonymous session lifecycle

| Method / path | Behavior |
|---|---|
| `POST /auth/anonymous-session` | Requires an exact allowed `Origin`. Creates a fresh 256-bit random capability if the cookie is absent/invalid/expired, or restores the existing session. Returns only `csrf_token` and `expires_at`; the capability is only in Set-Cookie. |
| `POST /auth/anonymous-session/rotate` | Requires the current cookie, allowed Origin and `X-CSRF-Token`. Atomically invalidates the old credential, preserves its owner and absolute expiry, and returns a new CSRF token/cookie. |
| `DELETE /auth/anonymous-session` | Requires cookie, Origin and CSRF; revokes the server credential and clears the cookie. Returns 204. Does not delete scan records. |

Cookies use `Path=/`, `SameSite=Strict`, no Domain, and HttpOnly. Production uses the Secure `__Host-sentinel_anon` cookie; local development uses `sentinel_anon` over HTTP. Session lifetime is seven days by default (`ANONYMOUS_SESSION_SECONDS`, 60 seconds–30 days). Rotation does not extend it. Cookies are shared by tabs in the same browser profile; refresh restores the session by cookie, without exposing the credential to frontend JavaScript. Expiry, revocation or loss of server state requires a new anonymous identity; existing records are not adopted by that identity, even if their retention period is longer. Legacy history stays untouched but inaccessible through the replacement mechanism, as explicitly approved.

Anonymous POST/PATCH/DELETE scan operations require the exact allowed Origin and matching `X-CSRF-Token`. Unknown/expired/revoked cookies return 401; missing/incorrect CSRF or Origin returns 403. GET history without a cookie has an empty scope; creating a scan without a session returns 400. Bearer-authorized account operations use account ownership and do not adopt cookie ownership. Session responses use `Cache-Control: no-store`. A capability remains a bearer credential if stolen; HttpOnly, TLS, CSRF checks, expiry and revocation reduce risk but do not bind it cryptographically to a physical browser.

History and analytics are owner-scoped; without either identity they have an empty scope. Detail/mutation access to missing, expired or another owner's scan returns 404. New anonymous scans without an established session cookie return 400. Anonymous permanent save returns 403. Pydantic/query validation and unsupported temporary retention windows return 422. Validation-error entries expose `type`, `loc` and `msg`, omitting raw submitted values/context. Password-byte and URL validation errors are controlled and do not echo submitted content.

## Health and authentication

| Method / path | Request | Response |
|---|---|---|
| `GET /` | None | `{"message":"Sentinel backend is running."}` |
| `GET /health` | None | `{"status":"ok"}`; liveness only, no database readiness probe. |
| `POST /auth/register` | JSON `username`, `email`, `password` | 201 `UserPublic`; duplicate username/email pre-check or database uniqueness conflict returns controlled 409. |
| `POST /auth/login` | JSON **`login`**, `password`; login accepts username or email | 200 `AuthToken`; incorrect credentials return 401. This is JSON, not an OAuth form request. |
| `GET /auth/me` | Valid bearer or account cookie | 200 `UserPublic`; invalid/missing credentials return 401. |

`UserPublic` contains `id`, `username`, `email`, `created_at`; it excludes password hashes. `AuthToken` contains `access_token`, `token_type` (default `bearer`), and the full `user: UserPublic` object.

Registration username constraints: 3–50 characters, letters/digits/underscore/hyphen; username and email normalize to lowercase/trimmed values. New-account email has 5–255 characters and standards-based EmailStr validation without DNS/deliverability lookups. Existing account identifiers/password hashes are not rewritten. Login has 3–255 characters. Passwords must contain 8–128 characters **and at most 72 UTF-8 bytes** for both registration and login. Overlong/invalid-Unicode passwords return 422 without truncation. Existing raw bcrypt hashes remain in use; there is no rehash or database migration.

```json
{
  "login": "analyst@example.com",
  "password": "example-password"
}
```

### Revocable account sessions

| Method / path | Behavior |
|---|---|
| `POST /auth/login?transport=cookie` | Same JSON login payload; exact allowed Origin required. Sets HttpOnly account cookie and returns `{token_type:"cookie",user,csrf_token,expires_at}` without an access token in JSON. Default `transport=bearer` preserves the API token response shape. |
| `GET /auth/session` | Requires valid account session and allowed Origin; returns the cookie-session response for browser restoration without disclosing the JWT. |
| `POST /auth/logout` | Requires current account authentication (and Origin/CSRF for cookie authentication). Revokes that session and clears the account cookie; 204. Other sessions remain active. |
| `POST /auth/password` | Requires authentication, current-password verification and `{current_password,new_password}`. Same password-byte policy applies. Updates only the account hash, invalidates all earlier account sessions and clears the cookie; 204. Wrong password 401; concurrent credential update 409. No password-change UI is added. |

Account cookies use `sentinel_account` locally and Secure `__Host-sentinel_account` in production, with HttpOnly, SameSite=Strict, Path=/ and no Domain. Account POST/PATCH/DELETE operations require the account session's CSRF token and exact allowed Origin; anonymous CSRF tokens cannot authorize them. Explicit invalid/malformed Authorization headers take precedence and return 401 without falling back to cookies or guests. Expired/invalid account cookies return 401 and are cleared so the browser can recover; the failed operation is not replayed as a guest operation.

JWTs require valid signatures, fixed issuer/audience, integer `iat`/`nbf`/`exp`, a valid user subject, a random `jti` and matching server state. Lifetime defaults to 60 minutes (`ACCESS_TOKEN_EXPIRE_MINUTES`, 1–1,440). Logout revocation is checked on subsequent requests; already-authorized in-flight work can complete. No automatic refresh/sliding renewal is implemented: reauthenticate after expiry. A keyed password-hash fingerprint invalidates all old sessions after a successful credential change without altering scan ownership. Redis loss/restarts invalidate sessions if state is lost. Old stateless JWTs are rejected under the approved one-time re-login policy; passwords and stored accounts/scans are preserved.

Browser JWTs are no longer stored/read in localStorage. Old values, if any, are unused and remain until a separately authorized cleanup. Browser restoration distinguishes authentication failure from service/network failure; a failed logout shows an error and does not claim server revocation. API auth/scan responses use `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Database failures return a redacted 503; feedback uniqueness races return controlled 409. Raw submitted content is returned only within owner-authorized JSON reports; React renders it as text, never submitted HTML.

## Scan creation and result shape

`POST /scans` returns 200 `ScanResult` after synchronous rule analysis and persistence.

```json
{
  "input_type": "url",
  "raw_content": "https://example.com/login",
  "save_scan": false,
  "retention_days": 7
}
```

`input_type` is `url`, `email`, or `message`. Content length is 4–5,000 characters. `save_scan` defaults to false; omitted/null retention defaults to 7 days. The integer schema range is 1–365, but **routes only accept 7, 14 or 30**. On creation the retention value is checked even when `save_scan` is true. Permanent saving requires an authenticated user and sets `expires_at` to null; temporary expiration is calculated from the analysis creation time.

URL scans accept HTTP(S), scheme-relative URLs, or bare hosts (including optional ports/paths), with ASCII/IDNA domains, IPv4 or bracketed IPv6. Malformed hosts/brackets/ports, unsupported schemes, raw control/space characters inside the URL, backslashes, invalid percent escapes/UTF-8, encoded controls and percent-encoded hosts return 422 before persistence. Surrounding ordinary spaces are allowed. Valid percent-encoded spaces in paths/queries remain supported. This is structural validation, not a safety verdict or DNS lookup; email/message scans may still contain malformed URL text. The scoring implementation is unchanged; bare hosts retain the existing engine's limited host analysis rather than being silently rewritten into explicit URLs.

| `ScanResult` fields | Meaning |
|---|---|
| `id`, `input_type`, `raw_content`, `created_at` | Scan identity, original input and timestamp. History also returns raw content. |
| `risk_score`, `confidence_score`, `risk_level` | Integer scores 0–100; risk level `Low`, `Medium`, `High`. Confidence is heuristic, not calibrated probability. |
| `summary`, `recommendation`, `detected_categories` | Explanation, recommended action and category strings. |
| `findings` | List of finding message strings; a no-obvious-indicators fallback message appears when there are no structured findings. |
| `finding_details` | Objects with `category`, `severity` (`Low`/`Medium`/`High`), `message`, nullable `matched_text`. |
| `feedback`, `feedback_note` | Nullable label/note; label is `Correct`, `False Positive`, or `False Negative`. |
| `is_saved`, `expires_at` | Permanent flag and nullable expiration timestamp. |

The rule engine does not fetch submitted URLs, train models, query live reputation feeds, or certify that low-risk content is safe.

## History and analytics

`GET /scans` returns a list of full `ScanResult` objects, newest first by `created_at`, then `id`. `GET /scans/analytics/summary` returns `ScanAnalyticsSummary`. Both accept:

| Query parameter | Accepted values / behavior |
|---|---|
| `limit` | Optional integer 1–100; omitted requests now default to 100 (configurable downward with `HISTORY_DEFAULT_LIMIT`). |
| `days` | Optional integer 1–3,650, selecting recent creation times. |
| `risk_level` | Optional `Low`, `Medium`, `High`. |
| `feedback_status` | Optional `pending` (no feedback) or `reviewed` (any feedback exists). This is not independent analyst adjudication. |

Summary fields are `total_scans`, `high_risk_count`, `medium_risk_count`, `low_risk_count`, `feedback_count`, `needs_review_count`, `high_risk_needing_feedback_count`, `average_risk_score`, `average_confidence_score`, `latest_high_risk_created_at`, `input_type_counts`, `feedback_breakdown`, `common_categories`, and `comparison`.

Count entries are `{input_type,count}`, `{label,count}`, and `{name,count}` respectively; common categories include at most six. Averages are rounded integers (zero for an empty result); latest high-risk time is nullable. With `days`, `comparison` contains previous-period total/high-risk/average-risk values and their current-minus-previous changes; otherwise it is null. An optional limit caps each selected comparison period. Metrics describe the filtered/latest-N scope and must not be read as uncapped lifetime totals when a limit is supplied.

## Scan detail, feedback, storage and deletion

| Method / path | Request / behavior | Response |
|---|---|---|
| `GET /scans/{scan_id}` | Owner identity | 200 `ScanResult` |
| `POST /scans/{scan_id}/feedback` | JSON `feedback` and optional/null `feedback_note` (maximum 1,000 characters) | 200 updated `ScanResult`; creates or overwrites the one feedback record. **Does not change retention.** |
| `PATCH /scans/{scan_id}/storage` | Required boolean `save_scan`, optional/null `retention_days` | 200 updated `ScanResult`. True requires account auth and removes expiration; false sets a 7/14/30-day window from now (default 7). |
| `DELETE /scans/{scan_id}` | Owner identity | 204, empty body; deletes scan and related ORM children. |

```json
{
  "feedback": "False Positive",
  "feedback_note": "Synthetic review note."
}
```

```json
{
  "save_scan": false,
  "retention_days": 14
}
```

Scan routes perform request-driven expired-scan housekeeping in batches of at most 100 rows. Owner queries exclude expired rows even if housekeeping leaves a backlog; feedback does not override expiration. No automatic guest-to-account transfer or immutable feedback decision history is implemented. See [architecture](architecture.md) and the unchanged audit for remaining storage/privacy/security limitations.

## Resource limits

Fixed-window defaults count admitted attempts, including failed operations. Each multi-counter admission check is atomic; peer checks precede owner/login checks, so a later rejection can still consume peer allowance. Windows reset after their first request's window expires. Exhaustion returns 429 with `Retry-After`, `Cache-Control: no-store`, and `{"detail":"Request quota exceeded.","retry_after":seconds}`. Missing/unavailable required security state returns 503 with Retry-After 5, without an in-memory production fallback.

| Scope | Default |
|---|---|
| Registration / peer IP | 10/hour |
| Login / peer IP; normalized login identity | 20/minute; 10/minute |
| Session bootstrap, rotation and revocation / peer IP | 30/hour combined |
| Scan / peer IP | 60/minute and 500/day |
| Feedback / peer IP; other scan mutations / peer IP | 30/minute each group |
| Reads (history, analytics, details, profile) / peer IP | 120/minute combined |
| Verified owner / reads; scan or mutation group | 60/minute; 20/minute per group |
| Verified owner / scan submissions | 30/day anonymous; 100/day account |
| Site-wide scan submissions | 2,000/day |

Rotation retains the same owner quotas. New sessions/accounts do not bypass IP/site ceilings. The application uses the ASGI peer, not forwarded-IP header values. The server/proxy must supply a trustworthy peer: the development runner disables Uvicorn proxy-header processing. Production proxies must strip spoofed forwarding headers and use an explicitly trusted topology; simply trusting all proxies undermines IP controls. These are request quotas, not a permanent database-size quota or complete DDoS defense.

Request bodies are bounded to 65,536 actual bytes by default, including streamed bodies regardless of declared size, with a five-second receive budget and 64-level JSON nesting limit. Oversize/deep bodies return 413; slow bodies 408; invalid Content-Length 400; request targets over 4,096 bytes 414; headers over 16,384 bytes 431. Existing field-level limits remain. Expensive requests share eight admission slots by default. Redis slots use expiring 60-second leases for crashed-worker recovery; they are not a hard CPU/SQL execution timeout. Normal work is also bounded by input length, password-byte limits, result limits and quotas.

Local/test state is bounded in-memory and single-process; restarting it invalidates guest credentials and resets counters. Production requires the optional Redis adapter, exact HTTPS frontend origins and shared configuration. Redis Lua admits multi-counter requests, concurrency leases and credential rotation atomically. Distributed enforcement still needs live Redis/failover/load verification; no production capacity claim is established by unit tests.
