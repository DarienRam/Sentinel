# Sentinel V1 architecture

## Request flow

The Next.js frontend calls FastAPI over a configured API origin. Resource middleware applies size/time/admission limits. Account or anonymous credentials establish an owner. Pydantic validates the input; the scan route calls `app.services.scan_engine.analyze_scan` directly. SQLAlchemy stores and returns the resulting rule-based report. Feedback records do not automatically alter detection behavior.

## Components

- Frontend routes: landing, analysis, dashboard, report, registration, login and safety guide.
- Auth/session modules: HttpOnly browser cookies, server-side revocation, CSRF and exact Origin checks; bearer API clients remain supported.
- Original rule engine: deterministic keyword/context and URL-structure evidence, 0-100 heuristic score, fixed Low/Medium/High boundaries and recommendations.
- Persistence: users, scans, findings, categories and feedback; owner and expiry filters apply to access.
- Security state: bounded in-memory storage for local/test use; protected Redis required for production.

Rule confidence is calculated from rule findings and score; it is not a statistically calibrated probability. A low score does not verify safety.

## Database initialization and migrations

An empty local development database can initialize the current schema. Startup refuses an incompatible existing schema rather than silently altering it. Production requires Alembic revision `0002`. Run migrations only against an explicit, approved target using `MIGRATION_DATABASE_URL` and `python -m alembic -c alembic.ini upgrade head` from the backend directory. Never blindly stamp an existing database. The initial baseline refuses destructive downgrade; index rollback also requires an operator decision.

This release starts with a fresh database. It does not include or migrate any previous private development records.

## Sessions and ownership

Cookies are HttpOnly and SameSite=Strict; production uses Secure host-only cookies. Cookie mutations require exact Origin and CSRF tokens. Account sessions expire after 60 minutes by default; logout revokes a session and password changes invalidate old sessions. Anonymous credentials last seven days by default and are shared by tabs in a browser profile. Expiry, revocation or loss of local memory state ends access; new credentials cannot adopt prior ownership. Use same-site frontend/API hosts.

## Retention

Temporary scans support 7, 14 or 30 days. Anonymous credential lifetime is independent of retention. Expired records are hidden immediately by owner queries; physical cleanup deletes bounded batches. The maintenance entry point `python -m app.retention` requires `RETENTION_DATABASE_URL`; it is a dry run unless both `--apply` and `--confirm-retention-policy` are supplied. Scheduling/target selection is an explicit operational decision. Backups require their own retention policy.

## Deployment boundary

The combined runner is local development only. Hosted operation requires TLS, production configuration, exact origins, protected/persistent Redis, migrated PostgreSQL or another reviewed database target, trusted-proxy design and independent operational checks. `/health` is liveness only, not a database or Redis readiness probe. Production load and failover assurance must not be inferred from SQLite tests.
