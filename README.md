# Sentinel

Sentinel V1 is a full-stack, **rules-based** phishing and social-engineering triage application. Paste a suspicious URL, email or message to see explainable indicators, a heuristic risk score and a recommended next step.

Sentinel supports independent verification; it cannot guarantee that content or a destination is safe. It does not open submitted links, query reputation services or execute attachments.

## Features

- URL, email and message analysis using transparent rules.
- Findings for credential requests, impersonation, urgency, payment rerouting and other social-engineering patterns.
- Registration, secure account sessions, logout and account-owned history.
- Server-issued anonymous sessions with owner isolation and CSRF protection.
- History filters, bounded analytics, feedback and report deletion.
- Temporary 7/14/30-day retention or explicitly saved reports.
- A safety guide with practical verification habits.

## Screenshots

![Sentinel landing page](docs/screenshots/01-landing-page.png)
![Rules-based analysis](docs/screenshots/02-analyze-high-risk.png)
![Report and retention controls](docs/screenshots/03-scan-report.png)
![Synthetic history dashboard](docs/screenshots/04-dashboard.png)
![Safety guide](docs/screenshots/05-safety-guide.png)

Screenshots use synthetic demonstration content.

## Architecture

Next.js / React / TypeScript → FastAPI → original rule engine → SQLAlchemy storage. SQLite keeps local setup self-contained. PostgreSQL is configurable; protected Redis state is required for production operation. See [architecture](docs/architecture.md) and the [API contract](docs/api-contract.md).

## Local setup

Validated target runtimes: **Python 3.13.18** and **Node 22.23.4**. Newer security patches in the same supported series should be revalidated. The selected versions are recorded in `.python-version` and `.nvmrc`.

1. Obtain this repository's source and enter its root directory.
2. Install the listed runtimes and make `python3.13`, `node` and `npm` available.
3. Run:

```sh
bash scripts/setup.sh
bash scripts/dev.sh
```

Open http://localhost:3000. The backend runs on http://127.0.0.1:8000. Browser API calls follow the browser hostname; use **localhost for both**, or **127.0.0.1 for both**, rather than mixing them. Press Ctrl+C to stop both processes.

Local setup needs no environment file or PostgreSQL server. A fresh ignored SQLite database is created in the backend directory. Optional sanitized examples are provided in the backend/frontend directories; never commit actual environment values. If using a different Python executable, pass `PYTHON_BIN=/path/to/python3.13` to setup.

## Validation

```sh
# Backend, from backend/
.venv/bin/python -m pytest app/tests -q -p no:cacheprovider
.venv/bin/python -m ruff check app migrations --select E9,F63,F7,F82
.venv/bin/python -m pip check
.venv/bin/python -m pip_audit -r requirements.lock --no-deps --disable-pip

# Frontend, from frontend/
npm run lint
npm test
npm run typecheck
npm run build
npm audit --audit-level=moderate
```

Tests use synthetic data and disposable databases. Frontend transport tests mock requests; browser journeys need separate validation. The CI workflow also checks the complete reachable Git history and the approved source boundary. Local checks do not establish hosted CI, production failover or load assurance.

## Security and limitations

- Risk scores and confidence percentages are **heuristics**, not calibrated probabilities. No detection accuracy or guarantee is claimed.
- Browser credentials use HttpOnly cookies; mutations require Origin/CSRF checks. Logout revokes account sessions. Memory-backed local sessions reset when the service restarts.
- Submitted text, findings and feedback are stored. Avoid live passwords and sensitive personal data. Expiry hides temporary reports; physical deletion depends on cleanup operations and a separate backup policy.
- Anonymous credentials default to seven days, independently of record retention. Closing a browser is not a deletion guarantee.
- Feedback records your review; it does not automatically change scoring or retention.
- The combined runner is local development only. Hosted operation needs explicit production settings, fresh secrets, exact HTTPS origins, same-site secure cookies, protected Redis, reviewed migrations, TLS and operational validation. See [security policy](SECURITY.md).

## Development and attribution

Created and maintained by **DarienRam** as an individual project covering the product interface, rule-based analysis, API, persistence and security maintenance. Third-party packages retain their own licenses. See [attribution](docs/attribution.md).

The landing-page chart cites the [FTC Consumer Sentinel Network Data Book 2024](https://www.ftc.gov/reports/consumer-sentinel-network-data-book-2024). Its totals cover consumer reports across fraud, identity theft and related concerns, not every scam attempt.

## Future development

Future research may explore ML-assisted phishing detection, account recovery and accessibility improvements. These are not part of V1; no ML-assisted detection capability or validated performance is claimed.

## Licensing

Rights are reserved for now. No open-source license grant has been selected. Licensing remains an owner decision before a public release; do not infer redistribution permission from this portfolio preparation.
