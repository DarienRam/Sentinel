# Security policy

Sentinel V1 is a rules-based decision-support project, not a guarantee that a message or destination is safe. It parses supplied content; it does not visit links, verify reputations or execute attachments. Rule confidence is a heuristic, not a calibrated probability.

## Reporting

Do not publish passwords, tokens, personal messages or database contents in issues. Contact the repository owner through an available private GitHub reporting channel. If private vulnerability reporting is enabled, use the Security tab. A public issue can request a private contact route without including sensitive details. Reporting-channel availability must be verified before a public release.

## Local development

Development defaults are for local use only. Memory-backed session state resets on restart. Actual environment files, databases and generated output must remain untracked. Use synthetic examples; do not submit live credentials or sensitive personal information.

## Hosted operation

Do not expose development servers publicly. Production requires an explicit production environment, a newly generated signing key, exact HTTPS frontend origins, same-site secure cookies, protected Redis state and an explicitly migrated database. No memory fallback is allowed in production. Configure TLS, trusted proxy boundaries, backups, monitoring and database/Redis access controls separately.

## Data lifecycle

Scans store submitted text, findings and optional feedback. Temporary records become inaccessible after expiry. Physical removal depends on bounded cleanup calls or an explicitly scheduled retention job; backups have a separate lifecycle. Saved scans remain until deleted. Anonymous credentials expire independently of record retention; closing the browser does not necessarily remove its cookie or stored scans. Logout/revocation does not delete stored reports.

Account logout revokes its server session. A password change invalidates older account sessions. Legacy arbitrary anonymous identifiers are not accepted, and new sessions do not adopt other owners' history.

## Scope of assurance

Unit tests, dependency checks and local browser checks are not a penetration test or a production load/failover assessment. Live production deployment is a separate validation gate.

## Dependency maintenance

The development-only TypeScript parser has a scoped minimatch 11.0.1 override for GHSA-g3hv-75wg-m249. The fix is restricted to that parser dependency; the application uses no glob input from users. Lint/type/build checks must pass when updating or removing the override.
