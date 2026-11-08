# Sentinel frontend

The Next.js interface provides URL/email/message analysis, authentication, scan reports, retention controls, dashboards and a safety guide. See the [project README](../README.md) for setup and security limitations.

The API defaults to port 8000 on the browser's hostname. Keep the frontend and API on the same hostname locally. `NEXT_PUBLIC_API_BASE_URL` is an optional public address override, not a place for credentials.

Use `npm run lint`, `npm test`, `npm run typecheck` and `npm run build` to validate the interface. Browser journeys must also be checked; mocked transport tests do not establish end-to-end behavior.
