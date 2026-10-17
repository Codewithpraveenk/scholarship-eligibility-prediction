# ScholarPath

A complete account-based scholarship screening application with a FastAPI backend, responsive web interface, PostgreSQL production storage (SQLite locally), administrator policy management, saved assessments, JSON exports, and a policy audit trail.

## What eligibility means

This application evaluates **explicit rules**, not a trained machine learning model or selection probability. No real training dataset or verified scholarship policy was supplied. Three illustrative policies are seeded **unpublished**. The administrator must replace them or add real policies and verify the marks, household income, study level, deadline and official HTTPS source before publishing. Some real scholarships require additional conditions; do not publish policies that this rule schema cannot fully represent. Source URLs are administrator attestations, not automatically verified documents. Students must confirm details and apply with the provider. No application is submitted by this app.

## Run locally (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:ADMIN_EMAIL = 'your-email@example.com'
$env:ADMIN_PASSWORD = 'a-unique-password-of-at-least-12-characters'
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Sign in with the configured administrator account. Open **Manage policies**, replace the example criteria with verified rules, supply an official source and enable publication. Create a separate student account to assess eligibility. Students see only published policies; historical results preserve the exact policy version used. Dates in assessment history are UTC. Deadline dates are inclusive, evaluated against the server's date.

Environment variables are read from the process environment, not automatically from `.env`. The initial administrator is created only when its email does not exist. Changing `ADMIN_PASSWORD` later does not reset an existing account. Keep the bootstrap email private and configure it before accepting traffic. Account recovery and email verification are not implemented; use controlled account onboarding until an identity provider is integrated.

## Verify

```powershell
python -m unittest discover -s tests -v
```

The suite starts an isolated real HTTP server and database. It checks registration/login/logout, CSRF and origin protection, validation, administrator authorization, eligibility boundaries, result ownership, source requirements, versioned snapshots, deletion, rate limiting, assets and health checks.

## Production deployment

The repository includes a Docker image definition and a **Render Free Blueprint** (`render.yaml`). Use an external **Neon Free PostgreSQL** database so accounts and assessments survive Render restarts. No paid disk or paid service is configured. Create a free Neon project, copy its pooled PostgreSQL connection string into Render's secret environment settings, and create the Render Blueprint from this GitHub repository. Set:

- `APP_ORIGIN`: the exact public HTTPS origin without a trailing slash (e.g. `https://your-service.onrender.com`).
- `DATABASE_URL`: the Neon pooled PostgreSQL connection string. Treat it as a password; never commit it or paste it in chat.
- `ADMIN_EMAIL`: the initial administrator email.
- `ADMIN_PASSWORD`: a unique secret of at least 12 characters.

The blueprint sets `APP_ENV=production` (Secure cookies, HSTS, no interactive API docs). Production refuses to start without `DATABASE_URL`, preventing accidental use of ephemeral SQLite. PostgreSQL connections require TLS in production. SQLite remains available for local development; existing local data is not automatically migrated. TLS must terminate at the trusted hosting proxy; the supplied container trusts forwarded headers and should not be exposed directly without that proxy. The health endpoint is `/health`.

Free-plan limits apply: Render sleeps after inactivity and has shared monthly usage quotas, so cold starts can delay requests. Neon also scales down when idle and has storage/compute quotas. Do not enable paid upgrades or billing automatically. Free hosting does not provide an always-on production SLA. Check current limits at https://render.com/docs/free and https://neon.com/pricing.

GitHub CI runs the integration suite on both SQLite and a disposable PostgreSQL service on pushes and pull requests. `TEST_DATABASE_URL` must point only to an empty disposable test database, never the production database. Connect Render auto-deploy to the protected main branch after requiring CI to pass. A public repository URL can be used for manual deployment without granting repository access. A configuration file is not evidence of a live deployment: obtain and verify the host's deployed URL before announcing production availability.

## Operations and limits

- Passwords use salted scrypt; session tokens are stored as SHA-256 hashes and expire after 24 hours. Cookies are HttpOnly and SameSite Strict. Mutations require CSRF tokens and same-origin requests.
- Authentication attempts are limited to 10 per email/IP pair per 15 minutes in the database. Add edge-level IP throttling for public traffic and enforce request size/time limits at the reverse proxy.
- No external scripts, fonts, analytics, or frontend dependencies; a same-origin Content Security Policy is applied. SQL values are parameterized and browser-rendered text is escaped.
- Only the signed-in owner can read or delete their assessments. Published policy changes are versioned and audited. Audit records contain policy data, not student passwords.
- Back up production PostgreSQL with `pg_dump` or provider-supported backups and test restoration. For local SQLite, use its online backup API rather than copying a live database file alone. Encrypt backups and restrict access. Set retention and privacy policies before collecting real student financial data.
- There is no email delivery/recovery, document upload/verification, payment, provider application submission, or ML training pipeline. Official rules and operational monitoring must be supplied before a public student launch.

## Structure

`app/main.py` — API, authentication, eligibility engine.

`app/database.py` — PostgreSQL/SQLite connection and transaction handling.

`app/static/` — accessible responsive student/admin interface.

`tests/` — isolated HTTP integration tests.

`render.yaml`, `Dockerfile`, `.github/workflows/ci.yml` — deployment and CI.
