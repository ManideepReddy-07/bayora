# Bayora

Bayora is a controlled AI-security testing prototype. It provides a deterministic demo chatbot, a repeatable red-team suite, configurable blue-team gateway controls, evidence storage, safe source-archive analysis, and a React SOC-style dashboard.

It is intentionally designed to demonstrate authorized testing. The only executable behavior target in this prototype is the built-in synthetic demo chatbot. Registered external API targets are stored as inventory records only; the app does not conduct arbitrary network scans or exploit external systems.

## Implemented workflow

1. Open the built-in mock chatbot in **Chatbot Lab**.
2. Run a baseline suite in **Red Team** with blue defenses disabled.
3. Review evidence and generated findings in **Security Reports**.
4. Enable or inspect policies in **Blue Team**.
5. Rerun the same suite with defenses enabled and compare the stored evidence in **Test History**.
6. Export JSON or CSV reports.

The mock provider is deterministic and does not need an API key. The provider gateway also implements OpenAI, Gemini, Anthropic, and OpenAI-compatible adapters; those use a server-side environment-variable reference and are never exposed to frontend code.

## Features

- FastAPI API with versioned `/api/v1` route groups, validation, consistent errors, and generated OpenAPI documentation at `/docs`.
- SQLAlchemy models for users, roles, providers, targets, test suites/cases/runs/results, findings, defense policy/events, alerts, source uploads/scans, patch proposals, and audit records.
- SQLite local database with an Alembic initial migration and PostgreSQL-compatible ORM setup.
- Signed local sessions for Administrator, Red Team, Blue Team, and Viewer. The development-only role header can be enabled to make authorization behavior testable, but a shared deployment must disable it and use a real identity provider.
- A mock model that can simulate test-only failures only within the built-in lab. All “confidential” data is synthetic.
- Deterministic prompt-injection, jailbreak, and sensitive-information tests, with stored redacted output excerpts and findings.
- Blue-team input checks, per-session gateway rate limiting, response redaction, event logging, alert generation, and repeatable baseline/protected comparisons.
- Safe ZIP source analysis: file/expanded-size bounds, traversal rejection, in-memory parsing, no uploaded-code execution, redacted findings, and optional Bandit/Semgrep/pip-audit availability detection.
- CSV and JSON test reports; sample synthetic report in [docs/example-security-report.json](docs/example-security-report.json).
- Docker Compose local service boundaries, non-root images, read-only containers, temporary filesystem mounts, dropped Linux capabilities, and resource limits.

## Prerequisites

- Python 3.11 or newer
- Node.js 20 or newer
- Docker Desktop, optional for the Compose path

## Run locally

In PowerShell, from the repository root:

```powershell
python -m pip install -r backend/requirements.txt
$env:PYTHONPATH = "backend"
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

In a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The API health check is `http://localhost:8000/health` and interactive API documentation is `http://localhost:8000/docs`.

## Local sign-in and roles

The app offers an optional signed local session. In the dashboard, select **Sign in** and use one of the seeded local addresses (`admin@bayora.local`, `red@bayora.local`, `blue@bayora.local`, or `viewer@bayora.local`) with the password in `BAYORA_DEMO_PASSWORD`.

The token is HMAC-signed by the API and limits routes by role. `BAYORA_ALLOW_DEMO_ROLE_HEADER=true` keeps the role selector available only as a local authorization-test convenience. Set it to `false` in any shared environment, change `BAYORA_AUTH_SECRET`, and replace demo identity with OIDC or a similarly managed identity provider.

## Run with Docker Compose

Create the local environment file first. It is ignored by Git:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Open `http://localhost:8080`. The Docker deployment exposes only the browser frontend gateway; check API readiness through `http://localhost:8080/health/ready`. Compose starts the browser frontend, API, red-team worker boundary, and blue-monitor boundary. The worker containers do not receive externally supplied target URLs and do not execute uploaded source code.

Compose first runs a narrowly scoped `db-init` helper that owns only the named SQLite data volume long enough to grant it to the non-root API user. The API, frontend, and worker services then run with read-only filesystems, dropped capabilities, resource limits, and health checks.

## Database migrations

The app creates its local schema at startup for a zero-friction demo. For a managed deployment, use the included initial migration:

```powershell
cd backend
alembic upgrade head
```

Set `BAYORA_DATABASE_URL` to a PostgreSQL SQLAlchemy URL before migration to use PostgreSQL.

## Configure a model provider

1. Add the key only to the backend environment, for example `OPENAI_API_KEY` in your non-committed `.env` or deployment secrets manager.
2. In **Integrations**, add a provider configuration with provider, model, optional custom base URL, and the environment-variable name (for example `OPENAI_API_KEY`).
3. Select **Test connection**. The API reads the secret server-side and only returns a short redacted status.
4. Make the tested configuration active, then select it in **Chatbot Lab**.

Provider configuration records never retain the raw key. Avoid placing keys in `VITE_*` variables, browser storage, or source files.

## Demo and validation details

For the strongest visual contrast, first run the baseline suite with defenses disabled. Then use **Blue Team** to ensure the gateway policies are enabled and rerun with “Run with blue defenses” switched on. The baseline mock uses only synthetic test records and deliberately configurable response behavior; the protected run uses deterministic policy checks and response redaction.

The default gateway request-limit policy permits 20 requests per synthetic session per 60 seconds. Adjust `BAYORA_RATE_LIMIT_REQUESTS` and `BAYORA_RATE_LIMIT_WINDOW_SECONDS` server-side for an approved environment; the limit is intentionally a deterministic control, not a replacement for upstream rate controls.

Metrics are calculated from stored execution results. They distinguish actual blocked attacks from test outcomes, but are explicitly not a universal security score.

The patch endpoint supports a safe human approval record. It does not overwrite any uploaded project. A production patch workflow should create a separate working copy, show a diff, validate in a sandbox, record a backup, request approval, apply only to that copy, and rerun the original regression suite.

## Source-code analysis

Upload only ZIP archives you are authorized to inspect. The implementation accepts a 5 MB upload with at most 300 entries and 10 MB expanded content. It examines selected source/config files in memory and never runs archive contents. When installed, Bandit runs with a no-shell, 15-second bounded subprocess over a temporary safe copy; its parsed results are stored beside the built-in rules. The tool status panel also detects Semgrep, pip-audit, and ZAP’s baseline script. Semgrep requires an administrator-managed local rule configuration and pip-audit is intentionally not auto-run in no-egress mode.

A reported code pattern is not proof that a vulnerability is exploitable. Each finding should be reviewed in its context.

## Authorized backend testing

Target registration requires an explicit authorization checkbox. Localhost, private address ranges, link-local metadata addresses, and unapproved destinations are rejected. This repository deliberately does not implement an arbitrary network scanner or uncontrolled exploitation. To add a production-authorized black-box mode, place it behind an administrator-managed allowlist, outbound egress policy, strict timeouts, rate limits, and an isolated worker.

## Tests and build checks

```powershell
$env:PYTHONPATH = "backend"
python -m pytest backend/tests -q
cd frontend
npm run build
```

The tests exercise health, mock chat, input defense behavior, repeatable baseline/protected runs, local target restrictions, and role-based denial.

## Architecture and limits

See [docs/architecture.md](docs/architecture.md) for the data flow and trust boundaries.

Docker Compose is only a development containment layer; it is not equivalent to a hardened production sandbox. Before deploying, use a real identity provider, a secrets manager, a production database, immutable audit storage, scoped service accounts, explicit outbound allowlists, independent worker sandboxes, centralized logging, TLS, and an application-specific threat model.

## Troubleshooting

- If the dashboard cannot reach the API in development, verify that Vite is running on port 5173 and FastAPI is running on port 8000.
- If provider testing fails, check that the named environment variable exists in the backend process, that the selected model is supported, and that the provider endpoint allows the request. The UI will not reveal a credential.
- If optional scanner status says “not installed,” install that tool in the isolated scanner image or use the built-in rule-based analysis for the demo.
- If a role action returns 403, switch to a role permitted for that operation. This is expected for the local RBAC demonstration.
