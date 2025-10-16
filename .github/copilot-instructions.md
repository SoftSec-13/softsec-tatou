# AI Coding Assistant Instructions for softsec-tatou

These rules help an AI agent work productively on this repository. The project is a pedagogical PDF watermarking web platform (intentionally vulnerable in places) consisting of a Flask API, MariaDB schema, and watermarking method plug‑ins. Focus on respecting existing patterns; do not "harden" security beyond current conventions unless explicitly asked.

## Architecture & Key Components
- Runtime stack: Python 3.12, Flask (`server/src/server.py`), SQLAlchemy Core (manual SQL via `text()`), MariaDB (schema in `db/tatou.sql`), Gunicorn for prod (Dockerfile), optional PyMuPDF for richer PDF introspection.
- Main app factory & routes: `create_app()` in `server/src/server.py`. Authentication: stateless signed tokens via `itsdangerous.URLSafeTimedSerializer`; `@require_auth` decorator attaches `g.user`.
- Watermarking subsystem: Interface & base contract in `watermarking_method.py`; registry + dispatch in `watermarking_utils.py`; concrete implementations (`robust_xmp_watermark.py`, `signed_annotation_watermark.py`, `structural_and_overlay_watermark.py`, etc.). Registry map `METHODS` is the single source for exposed methods and drives `/api/get-watermarking-methods` and tests.
- RMAP (custom handshake → session secret): Orchestrated by `RMAPHandler` (`rmap_handler.py`) which mounts `/rmap-initiate` and `/rmap-get-link`. Uses external `rmap` library (installed from private Git repo) and local GPG keys (`server/src/server_priv.asc`, `server/src/server_pub.asc`). Successful handshake auto‑generates a watermarked PDF version whose link equals the 32‑hex session secret.
- Storage layout: All uploaded PDFs and generated watermarks live beneath `STORAGE_DIR` (default `./storage` or container volume). User files: `storage/files/<login>/...`; Watermarked variants stored near originals (subdir `watermarks/`) or `storage/rmap_watermarks` for RMAP sessions.

## Data & Persistence
- DB access pattern: Direct `engine.execute(text(...), params)` with explicit transactions (`with get_engine().begin():`). No ORM models—keep using raw SQL consistent with existing style.
- Schema constraints: `Users`, `Documents`, `Versions` (see `db/tatou.sql`). Enforce ownership by joining / filtering with `ownerid`; never expose existence of another user's document (return 404 generic error).
- Hashing: File integrity via SHA‑256 (hex stored as binary in DB via `UNHEX(:sha256hex)`); version link tokens often derived from `sha256(filename)` or RMAP session secret.

## API Conventions
- Dual route styles: Many endpoints accept both path parameter and query/body fallback (`/api/get-document/<id>` or `/api/get-document?id=`). Preserve this flexibility when adding endpoints.
- Auth header: `Authorization: Bearer <token>`; token includes `uid`, `login`, `email`; TTL configurable via `TOKEN_TTL_SECONDS`.
- Error responses: Always JSON `{"error": <string>}` with appropriate HTTP status; avoid leaking internal details—log server‑side (`app.logger.*`). Return 503 for generic DB errors, 400 for validation issues, 404 for not found, 410 for missing file on disk, 415 for invalid PDF content/type, 413 for size.
- File validation: Confirm MIME, extension `.pdf`, size limit (50MB), and header starts with `%PDF-` before serving.

## Watermarking Patterns
- Capability checks: Always call `WMUtils.is_watermarking_applicable()` before `apply_watermark`; reject with 400 if not applicable.
- Registry extension: To add a new method, implement subclass of `WatermarkingMethod`, expose `name` and `get_usage()`, then add an instance to `METHODS` in `watermarking_utils.py` (or call `register_method()` early in app startup). Tests automatically parametrize over methods found in `METHODS` (excluding disabled / unsafe ones like `UnsafeBashBridgeAppendEOF`).
- Determinism: Output bytes should be deterministic for identical inputs (tests expect size >= original and `%PDF-` prefix).

## Observability & Monitoring
- Built-in metrics: Custom Prometheus-compatible metrics via `observability.py` (no external deps). Counters track uploads, watermarks, errors, DB latency.
- Metrics endpoint: GET `/metrics` with `X-Metrics-Token` header (configurable via `METRICS_TOKEN` env var).
- Event tracking: Use `inc_*()` and `observe_*()` functions from observability module; automatically includes route templates and method labels.
- Monitoring stack: Docker Compose includes Grafana (3000), Loki (3100), Prometheus (9090), Promtail, and Falco for security events.

## RMAP Flow
1. Client POST `/rmap-initiate` with base64 PGP payload (nonceClient, identity). Handler may pre‑extract identity to map later.
2. Server returns encrypted payload containing nonceClient + nonceServer.
3. Client POST `/rmap-get-link` with response payload; server computes 128‑bit concatenation → 32 hex session secret.
4. Server (RMAPHandler) embeds secret using method `robust-xmp` into static `static/Group_13.pdf`, inserts a `Versions` row with `link=session_secret` if not already materialized.

## Development Workflow
- Local tests: From `server/`: create venv, `pip install -e ".[dev]"`, run `pytest` (configured via `[tool.pytest.ini_options]` in `pyproject.toml`, tests under `server/test/`).
- CLI tool: Install provides `pdfwm` command for watermarking operations outside web interface.
- Linting/security: `ruff` configured (rules E,W,F,I,B,C4,UP,S). Bandit rules partially ignored; do not over‑correct intentionally vulnerable patterns unless asked.
- Pre-commit: Install with `pre-commit install`; CI runs it on all files before build.
- Docker (dev): `docker compose up --build -d` after preparing `.env` & server key files. Flask served by Gunicorn on 5000, DB on 3306 (loopback only), Grafana 3000, Loki 3100.
- Secrets/keys: Ensure `server_priv.asc`, `server_pub.asc` present; `.env` requires `GITHUB_TOKEN` to install the private `rmap` dependency during image build.
- Environment variables: Key vars include `STORAGE_DIR`, `TOKEN_TTL_SECONDS`, `METRICS_TOKEN`, `PRIVKEY_PASSPHRASE`, `TATOU_TEST_DISABLE_RMAP` (for tests).

## Adding / Modifying Endpoints
- Use existing decorators & error style; for authenticated routes wrap with `@require_auth` inside `create_app()` scope so `g.user` is available.
- Input retrieval precedence: path param → query (`id` or `documentid`) → JSON body (for POST). Maintain this pattern and sanitize/validate numeric ids early.

## Safety & Intentional Gaps
- Project is pedagogical: refrain from silently "fixing" insecure defaults (e.g., default SECRET_KEY, broad exception catches) unless the task is explicitly about hardening.
- When improving, document behavior in commit message but keep compatibility with tests and existing API contracts.

## Quick Reference Examples
- List methods: GET `/api/get-watermarking-methods` → uses `WMUtils.METHODS`.
- Create watermark: POST `/api/create-watermark/<doc_id>` JSON `{method, key, secret, intended_for, position?}`.
- Read watermark: POST `/api/read-watermark/<doc_id>` JSON `{method, key, position?}`.
- RMAP session link retrieval: POST `/rmap-initiate` then `/rmap-get-link`; fetch PDF via GET `/api/get-version/<32hex>`.

## Common Pitfalls
- Forgetting to call `is_watermarking_applicable` before `apply_watermark`.
- Returning raw exceptions to client (should log and send generic message).
- Path traversal: always resolve & ensure under `STORAGE_DIR` (see `_safe_resolve_under_storage`).
- Adding a method but not registering in `METHODS` -> endpoint & tests won’t see it.

When unsure, mirror surrounding code in `server/src/server.py` and keep responses minimal & consistent.
