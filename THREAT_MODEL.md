# Tatou Platform Threat Model

Date: 2025-10-04 (updated)
Scope: Deployed PDF watermarking service (Flask API + MariaDB + watermarking methods + RMAP flow) with added observability (Prometheus style metrics via /metrics, Loki/Promtail/Grafana log aggregation, Falco runtime security).

## 1. Assets
- User credentials (email, password hash)
- Authentication tokens (signed serializer tokens)
- PDF documents & derived watermarked versions
- RMAP session secrets (also used as version link tokens)
- Watermark secrets embedded inside PDFs
- Source code & watermarking method implementations
- Logging & telemetry data (may contain metadata, IPs)
- Falco runtime alerts and custom rule definitions (sensitive operational intel)

## 2. Trust Boundaries
- Internet client -> Flask HTTP interface
- Flask app -> MariaDB
- Flask app -> Filesystem storage directory
- RMAP handshake (untrusted payloads) -> internal watermarking subsystem
- Metrics/Logs (read-only by monitoring stack) -> Grafana viewers
- Container runtime/syscalls -> Falco sensor (privileged host visibility)

## 3. Actors
- Legitimate end users (registered accounts)
- RMAP clients (external groups with PGP keys)
- Opportunistic attacker (no auth)
- Authenticated but malicious user (insider threat) trying to escalate / pivot
- Automated scanners / bots probing endpoints
- Security analyst monitoring metrics/logs/Falco alerts (defender)

## 4. Entry Points / Attack Surface
- REST endpoints: /api/*, /rmap-initiate, /rmap-get-link, /api/get-version/<link>
- File upload (/api/upload-document) - PDF parsing & watermark embedding
- Watermark create/read methods (method parameter selects implementation)
- RMAP base64 JSON payloads
- Token-based auth (Authorization: Bearer ...)
- Static file serving for index and assets
- Docker socket mounts for monitoring agents (Falco, Promtail)

## 5. Threat Enumeration (STRIDE)
| Category | Threat | Notes / Impact | Mitigations / Detection |
|----------|--------|----------------|-------------------------|
| Spoofing | Token theft or forging | Attacker replays token | Signed tokens + TTL; monitor unusual IP churn via access logs (future) |
| Tampering | Path manipulation to escape storage root | Could read/delete arbitrary files | _safe_resolve_under_storage checks & validation; log suspicious path failures (added inc_suspicious) |
| Repudiation | User denies actions (upload/delete) | Need audit | Structured logs & metrics counters (uploads, deletes via HTTP logs) |
| Information Disclosure | Enumerate documents via timing / error messages | Learn existence of other users' docs | Uniform 404 for missing/unauthorized documents; monitor 404 rate per user/IP |
| Information Disclosure | Watermark secret leakage via logs | Sensitive secret printed | Avoid logging secrets (current code never logs secret value) |
| DoS | Large PDF uploads / many watermarks | Resource exhaustion | 50MB check; latency histogram & request counters to spot spikes |
| DoS | Crafted PDFs causing heavy processing | CPU load | Watermark duration histogram (tatou_watermark_duration_seconds) + create & failure counters |
| Elevation of Privilege | SQL injection through parameters | DB compromise | Parameterized SQL; detect DB errors (db_error counters) |
| Elevation of Privilege | Method selection to unsafe method | Execute arbitrary code | Unsafe method excluded from registry; failed watermark counters (stage label) reveal attempts |
| Elevation of Privilege | Container breakout via interactive shell / docker socket abuse | Host or other containers compromised | Falco alerts on shells, socket tampering (falco_rule label), Grafana panel for triage |
| Abuse | Brute force login | Account compromise | login failure counter + warning logs; alert on threshold |
| Abuse | RMAP secret guessing (/api/get-version/<link>) | Retrieve watermarked PDFs | 32/64 hex tokens high entropy; monitor 404 rate & distribution |

## 6. Selected Observation Points
1. HTTP request latency histogram `tatou_http_request_duration_seconds` & counter `tatou_http_requests_total` (labels: method, route, status) – spike & saturation detection.
2. In‑flight requests `tatou_http_requests_in_progress_total` (route) – hung handler / backlog signal.
3. Request body size histogram `tatou_http_request_body_bytes` – upload abuse & anomalous POST sizes.
4. Login successes vs failures: `tatou_login_successes_total` vs `tatou_login_failures_total{reason}` – brute force & credential stuffing ratio.
5. Watermark lifecycle: created `tatou_watermarks_created_total`, read `tatou_watermarks_read_total`, failed `tatou_watermarks_failed_total{method,stage}`, duration `tatou_watermark_duration_seconds` – performance regressions & exploitation attempts.
6. Upload activity: `tatou_uploads_total`, `tatou_upload_bytes_total` – storage flood detection.
7. Database health: `tatou_db_errors_total{operation}`, latency histogram `tatou_db_query_duration_seconds{operation}` – slow query & injection heuristics.
8. Suspicious validation events `tatou_suspicious_events_total{reason}` – early probing (bad mime, traversal, etc.).
9. Access logs (Promtail parsed labels: method, path, status, duration) – per‑IP anomaly & 404 enumeration outside metrics cardinality.
10. Falco runtime alerts (Loki `falco_rule`) – syscall-level breakout indicators.

## 7. Gaps / Future Work
- No correlation ID per request (could add X-Request-ID header & propagate to logs).
- No per-user or per-IP rate limiting.
- Metrics remain per-process (Gunicorn multi-worker aggregation left to Prometheus).
- No Grafana alert rules yet (define SLOs / detectors using new histograms & counters).
- Secrets in memory not redacted from debug tracebacks (intentional for course scope).
- Falco alert triage still manual; need severity mapping & routing.
- No metric for per-user 404 rate (derive from logs; avoid high-cardinality metric labels).

## 8. Abuse Cases & Detection Strategy
| Abuse Case | Signal | Metric / Log | Threshold (example) |
|------------|--------|--------------|---------------------|
| Brute force login | Rapid failed logins | tatou_login_failures_total | >50 in 5m |
| Token spray | High 401 count on authenticated routes | HTTP 401 in access logs | >5% of total req |
| Secret guessing of version links | Many 404s on /api/get-version | Access log status=404 path pattern | >200/h from single IP |
| Storage flood | Upload bytes spike | tatou_upload_bytes_total derivative | >2x baseline in 10m |
| Watermark abuse / enumeration | High watermark read vs create ratio | tatou_watermarks_read_total / tatou_watermarks_created_total | >10:1 sustained |
| Watermark fuzzing / exploit attempt | Spike in failures & duration tail | tatou_watermarks_failed_total + p95 watermark_duration | Failures >5% + p95 > baseline*2 |
| SQL injection attempts | DB error spike | tatou_db_errors_total | > baseline + 3σ |
| Container breakout attempt | Falco rule trigger (e.g. Terminal shell, Tatou storage write) | Loki `{container="/falco"}` stream | Any high-priority alert |

## 9. Residual Risk
Given academic scope, residual risks (token theft, DoS) remain accepted. Logging, metrics, and Falco runtime alerts provide richer detection, but Falco runs privileged and depends on timely rule/driver updates to avoid becoming a liability.

---
Updated to reflect refined metrics instrumentation (additional histograms & counters) leveraging existing Prometheus + Loki + Falco stack.
