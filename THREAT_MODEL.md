# Tatou Platform Threat Model

Date: 2025-10-13 (updated)
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
 - Input validation logic & regex patterns (email/login format) – protects against malformed account creation attempts

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
 - Metrics endpoint: /metrics (guarded by X-Metrics-Token header; returns 404 on failure to obscure existence)
 - Health check: /healthz (reveals DB connectivity state)
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
| Abuse | Brute force login | Account compromise | Constant-time password hash verification; login failure counter + warning logs; alert on threshold |
| Abuse | RMAP secret guessing (/api/get-version/<link>) | Retrieve watermarked PDFs | 32/64 hex tokens high entropy; monitor 404 rate & distribution |
| Information Disclosure | Metrics endpoint token brute force / enumeration | Learn that /metrics exists & scrape internal telemetry | Header secret required; returns 404 on failure (security by obscurity) – consider rate limiting & distinct 403 in future |
| Information Disclosure | /healthz reveals DB connectivity | Assist attacker in timing DB outages / maintenance | Limited data (boolean); acceptable risk; could gate behind auth or reduce detail later |
| Tampering | Abuse of position parameter (future methods) | Inject unexpected placement logic | Applicability check via is_watermarking_applicable; failures counted (stage=applicability) |

## 6. Selected Observation Points
1. HTTP request latency histogram `tatou_http_request_duration_seconds` & counter `tatou_http_requests_total` (labels: method, route, status) – spike & saturation detection.
2. In‑flight requests `tatou_http_requests_in_progress_total` (route) – hung handler / backlog signal.
3. Request body size histogram `tatou_http_request_body_bytes` – upload abuse & anomalous POST sizes.
4. Login successes vs failures: `tatou_login_successes_total` vs `tatou_login_failures_total{reason}` – brute force & credential stuffing ratio.
5. Watermark lifecycle: created `tatou_watermarks_created_total`, read `tatou_watermarks_read_total`, failed `tatou_watermarks_failed_total{method,stage}`, duration `tatou_watermark_duration_seconds` – performance regressions & exploitation attempts.
6. Upload activity: `tatou_uploads_total`, `tatou_upload_bytes_total` – storage flood detection.
7. Database health: `tatou_db_errors_total{operation}`, latency histogram `tatou_db_query_duration_seconds{operation}` – slow query & injection heuristics.
8. Suspicious validation events `tatou_suspicious_events_total{reason}` – early probing (bad mime, traversal, etc.). Current reasons: upload_missing_file_field, upload_bad_mime, upload_bad_extension, path traversal rejects.
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
 - Metrics endpoint relies on static shared header token; no rotation or per-operator scoping (risk: accidental leak in client tooling).
 - /healthz unauthenticated and reveals DB connectivity (low sensitivity but could aid targeted DoS timing).
 - Lack of explicit rate limiting for repeated failed /metrics access could enable token brute force (impractical if token long; still a theoretical gap).

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
| Metrics endpoint probing | Many 404s with X-Metrics-Token header variations | Access logs (path=/metrics) | >50 distinct attempts in 10m |
| Health check scraping | Elevated /healthz frequency from single IP | Access logs (path=/healthz) | >120/min (beyond normal monitoring) |

## 9. Residual Risk
Given academic scope, residual risks (token theft, DoS, limited obfuscation of /metrics) remain accepted. Logging, metrics (including body size & suspicious events), and Falco runtime alerts provide richer detection, but Falco runs privileged and depends on timely rule/driver updates to avoid becoming a liability. Lack of rate limiting and static metrics token are conscious trade-offs for simplicity.

## 10. Grafana Alerting Rules
Provisioned in `grafana/provisioning/alerting/alerts.yaml` (unified alerting). Each rule maps to abuse cases or observation points above.

| Rule UID | Purpose | Default Threshold | Threat Model Link |
|----------|---------|-------------------|-------------------|
| tatou_api_latency_p95 | Detect elevated p95 API latency | p95 > 0.5s for 5m | DoS / performance degradation |
| tatou_api_errors_spike | 5xx error ratio high | >5% 5xx over 5m | Backend instability / emerging fault |
| tatou_login_bruteforce | Brute force login | >50 failures /5m | Brute force abuse |
| tatou_watermark_fail_ratio | Watermark failures >5% | >5% over 15m | Fuzzing / method regression |
| tatou_version_404_guessing | Link guessing | >200 404s /1h | Secret guessing of version links |
| tatou_upload_volume_spike | Storage flood attempt | 10m bytes >2x prior 10m | Storage flood / DoS |
| tatou_db_error_spike | DB error surge | >5 errors /5m | SQLi attempts / DB outage |
| tatou_suspicious_event_rate | Input probing | >20 events /5m | Probing / reconnaissance |
| tatou_watermark_read_to_create_ratio | Enumeration of watermarks | read/create >10 /30m | Enumeration abuse |
| tatou_falco_high_priority | Critical Falco alert | any critical in 10m | Container breakout attempt |
| tatou_shell_detection | Shell spawned indicator | any in 10m | Container breakout attempt |

Tuning Guidance:
- Establish baseline first (observe at least 24h) and recalibrate static thresholds to minimize false positives (<1 non-actionable alert/day).
- Consider dynamic ratios (e.g., failed_logins / total_logins) if workload highly variable.
- Latency alert currently global; add route label segmentation if specific endpoints need tighter SLOs.
- Combine multiple consecutive evaluations (for durations already set) to reduce flapping.
- For production, add notification policies (Slack/Email/Pager) in Grafana UI; repository does not provision contacts.

Extension Steps:
1. Add rule under the relevant group in `alerts.yaml` using `prometheus_ds` (metrics) or `loki_ds` (logs).
2. Keep evaluation interval aligned with Prometheus `evaluation_interval` (1m) unless strong reason otherwise.
3. Update this table and, if new threat class, expand STRIDE or Abuse sections.

---
Updated to reflect refined metrics instrumentation (additional histograms & counters) leveraging existing Prometheus + Loki + Falco stack.

Revision notes (2025-10-13): Added /healthz and /metrics endpoint considerations, expanded STRIDE table with metrics & health check disclosure threats, documented new input validation asset, enumerated current suspicious event reasons, noted gaps around static metrics token & absent rate limiting, and migrated Grafana alerting documentation into this file (section 10).
