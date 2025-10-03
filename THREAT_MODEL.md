# Tatou Platform Threat Model

Date: 2025-10-03
Scope: Deployed PDF watermarking service (Flask API + MariaDB + watermarking methods + RMAP flow) with added observability (Prometheus style metrics via /metrics, Loki/Promtail/Grafana log aggregation).

## 1. Assets
- User credentials (email, password hash)
- Authentication tokens (signed serializer tokens)
- PDF documents & derived watermarked versions
- RMAP session secrets (also used as version link tokens)
- Watermark secrets embedded inside PDFs
- Source code & watermarking method implementations
- Logging & telemetry data (may contain metadata, IPs)

## 2. Trust Boundaries
- Internet client -> Flask HTTP interface
- Flask app -> MariaDB
- Flask app -> Filesystem storage directory
- RMAP handshake (untrusted payloads) -> internal watermarking subsystem
- Metrics/Logs (read-only by monitoring stack) -> Grafana viewers

## 3. Actors
- Legitimate end users (registered accounts)
- RMAP clients (external groups with PGP keys)
- Opportunistic attacker (no auth)
- Authenticated but malicious user (insider threat) trying to escalate / pivot
- Automated scanners / bots probing endpoints

## 4. Entry Points / Attack Surface
- REST endpoints: /api/*, /rmap-initiate, /rmap-get-link, /api/get-version/<link>
- File upload (/api/upload-document) - PDF parsing & watermark embedding
- Watermark create/read methods (method parameter selects implementation)
- RMAP base64 JSON payloads
- Token-based auth (Authorization: Bearer ...)
- Static file serving for index and assets

## 5. Threat Enumeration (STRIDE)
| Category | Threat | Notes / Impact | Mitigations / Detection |
|----------|--------|----------------|-------------------------|
| Spoofing | Token theft or forging | Attacker replays token | Signed tokens + TTL; monitor unusual IP churn via access logs (future) |
| Tampering | Path manipulation to escape storage root | Could read/delete arbitrary files | _safe_resolve_under_storage checks & validation; log suspicious path failures (added inc_suspicious) |
| Repudiation | User denies actions (upload/delete) | Need audit | Structured logs & metrics counters (uploads, deletes via HTTP logs) |
| Information Disclosure | Enumerate documents via timing / error messages | Learn existence of other users' docs | Uniform 404 for missing/unauthorized documents; monitor 404 rate per user/IP |
| Information Disclosure | Watermark secret leakage via logs | Sensitive secret printed | Avoid logging secrets (current code never logs secret value) |
| DoS | Large PDF uploads / many watermarks | Resource exhaustion | 50MB check; latency histogram & request counters to spot spikes |
| DoS | Crafted PDFs causing heavy processing | CPU load | Metrics on watermark creation count; (future: add duration per method) |
| Elevation of Privilege | SQL injection through parameters | DB compromise | Parameterized SQL; detect DB errors (db_error counters) |
| Elevation of Privilege | Method selection to unsafe method | Execute arbitrary code | Unsafe method excluded from registry; metrics may show unexpected method name attempts (future enhancement) |
| Abuse | Brute force login | Account compromise | login failure counter + warning logs; alert on threshold |
| Abuse | RMAP secret guessing (/api/get-version/<link>) | Retrieve watermarked PDFs | 32/64 hex tokens high entropy; monitor 404 rate & distribution |

## 6. Selected Observation Points
1. Request latency & volume (per method, route) – detect spikes / anomalies.
2. Failed logins (reason=invalid_credentials) – brute force detection.
3. Database error counts (operation label) – possible injection / DB outage.
4. Upload count & bytes – detect large ingestion bursts.
5. Watermark created/read counters (method label) – detect anomalous method usage.
6. Suspicious events (rejected uploads / validation issues) – early probing signal.
7. Access logs (via Promtail regex) – per-status distribution, client IP.

## 7. Gaps / Future Work
- No correlation ID per request (could add X-Request-ID header).
- No per-user or per-IP rate limiting.
- Metrics not aggregated across gunicorn workers (needs multi-process or external exporter).
- No anomaly alerting rules yet (Grafana alerting could be added).
- Secrets in memory not redacted from debug tracebacks (intentionally permissive for course).

## 8. Abuse Cases & Detection Strategy
| Abuse Case | Signal | Metric / Log | Threshold (example) |
|------------|--------|--------------|---------------------|
| Brute force login | Rapid failed logins | tatou_login_failures_total | >50 in 5m |
| Token spray | High 401 count on authenticated routes | HTTP 401 in access logs | >5% of total req |
| Secret guessing of version links | Many 404s on /api/get-version | Access log status=404 path pattern | >200/h from single IP |
| Storage flood | Upload bytes spike | tatou_upload_bytes_total derivative | >2x baseline in 10m |
| Watermark abuse / enumeration | High watermark read vs create ratio | tatou_watermarks_read_total / tatou_watermarks_created_total | >10:1 sustained |
| SQL injection attempts | DB error spike | tatou_db_errors_total | > baseline + 3σ |

## 9. Residual Risk
Given academic scope, residual risks (token theft, DoS) accepted. Logging + metrics now provide visibility for detection & manual response.

---
Generated as part of operational security instrumentation task.
