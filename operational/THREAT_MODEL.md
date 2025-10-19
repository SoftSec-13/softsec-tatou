# Tatou Platform Threat Model

**Date:** 2025-10-13 (updated)
**Scope:** Deployed PDF watermarking service (Flask API + MariaDB + watermarking methods + RMAP flow) with added observability (Prometheus style metrics via /metrics, Loki/Promtail/Grafana log aggregation, Falco runtime security)
**Methodology:** STRIDE (Microsoft Threat Modeling Framework)

---

## Executive Summary

This threat model follows the **STRIDE framework** developed by Microsoft for identifying security threats in software systems. STRIDE categorizes threats into six primary types:

- **S**poofing Identity
- **T**ampering with Data
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

This document applies STRIDE systematically to the Tatou PDF watermarking platform to identify threats, assess risks, and define detection and mitigation strategies.

---

## 1. System Overview

### 1.1 Assets

- User credentials (email, password hash)
- Authentication tokens (signed serializer tokens)
- PDF documents & derived watermarked versions
- RMAP session secrets (also used as version link tokens)
- Watermark secrets embedded inside PDFs
- Source code & watermarking method implementations
- Logging & telemetry data (may contain metadata, IPs)
- Falco runtime alerts and custom rule definitions (sensitive operational intel)
- Input validation logic & regex patterns (email/login format) — protects against malformed account creation attempts
- Docker volume backup archives (`tar.gz`) produced by `operational/backup.sh` (contain copies of persistent data)

### 1.2 Trust Boundaries

- Internet client → Flask HTTP interface
- Flask app → MariaDB
- Flask app → Filesystem storage directory
- RMAP handshake (untrusted payloads) → internal watermarking subsystem
- Metrics/Logs (read-only by monitoring stack) → Grafana viewers
- Container runtime/syscalls → Falco sensor (privileged host visibility)

### 1.3 Actors

- **Legitimate end users** - Registered accounts performing normal operations
- **RMAP clients** - External groups with PGP keys
- **Opportunistic attacker** - Unauthenticated attacker probing for vulnerabilities
- **Authenticated malicious user** - Insider threat attempting escalation/pivot
- **Automated scanners/bots** - Probing endpoints for vulnerabilities
- **Security analyst** - Defender monitoring metrics/logs/Falco alerts

### 1.4 Entry Points / Attack Surface

- REST endpoints: `/api/*`, `/rmap-initiate`, `/rmap-get-link`
- Metrics endpoint: `/metrics` (guarded by X-Metrics-Token header; returns 404 on failure to obscure existence)
- Health check: `/healthz` (reveals DB connectivity state)
- File upload (`/api/upload-document`) - PDF parsing & watermark embedding
- Watermark create/read methods (method parameter selects implementation)
- RMAP base64 JSON payloads
- Token-based auth (Authorization: Bearer ...)
- Static file serving for index and assets
- Docker socket mounts for monitoring agents (Falco, Promtail)

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing Identity

**Definition:** Attacker pretends to be someone or something else.

|Threat|Attack Vector|Impact|Current Mitigations|Detection Strategy|
|---|---|---|---|---|
|Token theft or replay|Stolen authentication token used to impersonate legitimate user|Unauthorized access to user documents and operations|Signed tokens with TTL expiration|Monitor `tatou_login_successes_total` from unusual IPs/patterns|
|Credential brute force|Automated password guessing against login endpoint|Account compromise|Constant-time password hash verification|`tatou_login_failures_total` >50 in 5m; alert via Grafana|
|RMAP session impersonation|Attacker forges RMAP session credentials|Unauthorized watermark generation|PGP-based verification of RMAP clients|Monitor RMAP endpoint access patterns|

### 2.2 Tampering with Data

**Definition:** Malicious modification of data or code.

|Threat|Attack Vector|Impact|Current Mitigations|Detection Strategy|
|---|---|---|---|---|
|Path traversal to escape storage root|Manipulated file paths to read/write arbitrary files|File system compromise, data leakage|`_safe_resolve_under_storage` / relative path checks (reject outside STORAGE_DIR)|Log warning; future metric reason (not currently emitted) – rely on access logs|
|Method selection to unsafe implementation|Attacker specifies malicious watermarking method|Arbitrary code execution|Unsafe methods excluded from registry|`tatou_watermarks_failed_total{stage}` counters reveal exploitation attempts|
|PDF content manipulation|Modified watermarked PDFs returned to users|Integrity compromise of watermarks|Watermark verification mechanisms|Compare watermark read success/failure ratios|
|Position parameter abuse|Injection of unexpected placement logic in future methods|Watermark bypass or rendering issues|Applicability check via `is_watermarking_applicable`|Method-specific validation failure logs|
|Backup archive modification/deletion|Tampering with `.tar.gz` backup files|Breaks recovery chain or injects poisoned data|Filesystem permissions (root-only)|Retention script logs deletions; consider future integrity hashes|

### 2.3 Repudiation

**Definition:** User denies performing an action without the system being able to prove otherwise.

|Threat|Attack Vector|Impact|Current Mitigations|Detection Strategy|
|---|---|---|---|---|
|User denies document upload|Claim they didn't upload a specific document|Disputes and accountability issues|Structured logs with user ID and timestamps|`tatou_uploads_total` per-user counters; HTTP access logs|
|User denies document deletion|Claim they didn't delete a document|Disputes and accountability issues|HTTP request logging with authentication context|Access logs capture DELETE operations with auth tokens|
|Denial of watermark creation|User claims they didn't create a watermark|Billing or usage disputes|`tatou_watermarks_created_total` with metadata|Correlate metrics with audit logs|

### 2.4 Information Disclosure

**Definition:** Exposure of information to unauthorized individuals.

|Threat|Attack Vector|Impact|Current Mitigations|Detection Strategy|
|---|---|---|---|---|
|Document enumeration via timing/errors|Different responses reveal document existence|Learn about other users' documents|Uniform 404 responses for missing/unauthorized documents|Monitor 404 rate distribution per IP|
|Watermark secret leakage via logs|Sensitive secrets printed in application logs|Watermark verification bypass|Avoid logging secrets (conscious decision for course scope)|Manual log review for sensitive data patterns|
|RMAP secret guessing|Brute force version link tokens at `/api/get-version/<link>`|Unauthorized PDF retrieval|32/64 hex tokens with high entropy|Monitor 404 rate on version endpoint; alert >200/h from single IP|
|Metrics endpoint enumeration|Brute force X-Metrics-Token header|Exposure of internal telemetry|Header secret required; returns 404 on failure (security by obscurity)|Access logs for `/metrics` with failed attempts >50 in 10m|
|Health check information leakage|`/healthz` reveals DB connectivity state|Assists attacker in timing DB outages|Limited data exposure|Elevated `/healthz` frequency detection >120/min|
|Backup archive theft|Stolen `.tar.gz` files containing data snapshots|Offline analysis of documents, DB, secrets|Restricted filesystem permissions (root-only)|Monitor unexpected archive access in logs|

### 2.5 Denial of Service

**Definition:** Making the system unavailable or unusable.

|Threat|Attack Vector|Impact|Current Mitigations|Detection Strategy|
|---|---|---|---|---|
|Large PDF upload flood|Multiple 50MB PDF uploads|Storage exhaustion, bandwidth saturation|50MB size check enforced; oversize flagged as suspicious|`tatou_upload_bytes_total` derivative & suspicious reason `upload_oversize`; body size histogram for distribution|
|Crafted malicious PDFs|PDFs designed to cause heavy processing|CPU/memory exhaustion|Watermark duration monitoring|`tatou_watermark_duration_seconds` p95 >2x baseline + `tatou_watermarks_failed_total` spike|
|API endpoint flooding|High volume requests to any endpoint|Service unavailability|Latency histograms & request counters|`tatou_http_requests_total` spike; `tatou_http_requests_in_progress_total` saturation|
|Database query overload|Resource-intensive queries|Database slowdown/crash|Query duration monitoring|`tatou_db_query_duration_seconds` increase + `tatou_db_errors_total` spike|
|Backup I/O contention|Tar operations during peak usage|Slower DB or watermark operations|Off-peak scheduling (cron 01:00), compression|Monitor I/O wait times during backup windows|

### 2.6 Elevation of Privilege

**Definition:** Unprivileged user gains privileged access.

|Threat|Attack Vector|Impact|Current Mitigations|Detection Strategy|
|---|---|---|---|---|
|SQL injection|Malicious SQL in parameters|Database compromise, data exfiltration|Parameterized SQL queries|`tatou_db_errors_total{operation}` >5/5m (alert) + error log review|
|Container breakout via shell|Interactive shell spawned inside container|Host or other container compromise|Falco runtime monitoring|Falco alerts on shell spawning; Grafana `tatou_shell_detection` rule|
|Docker socket abuse|Manipulation of Docker socket mounts|Full host compromise|Limited socket exposure; Falco monitoring|Falco alerts on socket tampering; `tatou_falco_high_priority` rule|
|Authentication bypass|Exploit to skip authentication checks|Unauthorized admin access|Token validation on all protected routes|High 401 rate followed by successful 200s pattern|
|Unsafe method execution|Trigger execution of excluded watermarking methods|Code execution|Method registry whitelist enforcement|Failed watermark attempts with invalid method names|

---

## 3. Component-Level STRIDE Mapping

|Component|S|T|R|I|D|E|
|---|---|---|---|---|---|---|
|Flask API|✓|✓|✓|✓|✓|✓|
|MariaDB|✓|✓|✓|✓|✓|✓|
|File Storage|-|✓|-|✓|✓|-|
|Authentication Tokens|✓|✓|✓|✓|-|✓|
|Watermarking Engine|-|✓|-|✓|✓|✓|
|RMAP Interface|✓|✓|-|✓|✓|-|
|Metrics Endpoint|✓|-|-|✓|✓|-|
|Backup System|-|✓|✓|✓|-|-|
|Falco Runtime Security|-|-|-|✓|-|-|

---

## 4. Observability & Detection Framework

### 4.1 Metrics-Based Detection Points

1. **HTTP request latency histogram** `tatou_http_request_duration_seconds` & counter `tatou_http_requests_total` (labels: method, route, status) — spike & saturation detection
2. **In-flight requests** `tatou_http_requests_in_progress_total` (route) — hung handler / backlog signal
3. **Request body size histogram** `tatou_http_request_body_bytes` — upload abuse & anomalous POST sizes
4. **Login successes vs failures:** `tatou_login_successes_total` vs `tatou_login_failures_total{reason}` — brute force & credential stuffing ratio
5. **Watermark lifecycle:** created `tatou_watermarks_created_total`, read `tatou_watermarks_read_total`, failed `tatou_watermarks_failed_total{method,stage}`, duration `tatou_watermark_duration_seconds` — performance regressions & exploitation attempts
6. **Upload activity:** `tatou_uploads_total`, `tatou_upload_bytes_total` — storage flood detection
7. **Database health:** `tatou_db_errors_total{operation}`, latency histogram `tatou_db_query_duration_seconds{operation}` — slow query & injection heuristics
8. **Suspicious validation events** `tatou_suspicious_events_total{reason}` — early probing (bad mime, missing file field, oversize attempts, extension issues). Current implemented reasons observed in code: `upload_missing_file_field`, `upload_bad_mime`, `upload_bad_extension`, `upload_oversize`. (Path traversal currently logged but not counted—potential future reason `path_traversal`).
9. **Access logs** (Promtail parsed labels: method, path, status, duration) — per-IP anomaly & 404 enumeration outside metrics cardinality
10. **Falco runtime alerts** (Loki `falco_rule`) — syscall-level breakout indicators

### 4.2 Abuse Case Detection Matrix

|STRIDE Category|Abuse Case|Primary Signal|Metric / Log Source|Alert Threshold (Implemented)|Alert UID / Status|
|---|---|---|---|---|---|
|Spoofing|Brute force login|Rapid failed logins|`tatou_login_failures_total`|>50 in 5m sustained 1m|`tatou_login_bruteforce` (active)|
|Spoofing|Token spray|High 401 ratio|Access logs (401 on auth routes)|>5% of total (heuristic)|Not yet alert (planned)|
|Information Disclosure|Secret guessing of version links|404 surge on `/api/get-version/<link>`|Access logs + `tatou_http_requests_total`|>200 in 1h|`tatou_version_404_guessing` (active)|
|Denial of Service|Storage flood|Upload bytes spike vs prior window|`tatou_upload_bytes_total`|Current 10m >2× prior 10m avg|`tatou_upload_volume_spike` (active)|
|Information Disclosure|Watermark enumeration|High read/create ratio|`tatou_watermarks_read_total` & `tatou_watermarks_created_total`|>10 over 30m sustained 10m|`tatou_watermark_read_to_create_ratio` (active)|
|Denial of Service / Elev. Priv.|Watermark fuzzing / exploit attempt|Failure ratio increase|`tatou_watermarks_failed_total` vs created|>5% over 15m sustained 10m|`tatou_watermark_fail_ratio` (active)|
|Denial of Service (perf)|Watermark heavy processing|p95 duration tail|`tatou_watermark_duration_seconds`|p95 > baseline×2 (heuristic)|Not yet alert (proposed `tatou_watermark_duration_tail`)|
|Elevation of Privilege / Tampering|SQL injection attempts|DB error spike|`tatou_db_errors_total`|>5 errors in 5m sustained 2m|`tatou_db_error_spike` (active)|
|Elevation of Privilege|Container breakout attempt|Falco critical event|Loki Falco logs|>0 critical in 10m|`tatou_falco_high_priority` (active)|
|Elevation of Privilege|Shell spawned inside container|Falco "shell was spawned"|Loki Falco logs|>0 in 10m|`tatou_shell_detection` (active)|
|Information Disclosure|Metrics endpoint probing|Repeated 404s with varying token|Access logs `/metrics`|>50 distinct attempts in 10m|Not yet alert (proposed `tatou_metrics_probe_rate`)|
|Information Disclosure|Health check scraping|Excessive `/healthz` hits per IP|Access logs `/healthz`|>120/min|Not yet alert (proposed `tatou_healthz_scrape_rate`)|

Coverage Notes:
- All active alerts correspond to implemented PromQL rules in `alerts.yaml` and have explicit severity & hold durations documented in Section 5.
- Pending alerts avoided presently due to need for baseline (reduce false positives) and potential high-cardinality label explosion if naively metricized; log-based aggregation recommended before exposing synthetic counters.
- SQL injection heuristic simplified from statistical (baseline + 3σ) to fixed threshold matching current implementation; revisit for adaptive thresholding once historical time series volume is sufficient.

---

## 5. Grafana Alerting Rules

Provisioned in `grafana/provisioning/alerting/alerts.yaml` (unified alerting). Each rule maps to STRIDE categories and abuse cases. Table now includes severity, evaluation lookback range, and hold duration (`for:`) consistent with YAML. Threshold phrasing mirrors PromQL semantics.

|Rule UID|Purpose|STRIDE Category|Threshold (PromQL logic)|Eval Range|Hold (`for:`)|Severity|
|---|---|---|---|---|---|---|
|tatou_api_latency_p95|p95 API latency elevated (perf degradation / emerging DoS)|Denial of Service|p95 >= 0.5s (histogram_quantile over 5m rate)|5m|5m|warning|
|tatou_api_errors_spike|5xx error ratio high|Denial of Service|(5xx / total) > 0.05|5m|5m|warning|
|tatou_login_bruteforce|Brute force login suspected|Spoofing|failures[5m] > 50|5m|1m|high|
|tatou_watermark_fail_ratio|Watermark failures >5% (fuzzing / regression)|Denial of Service / Elevation of Privilege|(failures / creations) > 0.05 over 15m|15m|10m|warning|
|tatou_version_404_guessing|Version link (secret) guessing|Information Disclosure|404s get-version[1h] > 200|1h|0m|info|
|tatou_upload_volume_spike|Upload volume spike|Denial of Service|bytes[10m] > 2 × (prior 10m avg)|10m vs prior 10m|5m|warning|
|tatou_db_error_spike|DB error spike (possible SQLi)|Elevation of Privilege / Tampering|db_errors[5m] > 5|5m|2m|warning|
|tatou_suspicious_event_rate|Suspicious validation events elevated|Multiple STRIDE|suspicious_events[5m] > 20|5m|2m|info|
|tatou_watermark_read_to_create_ratio|Watermark read/create ratio anomalous|Information Disclosure|(reads / creations) > 10 over 30m|30m|10m|info|
|tatou_falco_high_priority|Falco critical alert|Elevation of Privilege|critical events[10m] > 0|10m|0m|critical|
|tatou_shell_detection|Shell spawned in container|Elevation of Privilege|"shell was spawned"[10m] > 0|10m|0m|high|

Notes:
1. Eval Range reflects `relativeTimeRange` of primary query. Upload spike compares current 10m window against previous 10m (baseline approximation).
2. Hold shows sustained condition needed before firing; 0m means immediate evaluation trigger.
3. Severity values align with YAML `labels.severity` used for downstream routing.
4. Dual-category tagging (e.g., watermark fail ratio) indicates overlapping STRIDE threat dimensions.

---

## 6. Backup & Recovery Strategy

### 6.1 Implementation

Daily volume snapshot script `operational/backup.sh` (cron scheduled off-peak, e.g., 01:00):

1. Enumerates Docker volumes (or allowlist via VOLUMES env)
2. Resolves each volume mountpoint (`docker volume inspect`)
3. Creates compressed archives `backup_root/<vol>/<vol>-<timestamp>.tar.gz` (default root: `/var/backups/docker-volumes`)
4. Prunes archives older than RETENTION_DAYS (default 7) via `find -mtime`

### 6.2 Recovery Path

- **Single volume restore:** Create empty volume, extract latest archive with `tar -xzf` into mountpoint (or via temporary helper container)
- **Application-level regeneration:** Watermarked PDFs can be deterministically re-generated from original uploads + stored metadata if needed; backups primarily protect against total storage or host loss

### 6.3 STRIDE Analysis of Backup System

|STRIDE|Threat|Risk Level|Mitigation Status|
|---|---|---|---|
|Tampering|Modification/deletion of backup archives|Medium|Filesystem perms (root-only); retention script logs deletions|
|Information Disclosure|Theft of backup archives|High|Root-only access; unencrypted (accepted risk)|
|Repudiation|Undocumented backup operations|Low|Retention script logs all operations|
|Denial of Service|I/O contention during backup|Low|Off-peak scheduling, compression|

**Security Considerations:**

- Archives inherit underlying data sensitivity
- Currently stored unencrypted on same host; compromise of host → compromise of backups (no defense-in-depth)
- Tampering not cryptographically detected (no hashes/signatures recorded)
- Backup process requires root (reads `/var/lib/docker/volumes/...`); misuse of script could exfiltrate data

**Performance / Availability:**

- Potential I/O contention mitigated by off-peak scheduling; archive compression shortens retention footprint
- No incremental or differential strategy; full tar each run (acceptable for current dataset size, revisit on growth)

---

## 7. Risk Assessment & Gaps

### 7.1 Identified Gaps

- **No correlation ID per request** — Could add X-Request-ID header & propagate to logs (affects Repudiation)
- **No per-user or per-IP rate limiting** — Increases DoS and Spoofing risk
- **Metrics remain per-process** — Gunicorn multi-worker aggregation left to Prometheus
- **Secrets in memory not redacted from debug tracebacks** — Intentional for course scope (Information Disclosure risk)
- **No metric for per-user 404 rate** — Derive from logs to avoid high-cardinality metric labels
- **Metrics endpoint static token** — No rotation or per-operator scoping; accidental leak risk (Information Disclosure)
- **Backups unencrypted, same-host only** — No integrity hash or automated restore verification (Tampering & Information Disclosure)
- **No alerting for backup failures** — Missing expected daily archive detection

### 7.2 Residual Risk Statement

Given academic scope, residual risks are **consciously accepted**:

- **Token theft** (Spoofing) — Limited TTL provides some mitigation
- **DoS attacks** — No rate limiting, relying on monitoring for detection
- **Metrics endpoint obfuscation** (Information Disclosure) — Security by obscurity via 404 response
- **Backup security** (Tampering & Information Disclosure) — Unencrypted, same-host storage

**Risk Reduction Strategy:**
Layered detection via logging, metrics (including body size & suspicious events), Falco runtime alerts, and deterministic watermark regeneration provide defense-in-depth. RPO for volume loss: <24h (daily backup schedule).

---

## 8. Conclusion

This threat model applies the STRIDE framework systematically to the Tatou PDF watermarking platform. Key security controls include:

1. **Spoofing mitigation:** Signed tokens, constant-time password verification, login failure monitoring
2. **Tampering prevention:** Path validation, method whitelisting, parameterized SQL
3. **Repudiation controls:** Structured logging, metrics counters, audit trails
4. **Information Disclosure protection:** Uniform error responses, secret entropy, access monitoring
5. **DoS resilience:** Size limits, duration monitoring, off-peak backup scheduling
6. **Privilege escalation prevention:** SQL parameterization, Falco runtime monitoring, method registry controls

The observability framework provides comprehensive threat detection through Prometheus metrics, Loki log aggregation, and Grafana alerting. Accepted residual risks are documented and appropriate for the academic context of this project.

**Last Updated:** 2025-10-16
**Next Review:** Upon significant architectural changes or security incident
