# Tatou Platform Incident Report (Sample / Template)

Report Date: 2025-10-03
Observation Window: Initial deployment with observability stack enabled.

## 1. Executive Summary
During the observation period we recorded several failed login attempts and a small number of suspicious upload validation failures. No successful compromise detected. System availability remained normal. This report documents observable events, analysis, and recommended actions.

## 2. Timeline
| Time (UTC) | Event | Source |
|------------|-------|--------|
| T0 | Deployment with /metrics endpoint | Change log |
| T0 + 5m | First failed login attempts (invalid email) | app log + metric tatou_login_failures_total |
| T0 + 12m | Multiple upload attempts missing 'file' field | metric tatou_suspicious_events_total(reason=upload_missing_file_field) |
| T0 + 30m | Normal watermark creation & read activity | metrics |

## 3. Detection Sources
- Prometheus-compatible scrape of /metrics (counters & histograms)
- Loki aggregated container logs (Promtail docker_sd)
- Grafana dashboard (flask.json) visualizing request rates & status codes

## 4. Impact Assessment
No data exfiltration observed; failed logins blocked at auth step. Suspicious uploads rejected pre-storage. No elevation of privilege or resource exhaustion events.

## 5. Detailed Event Analysis
### 5.1 Failed Login Attempts
Metric: tatou_login_failures_total incremented steadily (reason=invalid_credentials). Access logs show diverse client IPs → likely automated enumeration. No single IP exceeded tentative brute force threshold (50/5m). No response required beyond continued monitoring.

### 5.2 Suspicious Upload Attempts
Missing file field / bad mimetype triggered tatou_suspicious_events_total with reasons upload_missing_file_field and upload_bad_mime. Indicates probing of upload endpoint (possibly for SSRF / content-type confusion). Early detection suggests instrumentation functioning.

### 5.3 Database Errors
No spike in tatou_db_errors_total; occasional benign errors (unique constraint) consistent with expected usage. No indication of SQL injection attempts in this window.

## 6. Metrics Snapshot (Illustrative)
```
tatou_login_failures_total{reason="invalid_credentials"} 7
tatou_suspicious_events_total{reason="upload_missing_file_field"} 3
tatou_uploads_total 5
tatou_watermarks_created_total{method="robust-xmp"} 5
tatou_watermarks_read_total{method="robust-xmp"} 4
```
(Latency histogram omitted for brevity.)

## 7. Response Actions Taken
- Monitored dashboard for anomalies.
- Verified no leaked secrets in logs.
- Confirmed watermarked versions correspond to legitimate user actions.

## 8. Lessons Learned
- Add alerting rules (Grafana / Alertmanager) for brute force & 404 spikes.
- Introduce correlation IDs to trace multi-step operations (e.g., upload → watermark → read).
- Consider per-IP rate-limiting middleware for login and get-version endpoints.

## 9. Follow-Up / Recommendations
| Priority | Action | Owner | ETA |
|----------|--------|-------|-----|
| High | Configure alert for tatou_login_failures_total rate | SecOps | 1d |
| Medium | Add request ID header & log field | Dev | 2d |
| Medium | Add per-method watermark latency histogram | Dev | 2d |
| Low | Enrich suspicious event reasons (e.g., path traversal) | Dev | 3d |

## 10. Appendix: Data Collection Queries
- Loki query (failed logins): `{container="server"} |~ "Failed login attempt"`
- Loki query (5xx errors): `{container="server"} | json | status >= 500`
- Metrics (curl): `curl -s http://server:5000/metrics | grep tatou_`

---
Template can be updated as new incidents occur.
