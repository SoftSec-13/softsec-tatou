# Discovered Security Bugs (Unfixed)

This document tracks security vulnerabilities discovered through fuzzing that have not yet been fixed.

**Last Updated:** 2025-10-17
**Total Active Vulnerabilities:** 7
**Latest Fuzzing Results:** `fuzzing_results_20251017_111628`
**Analysis Scope:** 12 fuzzing runs; 48 artifacts (34 crashes, 4 OOM, 10 slow/timeout)

---

## Bug #1: REST API Authentication Bypass

- Date: 2025-10-13
- Severity: Critical
- Category: Authentication / Input Validation
- Status: UNFIXED
- Fuzzer: `fuzz_rest_endpoints`
- Artifacts: `fuzz_rest_endpoints_crash-1d2dcbc36fbb6c27761a286b18efa7cef61cf6d5`, `fuzz_rest_endpoints_crash-ac9eaf20fd0ec1062e0ac715cfd0a09c418a7b57`
- Summary: Very long/invalid email/password fields trigger crashes in login, indicating missing length/format validation and potential auth bypass.
- Impact: Unauthorized access, data exposure, service instability.

---

## Bug #2: Workflow Command Injection

- Date: 2025-10-15
- Severity: Critical
- Category: Command Injection / RCE
- Status: UNFIXED
- Fuzzer: `fuzz_workflows`
- Artifact: `fuzz_workflows_crash-63288bf7d7a498a1d5e386a7196f4e454e013af2` (minimal 2-byte input)
- Summary: Minimal input crashes workflow handling; points to unsafe handling of untrusted input in command-like contexts.
- Impact: Potential code execution, full server compromise.

---

## Bug #3: PDF Memory Exhaustion (Huge /Count)

- Date: 2025-10-17
- Severity: High
- Category: DoS / Memory Exhaustion
- Status: UNFIXED
- Fuzzer: `fuzz_pdf_explore`
- Example Artifact: `fuzz_pdf_explore_oom-ce0b7a698ddcd972f38f771da18fc2d0a0edcb63`
- Summary: Malicious PDFs with absurd page `/Count` values cause OOM during parsing.
- Impact: Service crash and availability loss.

---

## Bug #4: PDF Reading Crash (Corrupted Structure)

- Date: 2025-10-17
- Severity: Medium
- Category: Input Validation / Parser Crash
- Status: UNFIXED
- Fuzzer: `fuzz_pdf_read`
- Example Artifact: `fuzz_pdf_read_crash-75bba68137466eed370a9d287d10d5cb3f988076` (more in Artifact Summary)
- Summary: Corrupted headers/xref/objects trigger crashes in watermark reading.
- Impact: 500s during watermark reads; user impact on document access.

---

## Bug #5: PDF Apply Crash (Corrupted Object)

- Date: 2025-10-17
- Severity: Medium
- Category: Input Validation / Parser Crash
- Status: UNFIXED
- Fuzzer: `fuzz_pdf_apply`
- Example Artifact: `fuzz_pdf_apply_crash-4aa9b6af44418258171003c4a6b87580b1b421a3`
- Summary: Incomplete/malformed dictionaries crash watermark application.
- Impact: 500s and potential error leakage.

---

## Bug #6: Performance Degradation (Deep PDF Nesting)

- Date: 2025-10-13
- Severity: Medium
- Category: Algorithmic Complexity / Resource Exhaustion
- Status: UNFIXED
- Fuzzer: `fuzz_pdf_explore`
- Artifacts: 1 timeout, 9 slow-units (see Artifact Summary)
- Summary: Deep page tree nesting causes very slow traversal and timeouts.
- Impact: CPU saturation, request timeouts, degraded service.

---

## Bug #7: Workflow Invariant Failure (Create → Login)

- Date: 2025-10-14
- Severity: Medium
- Category: Workflow Robustness / Endpoint Invariants
- Status: UNFIXED
- Fuzzer: `fuzz_workflows`
- Artifacts: `fuzz_workflows_crash-839c57582662320bd3bc2a5bff93b9d199c12300`, `fuzz_workflows_crash-dd8f40b9cd922391be3926e3fbfdeefb6bac6711`
- Summary: Valid create-user followed by login intermittently violates invariants (unexpected status/content-type, latency, or error leakage).
- Impact: Reliability issues in core auth workflows; potential information disclosure.
