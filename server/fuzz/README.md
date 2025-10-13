# Tatou Fuzzing Suite

**Industry-standard coverage-guided security fuzzing using Atheris (Google's libFuzzer for Python).**

## Overview

White-box security testing to discover:
- 🔒 **Security vulnerabilities** - SQL injection, XSS, SSRF, path traversal, IDOR, auth bypass, JWT flaws
- 💥 **Crashes and exceptions** - Memory corruption, unhandled errors, race conditions
- 🐛 **Edge cases** - Malformed inputs, boundary conditions, type confusion

**Key Features:**
- ✅ Python coverage tracking enabled (`enable_python_coverage=True`)
- ✅ Structure-aware mutations via dictionaries (198-281 tokens per fuzzer)
- ✅ Advanced attack pattern detection (JWT, XXE, NoSQL, SSTI, prototype pollution)
- ✅ Stateful fuzzing for multi-step workflows and IDOR
- ✅ Race condition detection via concurrent requests
- ✅ Enhanced PDF generation (6 strategies: valid, malicious, nested, memory exhaustion)

## Architecture

### Fuzzers

| Fuzzer | Target | Focus | Seeds |
|--------|--------|-------|-------|
| **targets/fuzz_rest_endpoints.py** | REST API endpoints | Auth, IDOR, input validation, SQL injection, XSS, path traversal | 100 |
| **targets/fuzz_pdf_explore.py** | PDF parsing | explore_pdf() function, structure validation, malformed PDFs | 20 |
| **targets/fuzz_pdf_apply.py** | PDF watermarking | apply_watermark(), structural mutations, edge cases | 20 |
| **targets/fuzz_pdf_read.py** | Watermark extraction | read_watermark(), method-specific attacks, crypto validation | 20 |
| **targets/fuzz_workflows.py** | Multi-step workflows | IDOR, session management, race conditions, state transitions | 85 |

### Key Components

```
fuzz/
├── README.md                      # This file
├── Dockerfile                     # Python 3.11 container
├── requirements.txt               # Dependencies
├── targets/                       # Fuzzing targets
│   ├── fuzz_rest_endpoints.py    # REST API endpoint fuzzer
│   ├── fuzz_pdf_explore.py       # PDF exploration fuzzer
│   ├── fuzz_pdf_apply.py         # PDF watermarking fuzzer
│   ├── fuzz_pdf_read.py          # Watermark reading fuzzer
│   └── fuzz_workflows.py         # Multi-step workflow fuzzer
├── harness/                       # Test harness infrastructure
│   ├── app.py                    # Flask app and SQLite DB initialization
│   ├── env.py                    # Environment configuration
│   └── reset.py                  # Cleanup utilities
├── builders/                      # Request builders
│   ├── auth.py                   # Authentication helpers
│   └── rest_builders.py          # REST endpoint builders
├── models/                        # Data models
│   ├── pdf.py                    # PDF input models
│   └── rest.py                   # REST request models
├── oracles/                       # Bug detection oracles
│   ├── invariants.py             # Endpoint invariants and IDOR checks
│   └── security.py               # Security vulnerability detection
├── seeds/                         # Curated seed inputs (version controlled)
│   ├── fuzz_rest_endpoints/      # REST API seeds
│   ├── fuzz_pdf_explore/         # PDF parsing seeds
│   ├── fuzz_pdf_apply/           # Watermarking seeds
│   ├── fuzz_pdf_read/            # Watermark reading seeds
│   └── fuzz_workflows/           # Multi-step workflow seeds
├── corpus/                        # Runtime discoveries (gitignored)
└── scripts/
    └── run_fuzzing_suite.sh       # Orchestrates all 5 fuzzers
```

## How It Works

### 1. Coverage-Guided Fuzzing

```python
with atheris.instrument_imports():
    import server  # ← Code is instrumented for coverage tracking
    import watermarking_utils
```

- Atheris instruments Python bytecode to track which lines are executed
- LibFuzzer uses this coverage feedback to guide mutations
- Inputs that reach new code paths are saved to the corpus
- The corpus grows over time as new paths are discovered

### 2. Security Checks

Each fuzzer includes **vulnerability-specific assertions**:

```python
def check_security_issues(resp, endpoint: str):
    """Detect vulnerabilities in responses."""
    text = resp.get_data(as_text=True).lower()

    # SQL error leakage
    if "syntax error" in text or "mysql" in text:
        raise AssertionError("SQL error leaked!")

    # Path traversal
    if "/etc/" in text or "/var/" in text:
        raise AssertionError("File path leaked!")

    # Stack trace disclosure
    if "traceback" in text:
        raise AssertionError("Stack trace leaked!")
```

When a vulnerability is found, the fuzzer **crashes with an assertion**, saving the input that triggered it.

### 3. Seed Corpus & Runtime Discovery

The fuzzing suite uses a **two-tier corpus strategy**:

#### Seeds (`seeds/` - version controlled)
Human-curated test cases with descriptive names:
- **api_fuzzer/**: `sql_injection_or.bin`, `valid_json_request.bin`
- **inputs_fuzzer/**: `path_traversal_etc_passwd.bin`
- **watermarking_fuzzer/**: `minimal_valid_pdf.bin`
- **stateful_fuzzer/**: `create_user_flow.bin`

**Naming convention:** Use descriptive names explaining what each seed tests (e.g., `xss_script_tag.bin`, not `test1.bin` or random hashes).

#### Runtime Corpus (`corpus/` - gitignored)
Auto-generated during fuzzing:
- Files are **SHA1 hashes** (libFuzzer convention)
- Contains inputs that discovered new code paths
- Grows over time as fuzzer finds interesting mutations
- Examples: `94a1e1be76067891b1ceaa31ce162728c07bb439`

**Why separate?**
- ✅ Seeds remain clean and understandable
- ✅ Runtime discoveries tracked by hash (libFuzzer standard)
- ✅ Seeds in git, runtime corpus ignored
- ✅ Faster bug discovery with quality seeds

The fuzzer reads seeds first (read-only), then writes discoveries to corpus (writable).

### 4. In-Memory Database

The fuzzer creates a SQLite in-memory database with minimal schema:

```python
def init_test_db():
    engine = create_engine("sqlite:///:memory:")
    # Create Users and Documents tables
    # Insert test user for authenticated requests
```

This allows **actual SQL injection testing** without requiring MariaDB.

## Running the Fuzzer

### Quick Start

```bash
# Build the fuzzer container
docker compose build fuzzer

# Run all fuzzers (default: 5 minutes each)
docker compose up fuzzer

# Results saved to server/fuzzing_results_*/
```

### Configuration

Environment variables in `.env` or docker-compose.yml:

| Variable | Default | Description |
|----------|---------|-------------|
| `FUZZ_TIME` | 300 | Seconds per fuzzer |
| `MAX_LEN` | 5000 | Max input size in bytes |
| `FUZZ_WORKERS` | 0 | Parallel workers (0 = auto) |
| `FUZZ_COLLECT_COVERAGE` | 1 | Generate coverage report (set to 0 for speed) |

Example:
```bash
FUZZ_TIME=600 MAX_LEN=10000 docker compose up fuzzer
```

### Run Individual Fuzzers

```bash
# REST API fuzzer
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    fuzz/corpus/fuzz_rest_endpoints/ \
    fuzz/seeds/fuzz_rest_endpoints/ \
    -max_total_time=300 \
    -max_len=5000

# PDF exploration fuzzer
docker compose run --rm fuzzer python fuzz/targets/fuzz_pdf_explore.py \
    fuzz/corpus/fuzz_pdf_explore/ \
    fuzz/seeds/fuzz_pdf_explore/ \
    -max_total_time=300 \
    -max_len=5000

# PDF watermarking fuzzer
docker compose run --rm fuzzer python fuzz/targets/fuzz_pdf_apply.py \
    fuzz/corpus/fuzz_pdf_apply/ \
    fuzz/seeds/fuzz_pdf_apply/ \
    -max_total_time=300 \
    -max_len=5000

# Watermark reading fuzzer
docker compose run --rm fuzzer python fuzz/targets/fuzz_pdf_read.py \
    fuzz/corpus/fuzz_pdf_read/ \
    fuzz/seeds/fuzz_pdf_read/ \
    -max_total_time=300 \
    -max_len=5000

# Multi-step workflow fuzzer
docker compose run --rm fuzzer python fuzz/targets/fuzz_workflows.py \
    fuzz/corpus/fuzz_workflows/ \
    fuzz/seeds/fuzz_workflows/ \
    -max_total_time=300 \
    -max_len=1000

```

### Advanced Options

LibFuzzer flags (see [LibFuzzer docs](https://llvm.org/docs/LibFuzzer.html)):

```bash
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    fuzz/corpus/fuzz_rest_endpoints/ \
    fuzz/seeds/fuzz_rest_endpoints/ \
    -max_total_time=600 \          # Fuzz for 10 minutes
    -max_len=10000 \                # Allow 10KB inputs
    -workers=4 \                    # Use 4 parallel workers
    -jobs=4 \                       # Run 4 jobs
    -print_final_stats=1            # Show statistics at end
```

### Performance Optimization Flags

For **faster fuzzing** and **better resource usage**:

```bash
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    fuzz/corpus/fuzz_rest_endpoints/ \
    fuzz/seeds/fuzz_rest_endpoints/ \
    -max_total_time=3600 \
    -timeout=30 \                   # Kill inputs that hang >30s
    -rss_limit_mb=2048 \            # Limit memory to 2GB (prevent OOM)
    -reduce_inputs=1 \              # Minimize corpus size (removes redundant inputs)
    -fork=4 \                       # Crash-resistant parallel fuzzing
    -ignore_crashes=1 \             # Continue after crashes (for long runs)
    -close_fd_mask=3                # Close stdout/stderr for speed
```

**Corpus management:**

```bash
# Merge and minimize corpus from multiple runs
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    -merge=1 \
    fuzz/corpus/fuzz_rest_endpoints_merged/ \
    fuzz/corpus/fuzz_rest_endpoints/ \
    fuzzing_results_*/corpus/

# This removes duplicate/redundant inputs, keeping only unique coverage
```

## Interpreting Results

### Successful Run

```
=== Tatou Fuzzing Suite ===
Running fuzz_rest_endpoints...
#2      INITED exec/s: 0 rss: 54Mb
#4096   pulse  corp: 12/234b lim: 43 exec/s: 2048
#8192   pulse  corp: 28/1.2kb lim: 80 exec/s: 2730
#16384  pulse  corp: 45/3.4kb lim: 163 exec/s: 2340
✓ fuzz_rest_endpoints completed
```

**Good signs:**
- ✅ Corpus growing (`corp: 45/3.4kb`)
- ✅ High exec/s (>1000 = efficient)
- ✅ No crashes or assertion failures

### Security Findings

```
AssertionError: SQL error leaked in /api/create-user: found 'syntax error'
```

**This is what you want to find!** The fuzzer discovered a vulnerability:
- Input saved to `fuzzing_results_*/fuzz_rest_endpoints_crash-*`
- Reproduce by running that input through the fuzzer
- Fix the bug in the application code
- Re-run fuzzer to verify fix

### Coverage Report

If `FUZZ_COLLECT_COVERAGE=1`:

```
Coverage report: fuzzing_results_*/coverage_report.txt
HTML report:     fuzzing_results_*/htmlcov/index.html
XML report:      fuzzing_results_*/coverage.xml
```

Review coverage to find untested code paths.

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `corp: 1/1b` never grows | No coverage feedback | Check instrumentation in `with atheris.instrument_imports()` |
| `WARNING: no interesting inputs` | Bad seed corpus or uninstrumented code | Add better seeds, verify imports |
| Low exec/s (<100) | Slow operations in fuzzing loop | Profile code, reduce I/O, use mocks |
| No crashes but known bugs | Weak assertions | Add security checks like in `check_security_issues()` |

## Development

### Adding New Fuzzers

1. **Create fuzzer file:** `fuzz/targets/fuzz_newfeature.py`

```python
#!/usr/bin/env python3
"""New feature fuzzer - Description of what it tests."""
from __future__ import annotations

import sys
from pathlib import Path

# Add fuzz directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import atheris

with atheris.instrument_imports():
    from harness import get_app, cleanup_storage
    from builders import build_auth_header
    from oracles import check_endpoint_invariants, check_security_vulnerabilities

def fuzz_one_input(data: bytes) -> None:
    """Fuzz new feature.

    Args:
        data: Raw bytes from fuzzer
    """
    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)
    app = get_app()

    # Build test inputs
    payload = {
        "field": fdp.ConsumeUnicodeNoSurrogates(256)
    }

    try:
        with app.test_client() as client:
            resp = client.post(
                "/api/endpoint",
                json=payload,
                headers={"Authorization": build_auth_header()}
            )

        # Check invariants and security
        check_endpoint_invariants(resp, "/api/endpoint")
        check_security_vulnerabilities(resp, "/api/endpoint")

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise  # Let fuzzer save the crashing input
    except Exception:
        pass  # Expected for malformed inputs
    finally:
        cleanup_storage()

def main() -> None:
    """Entry point for fuzzer."""
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
```

2. **Create seed corpus:** `fuzz/seeds/fuzz_newfeature/`
   - Add descriptive seed files: `valid_request.bin`, `edge_case_empty.bin`, etc.

3. **Add to suite:** Edit `fuzz/scripts/run_fuzzing_suite.sh`:
```bash
FUZZERS=(
  targets/fuzz_pdf_explore
  targets/fuzz_pdf_apply
  targets/fuzz_pdf_read
  targets/fuzz_rest_endpoints
  targets/fuzz_workflows
  targets/fuzz_newfeature  # Add here
)
```

### Improving Seed Corpus

Add realistic inputs that exercise different code paths in `seeds/` directory:

```bash
# Valid inputs
echo '{"email": "user@test.com", "password": "pass123"}' > seeds/fuzz_rest_endpoints/valid_login.bin  # pragma: allowlist secret

# Boundary conditions
echo '{"email": "", "password": "x"}' > seeds/fuzz_rest_endpoints/empty_email.bin

# Attack patterns
echo '{"email": "admin@test.com", "password": "' OR 1=1--"}' > seeds/fuzz_rest_endpoints/sql_injection_password.bin
```

**Best practices for seeds:**
- Use descriptive filenames (not `test1.bin` or hashes)
- Cover attack vectors (SQLi, XSS, path traversal)
- Include at least one completely valid input
- Add edge cases (empty, very long, boundary values)
- Quality > quantity (10-20 good seeds better than 1000 random ones)

### Enhancing Vulnerability Detection

Add more comprehensive security checks to catch additional vulnerability classes:

```python
def check_security_issues(resp, endpoint: str) -> None:
    """Enhanced vulnerability detection."""
    text = resp.get_data(as_text=True).lower()

    # SQL injection indicators
    sql_patterns = [
        "syntax error", "mysql", "mariadb", "sqlalchemy",
        "select * from", "table ", "column ", "sql", "query failed",
        "duplicate entry", "unknown column", "operand should contain"
    ]

    # XSS indicators (reflected in response)
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]

    # Command injection indicators
    cmd_patterns = ["/bin/sh", "/bin/bash", "sh -c", "cmd.exe", "; ls"]

    # SSRF indicators (internal URLs in response)
    ssrf_patterns = ["localhost", "127.0.0.1", "169.254.169.254", "metadata"]

    # Deserialization indicators
    deser_patterns = ["pickle", "dill", "yaml.load", "__reduce__"]

    # Path traversal success indicators
    path_patterns = [
        "/etc/passwd", "/etc/shadow", "root:x:",
        "/var/", "/proc/", "c:\\windows", "system32"
    ]

    for pattern in sql_patterns:
        if pattern in text:
            raise AssertionError(f"SQL vulnerability: {pattern} in {endpoint}")

    for pattern in xss_patterns:
        if pattern in text:
            raise AssertionError(f"XSS vulnerability: {pattern} in {endpoint}")

    # Check for authentication/authorization bypasses
    if endpoint not in ["/healthz", "/api/get-watermarking-methods"]:
        if resp.status_code == 200:
            auth = resp.request.headers.get("Authorization", "")
            if not auth or not auth.startswith("Bearer "):
                raise AssertionError(f"Auth bypass possible on {endpoint}")

    # Check for excessive error details
    if resp.status_code >= 500:
        if any(p in text for p in ["file ", "line ", ".py", "traceback"]):
            raise AssertionError(f"Stack trace leaked in {endpoint}")
```

**Key improvements:**
- ✅ **Broader SQL injection detection** - more error patterns
- ✅ **XSS detection** - catches reflected scripts
- ✅ **Command injection detection** - shell execution patterns
- ✅ **SSRF detection** - internal network access
- ✅ **Deserialization detection** - unsafe deserialization
- ✅ **Path traversal success** - actual file content leakage

### Creating Dictionaries

Dictionaries guide mutations toward interesting values:

```bash
# fuzz/api.dict
"email"
"password"
"login"
"' OR '1'='1"
"admin"
"root"
"<script>"
"../../../"
"%PDF-1.7"
"%%EOF"
```

Use with: `-dict=fuzz/api.dict`

## Integration with CI/CD

### GitHub Actions

```yaml
name: Fuzzing
on: [push, pull_request]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build fuzzer
        run: docker compose build fuzzer
      - name: Run fuzzing suite
        run: |
          FUZZ_TIME=120 docker compose run --rm fuzzer
      - name: Upload artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzzing-crashes
          path: server/fuzzing_results_*/*crash-*
```

### Continuous Fuzzing

For long-running fuzzing (24/7):

```bash
# Run indefinitely, restarting on completion
while true; do
    FUZZ_TIME=3600 docker compose run --rm fuzzer
    sleep 60
done
```

Save corpus between runs:
```bash
docker compose run --rm \
    -v ./persistent_corpus:/app/fuzz/corpus \
    fuzzer
```

## Best Practices

### Do:
- ✅ **Import all code inside `with atheris.instrument_imports()`**
- ✅ **Add security-specific assertions** (not just crash detection)
- ✅ **Create diverse seed corpus** covering different code paths
- ✅ **Run regularly** (CI/CD, pre-release, nightly)
- ✅ **Review coverage reports** to find untested code
- ✅ **Fix bugs immediately** when discovered

### Don't:
- ❌ Import code outside instrumentation block (no coverage feedback)
- ❌ Catch all exceptions without re-raising (hides bugs)
- ❌ Run without seed corpus (slow convergence)
- ❌ Ignore assertion failures (these are vulnerabilities!)
- ❌ Run only once (fuzzing is most effective over time)

## Troubleshooting

### "WARNING: Failed to find function __sanitizer_*"

**Normal.** These warnings are expected with Atheris and don't affect fuzzing.

### "No interesting inputs were found"

**Check instrumentation:**
```python
# BAD
with atheris.instrument_imports():
    pass
import server  # Not instrumented!

# GOOD
with atheris.instrument_imports():
    import server  # Instrumented!
```

### Fuzzer is very slow (exec/s < 100)

**Profile and optimize:**
- Remove expensive operations from fuzzing loop
- Use mocks for external dependencies (DB, network)
- Reduce input size with `-max_len=1000`
- Disable coverage collection: `FUZZ_COLLECT_COVERAGE=0`

### Found a bug - now what?

1. **Reproduce:** Run the crash-* artifact through the fuzzer
```bash
# Replay the exact crashing input
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    fuzzing_results_*/fuzz_rest_endpoints_crash-abc123
```

2. **Minimize:** Shrink the input to its minimal form
```bash
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    fuzzing_results_*/fuzz_rest_endpoints_crash-abc123 \
    -minimize_crash=1 \
    -exact_artifact_path=minimal_crash
```

3. **Debug:** Examine the input and stack trace
```bash
# View the crashing input
xxd fuzzing_results_*/fuzz_rest_endpoints_crash-abc123

# Run with Python debugger
docker compose run --rm fuzzer python -m pdb fuzz/targets/fuzz_rest_endpoints.py \
    fuzzing_results_*/fuzz_rest_endpoints_crash-abc123
```

4. **Fix:** Patch the vulnerability in application code

5. **Verify:** Re-run fuzzer to confirm it's fixed
```bash
# Should not crash anymore
docker compose run --rm fuzzer python fuzz/targets/fuzz_rest_endpoints.py \
    fuzzing_results_*/fuzz_rest_endpoints_crash-abc123

# Run full fuzzer to ensure no regressions
FUZZ_TIME=600 docker compose up fuzzer
```

6. **Regression test:** Add the crash input to the test suite
```python
# test/test_security.py
def test_crash_abc123_fixed():
    """Regression test for crash-abc123."""
    with open("fuzz/corpus/regression/crash-abc123", "rb") as f:
        data = f.read()
    # Should not raise
    result = vulnerable_function(data)
    assert result is not None
```

### Performance Benchmarks

Expected performance on modern hardware (4-core CPU, 8GB RAM):

| Fuzzer | exec/s | corpus/hour | Resource |
|--------|--------|-------------|----------|
| fuzz_rest_endpoints | 100-200 | +40 inputs | Medium (DB + validation) |
| fuzz_pdf_explore | 150-300 | +20 inputs | Heavy (PDF parsing) |
| fuzz_pdf_apply | 40-80 | +15 inputs | Very Heavy (watermarking) |
| fuzz_pdf_read | 100-200 | +20 inputs | Heavy (extraction) |
| fuzz_workflows | 20-40 | +30 inputs | Very Heavy (multi-step) |

**Factors affecting performance:**
- ✅ **Fast:** Simple input validation, pure computation
- ⚠️ **Medium:** Database queries, file I/O, authentication
- ❌ **Slow:** PDF parsing, cryptography, network operations

**Optimization tips:**
- Use in-memory SQLite instead of real MariaDB (already done)
- Mock expensive operations (network, crypto) where possible
- Use `-timeout=30` to skip hanging inputs
- Run with `-close_fd_mask=3` to reduce I/O overhead

### Resource Requirements

| Duration | CPU | RAM | Disk | Expected Findings |
|----------|-----|-----|------|-------------------|
| Quick test (5min) | 1-2 cores | 1GB | 100MB | Obvious bugs |
| Standard run (1hr) | 4 cores | 4GB | 500MB | Most vulnerabilities |
| Deep fuzz (24hr) | 8+ cores | 8GB | 2GB | Edge cases, rare bugs |
| Continuous (7d) | 16+ cores | 16GB | 10GB | All discoverable bugs |

**Storage:**
- Corpus: ~10-50MB per fuzzer after 24hr
- Logs: ~100-500MB per day
- Crashes: ~1KB-1MB per bug found

## Why This Approach?

### Comparison with Alternatives

| Approach | Coverage-Guided | Security Focus | Speed | Maintenance | Cost |
|----------|-----------------|----------------|-------|-------------|------|
| **This fuzzer** | ✅ Yes | ✅ Yes | ✅ Fast | ✅ Low | Free |
| Manual testing | ❌ No | ⚠️ Limited | ❌ Slow | ❌ High | $$ |
| Unit tests | ⚠️ Partial | ⚠️ Depends | ✅ Fast | ⚠️ Medium | Free |
| Black-box fuzzing | ❌ No | ⚠️ Crashes only | ⚠️ Medium | ✅ Low | Free |
| Property testing (Hypothesis) | ⚠️ Partial | ⚠️ Depends | ✅ Fast | ⚠️ Medium | Free |
| Commercial tools (Synopsys, Veracode) | ✅ Yes | ✅ Yes | ✅ Fast | ❌ Vendor lock-in | $$$$ |

**Key Advantages:**
- ✅ **Free and open-source** - No licensing costs
- ✅ **Integrated with codebase** - Understands your code structure
- ✅ **Customizable security checks** - Tailor detection to your threats
- ✅ **Coverage-guided** - Smart mutations, not random chaos
- ✅ **Security-focused** - Finds vulnerabilities, not just crashes
- ✅ **CI/CD ready** - Automated testing on every commit

**Known Limitations:**
- ⚠️ **Python-specific** - Requires Atheris (libFuzzer for Python)
- ⚠️ **Python 3.11 only** - Atheris doesn't support 3.12+ yet
- ⚠️ **CPU-intensive** - Long runs need compute resources
- ⚠️ **Manual corpus curation** - Seed inputs improve effectiveness

## Resources

- [Atheris Documentation](https://github.com/google/atheris)
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [Fuzzing Book](https://www.fuzzingbook.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Google's OSS-Fuzz](https://github.com/google/oss-fuzz)

## License

Part of the Tatou project - for educational use only.
