# Tatou Fuzzing Suite

**Industry-standard coverage-guided security fuzzing using Atheris (Google's libFuzzer for Python).**

## Overview

White-box security testing to discover:
- 🔒 **Security vulnerabilities** - SQL injection, XSS, SSRF, path traversal, IDOR, auth bypass, JWT flaws
- 💥 **Crashes and exceptions** - Memory corruption, unhandled errors, unexpected state transitions
- 🐛 **Edge cases** - Malformed inputs, boundary conditions, type confusion

**Key Features:**
- ✅ Python coverage tracking enabled (`enable_python_coverage=True`)
- ✅ Structure-aware mutations via dictionaries (198-281 tokens per fuzzer)
- ✅ Advanced attack pattern detection (JWT, XXE, NoSQL, SSTI, prototype pollution)
- ✅ Stateful fuzzing for multi-step workflows and IDOR
- ✅ Enhanced PDF generation (6 strategies: valid, malicious, nested, memory exhaustion)

## Architecture

### Fuzzers

| Fuzzer | Target | Focus | Seeds |
|--------|--------|-------|-------|
| **targets/fuzz_rest_endpoints.py** | REST API endpoints | Auth, IDOR, input validation, SQL injection, XSS, path traversal | 100 |
| **targets/fuzz_pdf_explore.py** | PDF parsing | explore_pdf() function, structure validation, malformed PDFs | 20 |
| **targets/fuzz_pdf_apply.py** | PDF watermarking | apply_watermark(), structural mutations, edge cases | 20 |
| **targets/fuzz_pdf_read.py** | Watermark extraction | read_watermark(), method-specific attacks, crypto validation | 20 |
| **targets/fuzz_workflows.py** | Multi-step workflows | IDOR, session management, state transitions | 60 |

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

## Integration with CI/CD
Fuzzing could be integrated into CI/CD. It will use quite a bit of resource time so that is something to think about.

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

## Why This Approach?

### Comparison with Alternatives

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
