#!/usr/bin/env bash
# Run Tatou fuzzing suite
set -euo pipefail

# Configuration
FUZZ_TIME="${FUZZ_TIME:-300}"
MAX_LEN="${MAX_LEN:-5000}"
TIMEOUT="${FUZZ_TIMEOUT:-30}"
RSS_LIMIT_MB="${FUZZ_RSS_LIMIT_MB:-2048}"
OUTPUT_DIR="${OUTPUT_DIR:-fuzzing_results_$(date +%Y%m%d_%H%M%S)}"
WORKERS="${FUZZ_WORKERS:-$(nproc 2>/dev/null || echo 1)}"
COLLECT_COVERAGE="${FUZZ_COLLECT_COVERAGE:-1}"

mkdir -p "${OUTPUT_DIR}/targets"

echo "=== Tatou Fuzzing Suite ==="
echo "Time per fuzzer: ${FUZZ_TIME}s"
echo "Max input: ${MAX_LEN} bytes"
echo "Workers: ${WORKERS}"
echo "Output: ${OUTPUT_DIR}"
echo "Coverage: ${COLLECT_COVERAGE}"
echo

# Fuzzing targets
FUZZERS=(
  targets/fuzz_pdf_explore
  targets/fuzz_pdf_apply
  targets/fuzz_pdf_read
  targets/fuzz_rest_endpoints
  targets/fuzz_workflows
)

# Setup coverage
if [[ "${COLLECT_COVERAGE}" == "1" ]]; then
  python -m coverage erase 2>/dev/null || true
  COV_CMD="python -m coverage run --parallel-mode"
else
  COV_CMD="python"
fi

failures=0

# Run each fuzzer
for fuzzer in "${FUZZERS[@]}"; do
  # Extract fuzzer name (handle targets/ prefix)
  fuzzer_name="${fuzzer##*/}"
  fuzzer_base="${fuzzer_name%.py}"

  echo "Running ${fuzzer_name}..."
  log="${OUTPUT_DIR}/${fuzzer_base}.log"
  corpus_dir="fuzz/corpus/${fuzzer_base}"
  seeds_dir="fuzz/seeds/${fuzzer_base}"
  dict_file="fuzz/dictionaries/${fuzzer_base}.dict"

  # Create corpus dir if missing
  mkdir -p "${corpus_dir}"

  # Build fuzzer command with corpus (writable) and seeds (read-only)
  # Add 120s overhead for instrumentation (atheris startup is slow)
  fuzz_cmd=(
    timeout $((FUZZ_TIME + 120)) ${COV_CMD} "fuzz/${fuzzer}.py"
    "${corpus_dir}"
  )

  # Add seeds directory if it exists
  if [[ -d "${seeds_dir}" ]]; then
    fuzz_cmd+=("${seeds_dir}")
    echo "  Using seeds: ${seeds_dir}"
  fi

  # Add fuzzer options
  fuzz_cmd+=(
    -max_total_time="${FUZZ_TIME}"
    -max_len="${MAX_LEN}"
    -timeout="${TIMEOUT}"
    -rss_limit_mb="${RSS_LIMIT_MB}"
    -workers="${WORKERS}"
    -jobs="${WORKERS}"
    -artifact_prefix="${OUTPUT_DIR}/${fuzzer_base}_"
    -print_final_stats=1
  )

  # Add dictionary if it exists
  if [[ -f "${dict_file}" ]]; then
    fuzz_cmd+=(-dict="${dict_file}")
    echo "  Using dictionary: ${dict_file}"
  fi

  set +e
  "${fuzz_cmd[@]}" 2>&1 | tee "${log}"

  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    echo "✗ ${fuzzer_name} exited with status ${status}"
    failures=$((failures + 1))
  else
    echo "✓ ${fuzzer_name} completed"
  fi
  echo
done

# Generate coverage report
if [[ "${COLLECT_COVERAGE}" == "1" ]]; then
  echo "Generating coverage report..."
  if python -m coverage combine 2>/dev/null; then
    python -m coverage report -m > "${OUTPUT_DIR}/coverage_report.txt"
    python -m coverage xml -o "${OUTPUT_DIR}/coverage.xml"
    python -m coverage html -d "${OUTPUT_DIR}/htmlcov"
    echo "✓ Coverage report generated"
  else
    echo "⚠ No coverage data collected"
  fi
fi

# Check for crashes
crashes=$(find . -maxdepth 1 -name "crash-*" -o -name "oom-*" -o -name "timeout-*" 2>/dev/null | wc -l)
if [[ $crashes -gt 0 ]]; then
  echo
  echo "⚠️  CRASHES DETECTED: $crashes artifacts"
  mv crash-* oom-* timeout-* "${OUTPUT_DIR}/" 2>/dev/null || true
  exit 1
fi

echo
if [[ $failures -gt 0 ]]; then
  echo "⚠️  Completed with $failures failures"
  exit 1
else
  echo "✓ All fuzzers completed successfully"
  echo "Results: ${OUTPUT_DIR}"
  exit 0
fi
