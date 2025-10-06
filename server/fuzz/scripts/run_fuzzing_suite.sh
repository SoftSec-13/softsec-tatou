#!/usr/bin/env bash
# Run Tatou fuzzing suite
set -euo pipefail

# Configuration
FUZZ_TIME="${FUZZ_TIME:-300}"
MAX_LEN="${MAX_LEN:-5000}"
OUTPUT_DIR="${OUTPUT_DIR:-fuzzing_results_$(date +%Y%m%d_%H%M%S)}"
WORKERS="${FUZZ_WORKERS:-$(nproc 2>/dev/null || echo 1)}"
COLLECT_COVERAGE="${FUZZ_COLLECT_COVERAGE:-1}"

mkdir -p "${OUTPUT_DIR}"

echo "=== Tatou Fuzzing Suite ==="
echo "Time per fuzzer: ${FUZZ_TIME}s"
echo "Max input: ${MAX_LEN} bytes"
echo "Workers: ${WORKERS}"
echo "Output: ${OUTPUT_DIR}"
echo "Coverage: ${COLLECT_COVERAGE}"
echo

# Fuzzers to run
FUZZERS=(
  fuzz_api
  fuzz_watermarking
  fuzz_inputs
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
  echo "Running ${fuzzer}..."
  log="${OUTPUT_DIR}/${fuzzer}.log"
  corpus_dir="fuzz/corpus/${fuzzer}"

  # Create corpus dir if missing
  mkdir -p "${corpus_dir}"

  set +e
  timeout $((FUZZ_TIME + 60)) ${COV_CMD} "fuzz/${fuzzer}.py" \
    "${corpus_dir}" \
    -max_total_time="${FUZZ_TIME}" \
    -max_len="${MAX_LEN}" \
    -workers="${WORKERS}" \
    -jobs="${WORKERS}" \
    -artifact_prefix="${OUTPUT_DIR}/${fuzzer}_" \
    -print_final_stats=1 \
    2>&1 | tee "${log}"

  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    echo "✗ ${fuzzer} exited with status ${status}"
    failures=$((failures + 1))
  else
    echo "✓ ${fuzzer} completed"
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
