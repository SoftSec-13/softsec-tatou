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

# Fuzzing targets with per-target configurations
# Format: "fuzzer_path:timeout:max_len"
FUZZERS=(
  "targets/fuzz_rest_endpoints:10:5000"
  "targets/fuzz_pdf_explore:20:50000"
  "targets/fuzz_pdf_read:20:50000"
  "targets/fuzz_pdf_apply:30:100000"
  "targets/fuzz_workflows:30:100000"
)

# Setup coverage
if [[ "${COLLECT_COVERAGE}" == "1" ]]; then
  python -m coverage erase 2>/dev/null || true
  COV_CMD="python -m coverage run --parallel-mode"
else
  COV_CMD="python"
fi

failures=0

# Run each fuzzer with per-target configuration
for fuzzer_config in "${FUZZERS[@]}"; do
  # Parse fuzzer configuration: "path:timeout:max_len"
  IFS=':' read -r fuzzer target_timeout target_max_len <<< "${fuzzer_config}"

  # Extract fuzzer name (handle targets/ prefix)
  fuzzer_name="${fuzzer##*/}"
  fuzzer_base="${fuzzer_name%.py}"

  # Use target-specific values or defaults
  FUZZ_TIMEOUT_VAL="${target_timeout:-${TIMEOUT}}"
  FUZZ_MAX_LEN_VAL="${target_max_len:-${MAX_LEN}}"

  echo "Running ${fuzzer_name} (timeout=${FUZZ_TIMEOUT_VAL}s, max_len=${FUZZ_MAX_LEN_VAL})..."
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

  # Add fuzzer options with target-specific values
  fuzz_cmd+=(
    -max_total_time="${FUZZ_TIME}"
    -max_len="${FUZZ_MAX_LEN_VAL}"
    -timeout="${FUZZ_TIMEOUT_VAL}"
    -rss_limit_mb="${RSS_LIMIT_MB}"
    -workers="${WORKERS}"
    -jobs="${WORKERS}"
    -artifact_prefix="${OUTPUT_DIR}/${fuzzer_base}_"
    -print_final_stats=1
    -close_fd_mask=3
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

# Check for crashes and perform triage
echo
echo "=== Crash Triage ==="
crashes=$(find "${OUTPUT_DIR}" -name "*crash-*" -o -name "*oom-*" -o -name "*timeout-*" 2>/dev/null | wc -l)

if [[ $crashes -gt 0 ]]; then
  echo "⚠️  Found $crashes crash artifacts"
  echo "Minimizing and triaging crashes..."

  # Create triage directory
  mkdir -p "${OUTPUT_DIR}/triage"

  # Track unique crash buckets
  declare -A crash_buckets

  # Process each crash artifact
  for artifact in "${OUTPUT_DIR}"/*crash-* "${OUTPUT_DIR}"/*oom-* "${OUTPUT_DIR}"/*timeout-*; do
    if [[ ! -f "${artifact}" ]]; then
      continue
    fi

    artifact_name=$(basename "${artifact}")
    echo "  Processing ${artifact_name}..."

    # Extract fuzzer name from artifact (format: fuzzer_crash-hash or fuzzer_oom-hash)
    if [[ "${artifact_name}" =~ ^([^_]+)_(crash|oom|timeout)-(.+)$ ]]; then
      fuzzer_name="${BASH_REMATCH[1]}"
      crash_type="${BASH_REMATCH[2]}"
      crash_hash="${BASH_REMATCH[3]}"
    else
      echo "    ⚠ Could not parse artifact name, skipping minimization"
      continue
    fi

    # Try to minimize the crash
    fuzzer_path="fuzz/targets/${fuzzer_name}.py"
    if [[ -f "${fuzzer_path}" ]]; then
      minimized="${OUTPUT_DIR}/triage/${artifact_name}.min"
      echo "    Minimizing to ${minimized}..."

      set +e
      timeout 60 python "${fuzzer_path}" "${artifact}" \
        -minimize_crash=1 \
        -exact_artifact_path="${minimized}" \
        -max_total_time=30 \
        2>&1 | grep -E "CRASH_MIN|ERROR" > "${OUTPUT_DIR}/triage/${artifact_name}.log" || true
      set -e

      # If minimization succeeded, use minimized version for bucketing
      if [[ -f "${minimized}" ]]; then
        echo "    ✓ Minimized: $(wc -c < "${minimized}") bytes (original: $(wc -c < "${artifact}") bytes)"
        bucket_artifact="${minimized}"
      else
        echo "    ✗ Minimization failed, using original"
        bucket_artifact="${artifact}"
      fi
    else
      echo "    ⚠ Fuzzer ${fuzzer_path} not found, skipping minimization"
      bucket_artifact="${artifact}"
    fi

    # Create crash bucket signature (fuzzer + crash_type + first line of error)
    # This is a simplified bucketing; production systems use stack hashing
    bucket_key="${fuzzer_name}_${crash_type}"
    crash_buckets["${bucket_key}"]=$((${crash_buckets["${bucket_key}"]:-0} + 1))
  done

  # Generate triage summary
  summary_file="${OUTPUT_DIR}/triage/summary.txt"
  echo "=== Crash Triage Summary ===" > "${summary_file}"
  echo "Total artifacts: $crashes" >> "${summary_file}"
  echo "Unique buckets: ${#crash_buckets[@]}" >> "${summary_file}"
  echo "" >> "${summary_file}"
  echo "Crashes by fuzzer and type:" >> "${summary_file}"

  for bucket in "${!crash_buckets[@]}"; do
    count="${crash_buckets[$bucket]}"
    echo "  ${bucket}: ${count}" >> "${summary_file}"
  done

  echo "" >> "${summary_file}"
  echo "Minimized artifacts saved to: ${OUTPUT_DIR}/triage/" >> "${summary_file}"
  echo "Review crash logs: ls ${OUTPUT_DIR}/triage/*.log" >> "${summary_file}"

  cat "${summary_file}"
  echo
  echo "⚠️  Fuzzing completed with crashes - see ${summary_file}"
  exit 1
fi

echo "✓ No crashes detected"

echo
if [[ $failures -gt 0 ]]; then
  echo "⚠️  Completed with $failures failures"
  exit 1
else
  echo "✓ All fuzzers completed successfully"
  echo "Results: ${OUTPUT_DIR}"
  exit 0
fi
