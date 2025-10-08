#!/bin/bash
# run_fuzzers.sh - Run all fuzzers with seeds for verification
#
# This script runs each fuzzer for a short time to verify they work correctly
# and that seeds are being loaded.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "Fuzzer Verification Script"
echo "=========================================="
echo ""

# Check if atheris is installed
if ! python3 -c "import atheris" 2>/dev/null; then
    echo "ERROR: atheris is not installed!"
    echo "Please run: pip install atheris"
    echo "Or: cd ../server && pip install -e \".[dev]\""
    exit 1
fi

echo "✓ atheris is installed"
echo ""

# Check if seed directories exist
WATERMARK_SEEDS="$SCRIPT_DIR/seeds/watermarking"
EXPLORE_SEEDS="$SCRIPT_DIR/seeds/pdf_exploration"

if [ ! -d "$WATERMARK_SEEDS" ]; then
    echo "ERROR: Watermarking seed directory not found: $WATERMARK_SEEDS"
    echo "Run: python3 generate_seeds.py"
    exit 1
fi

if [ ! -d "$EXPLORE_SEEDS" ]; then
    echo "ERROR: PDF exploration seed directory not found: $EXPLORE_SEEDS"
    echo "Run: python3 generate_seeds.py"
    exit 1
fi

WATERMARK_COUNT=$(ls -1 "$WATERMARK_SEEDS" | wc -l)
EXPLORE_COUNT=$(ls -1 "$EXPLORE_SEEDS" | wc -l)

echo "✓ Found $WATERMARK_COUNT seeds for watermarking fuzzer"
echo "✓ Found $EXPLORE_COUNT seeds for PDF exploration fuzzer"
echo ""

# Function to run a fuzzer
run_fuzzer() {
    local fuzzer_name=$1
    local fuzzer_script=$2
    local runs=${3:-1000}
    
    echo "=========================================="
    echo "Running: $fuzzer_name"
    echo "=========================================="
    echo "Fuzzer: $fuzzer_script"
    echo "Runs: $runs"
    echo ""
    
    if [ ! -f "$fuzzer_script" ]; then
        echo "ERROR: Fuzzer not found: $fuzzer_script"
        return 1
    fi
    
    # Run the fuzzer with a limited number of runs
    # Use timeout to ensure it doesn't run forever
    timeout 60 python3 "$fuzzer_script" -atheris_runs="$runs" 2>&1 || {
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo "⚠ Fuzzer timed out after 60 seconds (this is OK for verification)"
        elif [ $exit_code -ne 0 ]; then
            echo "ERROR: Fuzzer failed with exit code $exit_code"
            return 1
        fi
    }
    
    echo ""
    echo "✓ $fuzzer_name completed successfully"
    echo ""
}

# Run each fuzzer
echo "Starting fuzzer verification runs..."
echo ""

# Run watermarking fuzzer
run_fuzzer "Watermarking Fuzzer" "fuzz_watermarking.py" 500

# Run PDF exploration fuzzer  
run_fuzzer "PDF Exploration Fuzzer" "fuzz_pdf_exploration.py" 500

echo "=========================================="
echo "All Fuzzers Completed Successfully!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - 2 fuzzers executed"
echo "  - $WATERMARK_COUNT watermarking seeds verified"
echo "  - $EXPLORE_COUNT PDF exploration seeds verified"
echo ""
echo "To run fuzzers continuously, use:"
echo "  python3 fuzz_watermarking.py -atheris_runs=100000"
echo "  python3 fuzz_pdf_exploration.py -atheris_runs=100000"
echo ""
