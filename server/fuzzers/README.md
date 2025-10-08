# Fuzzing Infrastructure

This directory contains fuzzers for the Tatou PDF watermarking platform, using the [Atheris](https://github.com/google/atheris) fuzzing framework.

## Overview

The fuzzing infrastructure tests the robustness of the PDF watermarking system against malformed, edge-case, and potentially malicious inputs.

## Fuzzers

### 1. `fuzz_watermarking.py`
Tests all watermarking methods with various PDF inputs:
- Valid PDFs with different structures
- Malformed PDFs (missing headers, corrupted objects, etc.)
- Edge cases (empty files, single bytes, etc.)
- Different PDF versions (1.0 through 2.0)

**Seed corpus:** 120 carefully crafted PDF files in `seeds/watermarking/`

### 2. `fuzz_pdf_exploration.py`
Tests the PDF parsing and exploration logic:
- Tests the `explore_pdf` function with various inputs
- Validates handling of malformed PDF structures
- Checks for crashes and unexpected behavior

**Seed corpus:** 120 PDF files in `seeds/pdf_exploration/`

## Seed Corpus

The seed files (120 per fuzzer, 240 total) cover:

### Valid PDFs
- Minimal valid PDFs (different versions: 1.0, 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 2.0)
- PDFs with metadata (Info dictionary, XMP metadata)
- PDFs with pages (1, 2, 5 pages)
- PDFs with annotations
- PDFs with content streams and fonts
- PDFs with cross-reference tables and streams
- PDFs with various features (encryption, embedded files, forms, JavaScript, etc.)

### Edge Cases
- Empty files
- Single/two bytes
- Header only
- Header with EOF
- Very large version numbers
- Very large object numbers
- Large content (1KB)

### Malformed PDFs
- Missing or corrupted headers
- Missing or corrupted EOF markers
- Missing endobj markers
- Duplicate object numbers
- Invalid object numbers
- Unclosed dictionaries
- Wrong stream lengths
- Missing endstream markers

### Special Cases
- PDFs with null bytes
- PDFs with high bytes and Unicode
- Different line endings (CR, LF, CRLF, mixed)
- Binary data in comments
- Various whitespace patterns
- Circular and self-references
- Compressed objects
- Incremental updates

## Installation

Install the fuzzing dependencies:

```bash
cd server
pip install -e ".[dev]"
```

This will install `atheris` along with other development dependencies.

## Usage

### Running Individual Fuzzers

Run the watermarking fuzzer:
```bash
cd server/fuzzers
python3 fuzz_watermarking.py
```

Run the PDF exploration fuzzer:
```bash
cd server/fuzzers
python3 fuzz_pdf_exploration.py
```

### Fuzzing Options

Atheris supports various command-line options:

```bash
# Run for a specific number of iterations
python3 fuzz_watermarking.py -atheris_runs=10000

# Set a timeout per test case (in seconds)
python3 fuzz_watermarking.py -timeout=60

# Use multiple workers
python3 fuzz_watermarking.py -workers=4

# Specify output corpus directory
python3 fuzz_watermarking.py -artifact_prefix=crashes/
```

### Quick Test Run

To verify the fuzzers work correctly with seeds:

```bash
cd server/fuzzers
./run_fuzzers.sh
```

## Seed Generation

To regenerate the seed corpus:

```bash
cd server/fuzzers
python3 generate_seeds.py
```

This will create 120 PDF files in each of:
- `seeds/watermarking/`
- `seeds/pdf_exploration/`

## What the Fuzzers Test

### Watermarking Fuzzer
1. **is_watermarking_applicable**: Tests if the method can handle checking applicability on malformed PDFs
2. **add_watermark**: Tests embedding watermarks in various PDF structures
3. **read_secret**: Tests extracting watermarks from potentially corrupted PDFs

The fuzzer uses input bytes to:
- Select which watermarking method to test
- Choose which operation to perform
- Extract test parameters (key, secret)
- Provide PDF data (with automatic header addition if missing)

### PDF Exploration Fuzzer
- Tests the `explore_pdf` function with various malformed inputs
- Validates that the returned structure is correct (dict with expected keys)
- Catches crashes, hangs, and unexpected exceptions

## Interpreting Results

### Normal Operation
The fuzzer will report:
- Number of executions
- Coverage information
- Corpus size

### Finding Bugs
If a crash or bug is found:
1. Atheris will report the crash
2. A crashing input will be saved to disk
3. You can reproduce the crash by running: `python3 fuzz_watermarking.py <crash_file>`

### Coverage Tracking
Atheris automatically tracks code coverage and will:
- Explore new code paths
- Generate inputs that increase coverage
- Build a corpus of interesting test cases

## Best Practices

1. **Start with seeds**: Always use the seed corpus - it provides good initial coverage
2. **Run regularly**: Integrate fuzzing into CI/CD
3. **Monitor coverage**: Check that fuzzing is exploring new code paths
4. **Fix crashes promptly**: Each crash could indicate a security vulnerability
5. **Update seeds**: When adding new PDF features, add corresponding seed files

## Continuous Fuzzing

For long-running fuzzing campaigns:

```bash
# Run indefinitely with periodic stats
python3 fuzz_watermarking.py -max_total_time=3600  # 1 hour

# Save corpus for future runs
mkdir -p corpus_out
python3 fuzz_watermarking.py corpus_out/
```

## Integration with OSS-Fuzz

This fuzzing infrastructure can be integrated with [OSS-Fuzz](https://github.com/google/oss-fuzz) for continuous fuzzing:

1. The fuzzers follow OSS-Fuzz conventions
2. Seeds are in the standard `seeds/` directory structure
3. Entry points use the standard `TestOneInput` signature

## Troubleshooting

### "Could not import watermarking modules"
Make sure you've installed the package:
```bash
cd server
pip install -e ".[dev]"
```

### "No seed files found"
Run the seed generation script:
```bash
cd server/fuzzers
python3 generate_seeds.py
```

### Fuzzer runs but finds no issues
This is expected! The code is designed to handle edge cases. The fuzzer is still valuable for:
- Ensuring no crashes occur
- Building a corpus of test cases
- Increasing code coverage
- Finding performance issues

## Contributing

When adding new fuzzing targets:

1. Create a new `fuzz_*.py` file
2. Add a corresponding seeds directory
3. Create comprehensive seed files (aim for 100+)
4. Update this README
5. Add the fuzzer to `run_fuzzers.sh`

## References

- [Atheris Documentation](https://github.com/google/atheris)
- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
- [Fuzzing Best Practices](https://github.com/google/fuzzing/blob/master/docs/good-fuzz-target.md)
