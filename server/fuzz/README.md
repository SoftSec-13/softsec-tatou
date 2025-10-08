# Tatou Fuzzing Infrastructure

This directory contains coverage-guided fuzz testing for the Tatou PDF watermarking platform.

## Overview

Three specialized fuzzers target different attack surfaces:

1. **API Fuzzer** (`api_fuzzer.py`): Tests REST API endpoints for injection attacks, auth bypass, and malformed requests
2. **Inputs Fuzzer** (`inputs_fuzzer.py`): Tests input validation for path traversal, overflows, and special characters
3. **Watermarking Fuzzer** (`watermarking_fuzzer.py`): Tests PDF processing with malformed, encrypted, and edge-case PDFs

## Structure

```
fuzz/
├── api_fuzzer.py              # API endpoint fuzzer
├── inputs_fuzzer.py           # Input validation fuzzer
├── watermarking_fuzzer.py     # PDF watermarking fuzzer
├── dictionaries/              # Seed dictionaries for each fuzzer
│   ├── api_fuzzer.dict
│   ├── inputs_fuzzer.dict
│   └── watermarking_fuzzer.dict
├── corpus/                    # Seed corpus (100+ seeds per fuzzer)
│   ├── fuzz_api/             # API attack patterns
│   ├── fuzz_inputs/          # Input validation patterns
│   └── fuzz_watermarking/    # PDF variants
└── README.md                  # This file
```

## Usage

### Running Individual Fuzzers

```bash
# API fuzzer
python3 server/fuzz/api_fuzzer.py -dict=server/fuzz/dictionaries/api_fuzzer.dict server/fuzz/corpus/fuzz_api

# Inputs fuzzer
python3 server/fuzz/inputs_fuzzer.py -dict=server/fuzz/dictionaries/inputs_fuzzer.dict server/fuzz/corpus/fuzz_inputs

# Watermarking fuzzer
python3 server/fuzz/watermarking_fuzzer.py -dict=server/fuzz/dictionaries/watermarking_fuzzer.dict server/fuzz/corpus/fuzz_watermarking
```

### Seed Corpus

Each fuzzer has 100+ carefully crafted seeds covering:

- **API**: SQL injection, XSS, command injection, SSRF, auth bypass, JWT manipulation, etc.
- **Inputs**: Path traversal, buffer overflows, format strings, Unicode edge cases, etc.
- **Watermarking**: Malformed PDFs, encrypted PDFs, zero-page PDFs, large files, etc.

## Dictionary Files

Dictionary files contain tokens that the fuzzer will try to insert/substitute during mutation:
- Common attack patterns
- SQL/NoSQL injection payloads
- XSS vectors
- Path traversal sequences
- Special characters and Unicode
- PDF structure keywords

## Requirements

- Python >= 3.11 (for Atheris support)
- atheris (coverage-guided fuzzing engine)
- All Tatou server dependencies

Install with:
```bash
pip install atheris
```

## Coverage Reports

Fuzzers generate coverage information automatically. Crashes and interesting inputs are saved to the corpus directory.
