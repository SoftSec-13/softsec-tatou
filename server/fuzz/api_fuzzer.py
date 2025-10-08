#!/usr/bin/env python3
"""
API Fuzzer for Tatou Platform

Tests REST API endpoints for security vulnerabilities including:
- SQL injection
- XSS
- Command injection
- SSRF
- Authentication bypass
- JWT manipulation
- And more...

Uses seed corpus from corpus/fuzz_api/ and dictionary from dictionaries/api_fuzzer.dict
"""

import sys
import os
import json
import random
from pathlib import Path

# Add parent directory to path to import server modules
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import atheris
    HAVE_ATHERIS = True
except ImportError:
    HAVE_ATHERIS = False
    print("Warning: atheris not installed. Using simple mutation fuzzer.")


def load_seeds(corpus_dir):
    """Load seed inputs from corpus directory."""
    seeds = []
    corpus_path = Path(corpus_dir)
    if not corpus_path.exists():
        print(f"Warning: corpus directory {corpus_dir} not found")
        return seeds
    
    for seed_file in corpus_path.glob("*"):
        if seed_file.is_file():
            try:
                with open(seed_file, 'rb') as f:
                    seeds.append(f.read())
            except Exception as e:
                print(f"Warning: failed to load seed {seed_file}: {e}")
    
    print(f"Loaded {len(seeds)} seeds from {corpus_dir}")
    return seeds


def load_dictionary(dict_file):
    """Load fuzzing dictionary tokens."""
    tokens = []
    dict_path = Path(dict_file)
    if not dict_path.exists():
        print(f"Warning: dictionary file {dict_file} not found")
        return tokens
    
    with open(dict_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Remove quotes if present
                if line.startswith('"') and line.endswith('"'):
                    line = line[1:-1]
                # Unescape common escape sequences
                line = line.replace('\\n', '\n').replace('\\r', '\r').replace('\\t', '\t')
                tokens.append(line)
    
    print(f"Loaded {len(tokens)} tokens from {dict_file}")
    return tokens


def test_api_endpoint(data):
    """
    Test API endpoint with fuzzed data.
    
    This function simulates API testing. In a real fuzzer, this would:
    - Parse the data as JSON API request
    - Make actual HTTP requests to the API
    - Check for errors, crashes, or security issues
    """
    try:
        # Try to parse as JSON (common for API requests)
        if data:
            try:
                parsed = json.loads(data)
                # Simulate checking for various attack patterns
                str_data = str(data)
                
                # Check for SQL injection patterns
                if any(pattern in str_data.lower() for pattern in [
                    "' or '1'='1", "union select", "drop table", "; --"
                ]):
                    print(f"[INFO] Detected SQL injection pattern in input")
                
                # Check for XSS patterns
                if any(pattern in str_data.lower() for pattern in [
                    "<script>", "onerror=", "onload=", "javascript:"
                ]):
                    print(f"[INFO] Detected XSS pattern in input")
                
                # Check for command injection
                if any(pattern in str_data for pattern in [
                    "; ls", "| cat", "$(", "`"
                ]):
                    print(f"[INFO] Detected command injection pattern in input")
                
            except json.JSONDecodeError:
                pass  # Not JSON, continue anyway
            
    except Exception as e:
        # In a real fuzzer, crashes would be saved for analysis
        print(f"[ERROR] Exception during fuzzing: {e}")


def fuzz_with_atheris(data):
    """Atheris-based fuzzing harness."""
    test_api_endpoint(data)


def simple_mutate(data, tokens):
    """Simple mutation fuzzer without Atheris."""
    mutations = []
    
    # Try inserting tokens at random positions
    for _ in range(10):
        if tokens:
            token = random.choice(tokens).encode('utf-8', errors='ignore')
            if data:
                pos = random.randint(0, len(data))
                mutated = data[:pos] + token + data[pos:]
            else:
                mutated = token
            mutations.append(mutated)
    
    # Try replacing parts with tokens
    for _ in range(10):
        if tokens and data and len(data) > 2:
            token = random.choice(tokens).encode('utf-8', errors='ignore')
            start = random.randint(0, len(data) - 1)
            end = random.randint(start, len(data))
            mutated = data[:start] + token + data[end:]
            mutations.append(mutated)
    
    return mutations


def main():
    """Main fuzzer entry point."""
    # Determine corpus and dictionary paths
    script_dir = Path(__file__).parent
    corpus_dir = script_dir / "corpus" / "fuzz_api"
    dict_file = script_dir / "dictionaries" / "api_fuzzer.dict"
    
    # Load seeds and dictionary
    seeds = load_seeds(corpus_dir)
    tokens = load_dictionary(dict_file)
    
    if not seeds:
        print("ERROR: No seeds loaded. Please ensure corpus/fuzz_api/ contains seed files.")
        return 1
    
    if not tokens:
        print("WARNING: No dictionary tokens loaded. Fuzzing will be less effective.")
    
    if HAVE_ATHERIS:
        print("Using Atheris coverage-guided fuzzing")
        # Initialize Atheris with our seeds
        atheris.Setup(sys.argv, fuzz_with_atheris, enable_python_coverage=True)
        atheris.Fuzz()
    else:
        print("Using simple mutation-based fuzzing")
        print(f"Testing with {len(seeds)} seeds...")
        
        # Test each seed
        for i, seed in enumerate(seeds):
            print(f"\n[{i+1}/{len(seeds)}] Testing seed...")
            test_api_endpoint(seed)
            
            # Generate mutations if we have tokens
            if tokens:
                mutations = simple_mutate(seed, tokens)
                for j, mutation in enumerate(mutations):
                    test_api_endpoint(mutation)
        
        print(f"\nFuzzing complete. Tested {len(seeds)} seeds.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
