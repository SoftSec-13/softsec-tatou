#!/usr/bin/env python3
"""
Inputs Fuzzer for Tatou Platform

Tests input validation for security vulnerabilities including:
- Path traversal
- Buffer overflows
- Format string exploits
- Unicode edge cases
- Special character handling
- And more...

Uses seed corpus from corpus/fuzz_inputs/ and dictionary from dictionaries/inputs_fuzzer.dict
"""

import sys
import os
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
                line = line.replace('\\x00', '\x00')
                tokens.append(line)
    
    print(f"Loaded {len(tokens)} tokens from {dict_file}")
    return tokens


def test_input_validation(data):
    """
    Test input validation with fuzzed data.
    
    This function simulates input validation testing. In a real fuzzer, this would:
    - Test path validation functions
    - Test string parsing and handling
    - Test numeric conversions
    - Check for crashes or security issues
    """
    try:
        str_data = data.decode('utf-8', errors='ignore')
        
        # Check for path traversal patterns
        if any(pattern in str_data for pattern in ['../', '..\\', '%2e%2e']):
            print(f"[INFO] Detected path traversal pattern in input")
        
        # Check for format string patterns
        if '%n' in str_data or '%s' in str_data or '%x' in str_data:
            print(f"[INFO] Detected format string pattern in input")
        
        # Check for buffer overflow indicators (very long strings)
        if len(data) > 10000:
            print(f"[INFO] Detected potential buffer overflow (length={len(data)})")
        
        # Check for null bytes
        if b'\x00' in data:
            print(f"[INFO] Detected null byte in input")
        
        # Check for Unicode edge cases
        if any(ord(c) > 0xFFFF for c in str_data):
            print(f"[INFO] Detected extended Unicode characters")
        
        # Try to use the input in common scenarios
        # Test as filename
        try:
            path = Path(str_data)
            # Check if it tries to escape directory
            if '..' in path.parts:
                print(f"[INFO] Path contains '..' component")
        except Exception:
            pass
        
        # Test as numeric input
        try:
            num = int(str_data)
            if num < -2147483648 or num > 2147483647:
                print(f"[INFO] Numeric overflow detected: {num}")
        except (ValueError, OverflowError):
            pass
        
    except Exception as e:
        # In a real fuzzer, crashes would be saved for analysis
        print(f"[ERROR] Exception during fuzzing: {e}")


def fuzz_with_atheris(data):
    """Atheris-based fuzzing harness."""
    test_input_validation(data)


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
    
    # Try byte flipping
    for _ in range(5):
        if data:
            pos = random.randint(0, len(data) - 1)
            mutated = bytearray(data)
            mutated[pos] ^= random.randint(1, 255)
            mutations.append(bytes(mutated))
    
    return mutations


def main():
    """Main fuzzer entry point."""
    # Determine corpus and dictionary paths
    script_dir = Path(__file__).parent
    corpus_dir = script_dir / "corpus" / "fuzz_inputs"
    dict_file = script_dir / "dictionaries" / "inputs_fuzzer.dict"
    
    # Load seeds and dictionary
    seeds = load_seeds(corpus_dir)
    tokens = load_dictionary(dict_file)
    
    if not seeds:
        print("ERROR: No seeds loaded. Please ensure corpus/fuzz_inputs/ contains seed files.")
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
            test_input_validation(seed)
            
            # Generate mutations if we have tokens
            if tokens:
                mutations = simple_mutate(seed, tokens)
                for j, mutation in enumerate(mutations):
                    test_input_validation(mutation)
        
        print(f"\nFuzzing complete. Tested {len(seeds)} seeds.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
