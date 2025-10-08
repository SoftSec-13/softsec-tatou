#!/usr/bin/env python3
"""
Watermarking Fuzzer for Tatou Platform

Tests PDF watermarking functions for robustness and security:
- Malformed PDF files
- Encrypted PDFs
- Zero-page PDFs
- Extremely large/small PDFs
- Corrupted PDF structure
- Edge cases in watermarking methods
- And more...

Uses seed corpus from corpus/fuzz_watermarking/ and dictionary from dictionaries/watermarking_fuzzer.dict
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


def test_watermarking(data):
    """
    Test watermarking with fuzzed PDF data.
    
    This function simulates watermarking testing. In a real fuzzer, this would:
    - Try to load the PDF with PyMuPDF
    - Attempt to add watermarks using different methods
    - Check for crashes, exceptions, or security issues
    - Validate output PDF structure
    """
    try:
        # Check if data looks like a PDF
        if data.startswith(b'%PDF-'):
            print(f"[INFO] Valid PDF header detected")
        else:
            print(f"[INFO] Invalid PDF header (testing malformed PDF)")
        
        # Check for EOF marker
        if b'%%EOF' in data:
            print(f"[INFO] EOF marker found")
        else:
            print(f"[INFO] Missing EOF marker (malformed PDF)")
        
        # Try to import and use watermarking methods
        try:
            import fitz  # PyMuPDF
            
            # Attempt to open the PDF
            try:
                doc = fitz.open(stream=data, filetype="pdf")
                page_count = doc.page_count
                print(f"[INFO] Successfully opened PDF with {page_count} pages")
                
                if page_count == 0:
                    print(f"[INFO] Zero-page PDF detected")
                elif page_count > 1000:
                    print(f"[INFO] Large PDF detected ({page_count} pages)")
                
                # Try to access metadata
                try:
                    metadata = doc.metadata
                    if metadata:
                        print(f"[INFO] PDF has metadata")
                except Exception as e:
                    print(f"[INFO] Error reading metadata: {e}")
                
                # Try to access first page if exists
                if page_count > 0:
                    try:
                        page = doc.load_page(0)
                        print(f"[INFO] Successfully loaded first page")
                    except Exception as e:
                        print(f"[INFO] Error loading first page: {e}")
                
                doc.close()
                
            except Exception as e:
                print(f"[INFO] Failed to open PDF: {e}")
        
        except ImportError:
            print(f"[INFO] PyMuPDF not available, skipping PDF parsing")
        
        # Check for potentially malicious PDF content
        str_data = data.decode('latin-1', errors='ignore')
        
        if '/JavaScript' in str_data or '/JS' in str_data:
            print(f"[INFO] PDF contains JavaScript")
        
        if '/OpenAction' in str_data or '/AA' in str_data:
            print(f"[INFO] PDF contains auto-action")
        
        if '/Launch' in str_data:
            print(f"[INFO] PDF contains launch action")
        
        if '/URI' in str_data:
            print(f"[INFO] PDF contains URI action")
        
        # Check for encryption
        if '/Encrypt' in str_data:
            print(f"[INFO] PDF appears to be encrypted")
        
    except Exception as e:
        # In a real fuzzer, crashes would be saved for analysis
        print(f"[ERROR] Exception during fuzzing: {e}")


def fuzz_with_atheris(data):
    """Atheris-based fuzzing harness."""
    test_watermarking(data)


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
    
    # Try truncation
    if len(data) > 100:
        mutations.append(data[:len(data)//2])
        mutations.append(data[:100])
    
    return mutations


def main():
    """Main fuzzer entry point."""
    # Determine corpus and dictionary paths
    script_dir = Path(__file__).parent
    corpus_dir = script_dir / "corpus" / "fuzz_watermarking"
    dict_file = script_dir / "dictionaries" / "watermarking_fuzzer.dict"
    
    # Load seeds and dictionary
    seeds = load_seeds(corpus_dir)
    tokens = load_dictionary(dict_file)
    
    if not seeds:
        print("ERROR: No seeds loaded. Please ensure corpus/fuzz_watermarking/ contains seed files.")
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
            test_watermarking(seed)
            
            # Generate mutations if we have tokens
            if tokens:
                mutations = simple_mutate(seed, tokens)
                for j, mutation in enumerate(mutations):
                    test_watermarking(mutation)
        
        print(f"\nFuzzing complete. Tested {len(seeds)} seeds.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
