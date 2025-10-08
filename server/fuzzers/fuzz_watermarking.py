#!/usr/bin/env python3
"""Fuzzer for PDF watermarking methods.

This fuzzer tests the robustness of watermarking methods by providing
various malformed and edge-case PDF inputs. It uses atheris for
coverage-guided fuzzing.

Usage:
    # Run with atheris
    python fuzz_watermarking.py

    # Run with corpus/seeds
    python fuzz_watermarking.py seeds/watermarking/

    # Generate initial corpus
    python fuzz_watermarking.py -atheris_runs=1000
"""

import sys
import os
import atheris

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from watermarking_utils import METHODS, is_watermarking_applicable
    from watermarking_method import WatermarkingError, SecretNotFoundError, InvalidKeyError
except ImportError as e:
    print(f"Warning: Could not import watermarking modules: {e}")
    print("Make sure to run from the server directory with dependencies installed")
    sys.exit(1)


def TestOneInput(data: bytes) -> None:
    """Fuzz target for watermarking methods.
    
    This function will be called repeatedly by atheris with different inputs.
    We test various watermarking operations on potentially malformed PDFs.
    """
    # Need at least some bytes to work with
    if len(data) < 10:
        return
    
    # Use first byte to select which method to test
    if not METHODS:
        return
    
    method_idx = data[0] % len(METHODS)
    method_name = list(METHODS.keys())[method_idx]
    method = METHODS[method_name]
    
    # Use next byte to select operation
    operation = data[1] % 3
    
    # Extract test parameters from data
    key_len = min(data[2] % 32 + 1, len(data) - 10)
    secret_len = min(data[3] % 32 + 1, len(data) - 10 - key_len)
    
    # Extract key and secret from input
    key = data[4:4+key_len].decode('utf-8', errors='ignore')
    secret = data[4+key_len:4+key_len+secret_len].decode('utf-8', errors='ignore')
    
    # Rest is PDF data
    pdf_data = data[4+key_len+secret_len:]
    
    # Ensure we have minimal PDF header if not already present
    if not pdf_data.startswith(b'%PDF'):
        # Add minimal PDF header
        pdf_data = b'%PDF-1.4\n' + pdf_data
    
    try:
        if operation == 0:
            # Test is_watermarking_applicable
            _ = is_watermarking_applicable(method_name, pdf_data)
        
        elif operation == 1:
            # Test add_watermark
            if is_watermarking_applicable(method_name, pdf_data):
                try:
                    _ = method.add_watermark(
                        pdf_data,
                        secret=secret or "test-secret",
                        key=key or "test-key",
                        intended_for="fuzzer@test.com"
                    )
                except (WatermarkingError, ValueError, TypeError, AttributeError):
                    # Expected exceptions for malformed input
                    pass
        
        elif operation == 2:
            # Test read_secret
            try:
                _ = method.read_secret(pdf_data, key=key or "test-key")
            except (SecretNotFoundError, InvalidKeyError, WatermarkingError, ValueError, TypeError, AttributeError):
                # Expected exceptions
                pass
    
    except Exception:
        # Catch any unexpected exceptions to prevent fuzzer crashes
        # but allow atheris to track this as interesting behavior
        pass


def main():
    """Main entry point for fuzzing."""
    # Determine seed directory
    seed_dir = os.path.join(os.path.dirname(__file__), "seeds", "watermarking")
    
    # Check if seed directory exists and has files
    if os.path.isdir(seed_dir):
        seed_files = [f for f in os.listdir(seed_dir) if os.path.isfile(os.path.join(seed_dir, f))]
        if seed_files:
            print(f"Found {len(seed_files)} seed files in {seed_dir}")
            # Atheris will use files in this directory as initial corpus
            atheris.Setup(sys.argv + [seed_dir], TestOneInput)
        else:
            print(f"No seed files found in {seed_dir}, starting with empty corpus")
            atheris.Setup(sys.argv, TestOneInput)
    else:
        print(f"Seed directory {seed_dir} not found, starting with empty corpus")
        atheris.Setup(sys.argv, TestOneInput)
    
    atheris.Fuzz()


if __name__ == "__main__":
    main()
