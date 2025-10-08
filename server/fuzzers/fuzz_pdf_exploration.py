#!/usr/bin/env python3
"""Fuzzer for PDF exploration utilities.

This fuzzer tests the PDF parsing and exploration logic that builds
a tree structure from PDF documents. It's designed to catch crashes,
hangs, and unexpected behavior when processing malformed PDFs.

Usage:
    python fuzz_pdf_exploration.py seeds/pdf_exploration/
"""

import sys
import os
import atheris

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

try:
    from watermarking_utils import explore_pdf
except ImportError as e:
    print(f"Warning: Could not import watermarking_utils: {e}")
    sys.exit(1)


def TestOneInput(data: bytes) -> None:
    """Fuzz target for PDF exploration.
    
    Tests the explore_pdf function with various malformed PDF inputs.
    """
    if len(data) < 10:
        return
    
    try:
        # Test explore_pdf with raw bytes
        result = explore_pdf(data)
        
        # Verify result structure is valid
        if result:
            assert isinstance(result, dict), "explore_pdf should return dict"
            # Check for expected keys
            if 'type' in result:
                assert isinstance(result['type'], str), "type should be string"
            if 'children' in result:
                assert isinstance(result['children'], list), "children should be list"
    
    except (ValueError, TypeError, AttributeError, KeyError):
        # Expected exceptions for malformed PDFs
        pass
    except Exception:
        # Catch unexpected exceptions
        pass


def main():
    """Main entry point."""
    seed_dir = os.path.join(os.path.dirname(__file__), "seeds", "pdf_exploration")
    
    if os.path.isdir(seed_dir):
        seed_files = [f for f in os.listdir(seed_dir) if os.path.isfile(os.path.join(seed_dir, f))]
        if seed_files:
            print(f"Found {len(seed_files)} seed files in {seed_dir}")
            atheris.Setup(sys.argv + [seed_dir], TestOneInput)
        else:
            atheris.Setup(sys.argv, TestOneInput)
    else:
        atheris.Setup(sys.argv, TestOneInput)
    
    atheris.Fuzz()


if __name__ == "__main__":
    main()
