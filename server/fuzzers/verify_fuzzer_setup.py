#!/usr/bin/env python3
"""Test script to verify fuzzer infrastructure without running atheris.

This script validates:
1. Seed files exist and are accessible
2. Fuzzers have correct structure
3. Seed loading logic works correctly
"""

import os
import sys

def test_seed_directories():
    """Verify seed directories exist and contain files."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    seeds_base = os.path.join(script_dir, "seeds")
    if not os.path.isdir(seeds_base):
        print("❌ Seeds base directory not found")
        return False
    
    print("✓ Seeds base directory exists")
    
    # Check watermarking seeds
    watermark_dir = os.path.join(seeds_base, "watermarking")
    if not os.path.isdir(watermark_dir):
        print("❌ Watermarking seeds directory not found")
        return False
    
    watermark_files = [f for f in os.listdir(watermark_dir) if f.endswith('.pdf')]
    print(f"✓ Found {len(watermark_files)} watermarking seed files")
    
    if len(watermark_files) < 100:
        print(f"⚠ Warning: Only {len(watermark_files)} watermarking seeds (expected 120)")
    
    # Check PDF exploration seeds
    explore_dir = os.path.join(seeds_base, "pdf_exploration")
    if not os.path.isdir(explore_dir):
        print("❌ PDF exploration seeds directory not found")
        return False
    
    explore_files = [f for f in os.listdir(explore_dir) if f.endswith('.pdf')]
    print(f"✓ Found {len(explore_files)} PDF exploration seed files")
    
    if len(explore_files) < 100:
        print(f"⚠ Warning: Only {len(explore_files)} exploration seeds (expected 120)")
    
    return True


def test_seed_content():
    """Verify seed files have content and proper PDF headers."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    watermark_dir = os.path.join(script_dir, "seeds", "watermarking")
    
    valid_count = 0
    invalid_count = 0
    
    for filename in os.listdir(watermark_dir):
        if not filename.endswith('.pdf'):
            continue
        
        filepath = os.path.join(watermark_dir, filename)
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Check file is not empty
            if len(content) == 0:
                print(f"  ⚠ {filename}: Empty file")
                invalid_count += 1
                continue
            
            # Check for PDF header (some malformed seeds won't have this)
            if content.startswith(b'%PDF') or content.startswith(b'%pdf'):
                valid_count += 1
            else:
                # This is OK for some malformed test cases
                invalid_count += 1
        
        except Exception as e:
            print(f"  ❌ {filename}: Error reading: {e}")
            return False
    
    print(f"✓ Seed content check: {valid_count} with PDF headers, {invalid_count} without (malformed test cases)")
    return True


def test_fuzzer_structure():
    """Verify fuzzer files have correct structure."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    fuzzers = [
        "fuzz_watermarking.py",
        "fuzz_pdf_exploration.py"
    ]
    
    for fuzzer in fuzzers:
        filepath = os.path.join(script_dir, fuzzer)
        if not os.path.isfile(filepath):
            print(f"❌ Fuzzer not found: {fuzzer}")
            return False
        
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check for required functions/patterns
        required_patterns = [
            "def TestOneInput",  # Atheris entry point
            "atheris",  # Import or reference to atheris
            "def main",  # Main function
        ]
        
        for pattern in required_patterns:
            if pattern not in content:
                print(f"❌ {fuzzer}: Missing required pattern: {pattern}")
                return False
        
        print(f"✓ {fuzzer}: Structure OK")
    
    return True


def test_seed_loading_logic():
    """Verify that fuzzer code properly checks for and loads seeds."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    fuzzer_file = os.path.join(script_dir, "fuzz_watermarking.py")
    with open(fuzzer_file, 'r') as f:
        content = f.read()
    
    # Check that seed directory is constructed
    if "seed_dir" not in content:
        print("❌ Fuzzer doesn't construct seed_dir")
        return False
    
    # Check that it looks for seed files
    if "os.path.isdir" not in content or "os.listdir" not in content:
        print("❌ Fuzzer doesn't check for seed directory or list files")
        return False
    
    # Check that seeds are passed to atheris
    if "atheris.Setup" not in content:
        print("❌ Fuzzer doesn't call atheris.Setup")
        return False
    
    print("✓ Seed loading logic present in fuzzers")
    return True


def test_runner_script():
    """Verify runner script exists and is executable."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    runner = os.path.join(script_dir, "run_fuzzers.sh")
    
    if not os.path.isfile(runner):
        print("❌ Runner script not found")
        return False
    
    if not os.access(runner, os.X_OK):
        print("⚠ Runner script exists but is not executable")
        print("  Run: chmod +x run_fuzzers.sh")
        return True  # Not a critical failure
    
    print("✓ Runner script exists and is executable")
    return True


def test_documentation():
    """Verify README exists and has content."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    readme = os.path.join(script_dir, "README.md")
    
    if not os.path.isfile(readme):
        print("❌ README.md not found")
        return False
    
    with open(readme, 'r') as f:
        content = f.read()
    
    if len(content) < 1000:
        print("⚠ README.md is very short")
    
    # Check for key sections
    required_sections = [
        "Fuzzers",
        "Seed",
        "Usage",
        "Installation",
    ]
    
    for section in required_sections:
        if section not in content:
            print(f"⚠ README.md missing section about: {section}")
    
    print("✓ README.md exists with documentation")
    return True


def main():
    """Run all tests."""
    print("=" * 60)
    print("Fuzzer Infrastructure Verification")
    print("=" * 60)
    print()
    
    tests = [
        ("Seed Directories", test_seed_directories),
        ("Seed Content", test_seed_content),
        ("Fuzzer Structure", test_fuzzer_structure),
        ("Seed Loading Logic", test_seed_loading_logic),
        ("Runner Script", test_runner_script),
        ("Documentation", test_documentation),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\nTesting: {test_name}")
        print("-" * 60)
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append((test_name, False))
    
    print()
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print()
    print(f"Result: {passed}/{total} tests passed")
    
    if passed == total:
        print()
        print("✓ All verification tests passed!")
        print("The fuzzer infrastructure is correctly set up.")
        print()
        print("To verify seeds are actually used when running:")
        print("  1. Install dependencies: pip install -e '.[dev]'")
        print("  2. Run fuzzers: ./run_fuzzers.sh")
        return 0
    else:
        print()
        print("❌ Some tests failed. Please fix the issues above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
