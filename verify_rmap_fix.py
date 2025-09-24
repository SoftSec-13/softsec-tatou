#!/usr/bin/env python3
"""
RMAP Identity Extraction Verification Script

This script can be used to verify that the RMAP identity extraction 
implementation is working correctly without requiring a full server setup.
"""

import sys
import json
from pathlib import Path

def check_implementation():
    """Check that our RMAP implementation has the required changes."""
    print("RMAP Identity Extraction - Implementation Check")
    print("=" * 50)
    
    # Check if the files exist and have the expected changes
    server_src = Path("/home/runner/work/softsec-tatou/softsec-tatou/server/src")
    
    checks = []
    
    # Check 1: simple_rmap.py has identity tracking
    simple_rmap_file = server_src / "simple_rmap.py"
    if simple_rmap_file.exists():
        content = simple_rmap_file.read_text()
        if "session_identities" in content and "get_session_identity" in content:
            checks.append(("✅", "simple_rmap.py has identity tracking"))
        else:
            checks.append(("❌", "simple_rmap.py missing identity tracking"))
        
        if "_decrypt_message1_payload" in content:
            checks.append(("✅", "simple_rmap.py has PGP decryption logic"))
        else:
            checks.append(("❌", "simple_rmap.py missing PGP decryption logic"))
    else:
        checks.append(("❌", "simple_rmap.py not found"))
    
    # Check 2: rmap_handler.py uses identity instead of hardcoded value
    rmap_handler_file = server_src / "rmap_handler.py"  
    if rmap_handler_file.exists():
        content = rmap_handler_file.read_text()
        if "get_session_identity" in content:
            checks.append(("✅", "rmap_handler.py uses get_session_identity()"))
        else:
            checks.append(("❌", "rmap_handler.py missing get_session_identity() call"))
        
        # Check that hardcoded RMAP_CLIENT is now conditional
        if '"RMAP_CLIENT"' in content and "intended_for =" in content:
            checks.append(("✅", "rmap_handler.py has conditional RMAP_CLIENT fallback"))
        else:
            checks.append(("❌", "rmap_handler.py missing conditional fallback"))
    else:
        checks.append(("❌", "rmap_handler.py not found"))
    
    # Print results
    for status, message in checks:
        print(f"{status} {message}")
    
    # Overall status
    success_count = sum(1 for status, _ in checks if status == "✅")
    total_count = len(checks)
    
    print(f"\nImplementation Status: {success_count}/{total_count} checks passed")
    
    if success_count == total_count:
        print("✅ Implementation is complete and ready for testing!")
        return True
    else:
        print("❌ Implementation incomplete - some changes are missing")
        return False

def show_testing_instructions():
    """Show instructions for testing the implementation."""
    print("\n" + "=" * 50)
    print("Testing Instructions")
    print("=" * 50)
    
    print("""
To test the RMAP identity extraction:

1. Install dependencies:
   cd server/
   pip install -e .

2. Run the dynamic RMAP test:
   python3 dynamic_rmap_test.py

3. Check the database after the test:
   - Look at the Versions table
   - The 'intended_for' field should show the group name (e.g., "Group_13")
   - Instead of the old hardcoded "RMAP_CLIENT"

4. Expected database changes:
   Before: intended_for = "RMAP_CLIENT" (always)
   After:  intended_for = "Group_13" (actual group name from RMAP)

If PGP/RMAP libraries aren't available:
- The system will fallback to "RMAP_CLIENT" (same as before)
- This maintains backward compatibility
- No functionality is lost

See RMAP_TESTING_GUIDE.md for detailed testing instructions.
""")

def main():
    """Main verification function."""
    implementation_ok = check_implementation()
    show_testing_instructions()
    
    if implementation_ok:
        print("\n🎉 Ready to test! Run dynamic_rmap_test.py to verify the fix.")
        return 0
    else:
        print("\n⚠️  Implementation needs to be completed first.")
        return 1

if __name__ == "__main__":
    sys.exit(main())