# RMAP Identity Extraction Testing Guide

This guide explains how to test the RMAP cleanup implementation that fixes the `intended_for` field issue.

## Problem Solved

**Before**: The `intended_for` field in the database was always hardcoded to `"RMAP_CLIENT"`
**After**: The `intended_for` field now contains the actual group name from the RMAP authentication (e.g., `"Group_13"`)

## Changes Made

### 1. `simple_rmap.py`
- Added identity extraction from RMAP Message 1 payload
- Implemented PGP decryption to capture group identity  
- Added correlation logic to map identities to session secrets
- Added robust fallback behavior when PGP is unavailable

### 2. `rmap_handler.py`  
- Modified database insertion to use `get_session_identity()` instead of hardcoded `"RMAP_CLIENT"`
- Added fallback logic when identity extraction fails

## Testing Instructions

### Prerequisites
1. Install dependencies: `pip install -e .` (from the `server/` directory)
2. Ensure you have the RMAP library and PGP keys set up
3. Have a running Tatou server with database

### Test 1: Run the Dynamic RMAP Test
```bash
cd server/
python3 dynamic_rmap_test.py
```

**Expected Behavior:**
- RMAP authentication should work as before
- Check the database after the test completes

### Test 2: Verify Database Entries
After running the RMAP test, check the `Versions` table:

```sql
SELECT id, documentid, link, intended_for, secret, method FROM Versions WHERE link LIKE '%' ORDER BY id DESC LIMIT 5;
```

**Expected Results:**
- **With working PGP**: `intended_for` should be `"Group_13"` (or the actual group name used in the test)
- **With PGP issues**: `intended_for` should fallback to `"RMAP_CLIENT"`

### Test 3: Test Different Group Names
1. Modify `dynamic_rmap_test.py` to use different identity values:
   ```python
   identity = "Group_42"  # Change this line
   ```
2. Run the test again
3. Verify the database now shows `intended_for = "Group_42"`

## Expected Database Changes

### Before Fix
```
| id | documentid | link | intended_for | secret | method     |
|----|------------|------|--------------|--------|------------|
|  1 |          1 | ab54 | RMAP_CLIENT  | ab54   | robust-xmp |
|  2 |          1 | cd78 | RMAP_CLIENT  | cd78   | robust-xmp |
```

### After Fix  
```
| id | documentid | link | intended_for | secret | method     |
|----|------------|------|--------------|--------|------------|
|  1 |          1 | ab54 | Group_13     | ab54   | robust-xmp |
|  2 |          1 | cd78 | Group_42     | cd78   | robust-xmp |
|  3 |          1 | ef90 | RMAP_CLIENT  | ef90   | robust-xmp | <- fallback case
```

## Troubleshooting

### If identity extraction isn't working:
1. **Check PGP availability**: The `pgpy` library must be installed
2. **Verify key files**: `server_priv.asc` must exist and be readable
3. **Check logs**: Look for identity extraction warnings in server output
4. **Fallback behavior**: Even if extraction fails, RMAP should still work with `"RMAP_CLIENT"`

### If RMAP test fails completely:
1. This indicates an issue with the core RMAP functionality, not the identity extraction
2. The identity extraction code is designed to be non-intrusive
3. Check that all RMAP dependencies are properly installed

## Implementation Notes

The implementation uses a two-phase approach:
1. **Message 1**: Extract and store the identity from the encrypted payload
2. **Message 2**: Correlate the stored identity with the session secret

This approach ensures that:
- ✅ Identity extraction works when PGP is available
- ✅ Fallback behavior maintains compatibility when PGP fails  
- ✅ No changes to the core RMAP protocol
- ✅ No breaking changes to existing functionality

## Verification Success Criteria

1. ✅ `dynamic_rmap_test.py` runs successfully (same as before)
2. ✅ Database entries show actual group names instead of `"RMAP_CLIENT"`
3. ✅ System still works when identity extraction fails (graceful degradation)
4. ✅ No breaking changes to existing RMAP functionality