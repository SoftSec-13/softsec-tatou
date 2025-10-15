# Fixed Security Bugs

This document tracks security vulnerabilities found through fuzzing and manual code review, along with their fixes.

## Bug #1: PBKDF2 Denial of Service (DoS)

**Date Found:** 2025-10-07
**Severity:** Medium
**Category:** Denial of Service / Resource Exhaustion
**Status:** Fixed

### Description
The `signed_annotation_watermark.py` watermarking method allowed user-controlled PBKDF2 iteration counts up to 2,000,000 iterations when reading watermarks from PDF files. An attacker could craft a malicious PDF with a watermark containing `iter_count=2000000`, causing the server to perform expensive PBKDF2 key derivation that could tie up CPU resources and lead to denial of service.

### Vulnerable Code
**File:** `server/src/signed_annotation_watermark.py`
**Lines:** 198-200 (before fix)

```python
iter_count = int(manifest.get("iter", self._PBKDF2_ITER))
if iter_count <= 0 or iter_count > 2_000_000:  # sanity bounds
    raise WatermarkingError("Unreasonable PBKDF2 iteration count")
```

### Attack Scenario
1. Attacker creates a PDF with a valid watermark structure
2. Sets `iter` field in the watermark manifest to 2,000,000
3. Uploads the PDF to the server
4. When anyone tries to read the watermark via `/api/read-watermark`, the server performs 2 million PBKDF2 iterations
5. Multiple such requests could exhaust server CPU resources

### Fix
Reduced the maximum allowed PBKDF2 iteration count from 2,000,000 to 300,000. This still allows for secure key derivation (the default is 120,000) while preventing excessive resource consumption.

**File:** `server/src/signed_annotation_watermark.py`
**Lines:** 199-201 (after fix)

```python
iter_count = int(manifest.get("iter", self._PBKDF2_ITER))
# Limit to 300k iterations to prevent DoS attacks via excessive PBKDF2 computation
if iter_count <= 0 or iter_count > 300_000:
    raise WatermarkingError("Unreasonable PBKDF2 iteration count")
```

### Testing
This bug was identified through manual code review after fuzzing runs. While the fuzzer didn't directly trigger this vulnerability (it would require crafting specific PDF watermark structures), it highlighted areas of code that handle user-controlled parameters.

### Impact
- **Before Fix:** An attacker could cause significant CPU load with specially crafted PDFs
- **After Fix:** Maximum CPU usage for PBKDF2 is limited to a reasonable bound
- **Recommended:** Consider adding rate limiting on watermark reading operations for additional protection

### Related Security Considerations
- The `robust_xmp_watermark.py` method uses a fixed iteration count of 100,000 and is not vulnerable to this issue
- Future watermarking methods should avoid user-controlled iteration counts where possible
- Consider implementing request-level timeouts for watermarking operations

## Bug #2: TypeError in File Upload Size Validation

**Date Found:** 2025-10-07
**Severity:** Low-Medium
**Category:** Error Handling / Input Validation
**Status:** Fixed

### Description
The file upload endpoint `/api/upload-document` had improper handling of the `Content-Length` header validation. When a client uploads a file without providing a `Content-Length` header, the `file.content_length` attribute becomes `None`, and the comparison `None > MAX_FILE_SIZE` raises a `TypeError`, causing the server to return a 500 Internal Server Error instead of properly handling the request.

### Vulnerable Code
**File:** `server/src/server.py`
**Lines:** 291-294 (before fix)

```python
start_db = time.time()
# Validate file size
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
if file.content_length > MAX_FILE_SIZE:
    return jsonify({"error": "file too large"}), 413
```

### Attack Scenario
1. Attacker sends a multipart/form-data POST request to `/api/upload-document`
2. Omits the `Content-Length` header or uses chunked transfer encoding
3. Server crashes with TypeError when comparing `None > 50MB`
4. Server returns 500 error, potentially leaking stack trace information
5. Repeated requests could be used to cause service disruption

### Fix
Added a null check before comparing `file.content_length` to ensure the comparison only happens when the content length is actually provided.

**File:** `server/src/server.py`
**Lines:** 291-294 (after fix)

```python
start_db = time.time()
# Validate file size
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
if file.content_length and file.content_length > MAX_FILE_SIZE:
    return jsonify({"error": "file too large"}), 413
```

### Testing
This bug was identified through manual code review while analyzing potential error handling issues. The fuzzer didn't trigger this because it uses Flask's test client which automatically sets Content-Length headers.

### Impact
- **Before Fix:** Uploads without Content-Length header cause 500 errors and potential information disclosure
- **After Fix:** Missing Content-Length headers are handled gracefully
- **Note:** While this fix prevents the TypeError, files without Content-Length can still be uploaded. Flask will read the entire file into memory to save it, so very large files could still cause memory exhaustion. Consider adding additional size checks after the file is saved.

### Related Security Considerations
- Flask/Werkzeug have built-in limits on request body size that can be configured via `MAX_CONTENT_LENGTH`
- Consider setting a global `MAX_CONTENT_LENGTH` in Flask config as an additional defense layer
- The file size is verified after upload using `stored_path.stat().st_size`, which provides a secondary check
- Monitor memory usage on upload endpoints to detect potential memory exhaustion attacks
