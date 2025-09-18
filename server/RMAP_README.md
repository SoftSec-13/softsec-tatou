# RMAP Implementation Documentation

## Overview

This document describes the implementation of the Roger Michael Authentication Protocol (RMAP) for the Tatou PDF watermarking platform. The RMAP implementation provides a two-step authentication protocol that generates session secrets which can be used to create watermarked PDFs.

## RMAP Protocol Flow

### Step 1: Authentication Initiation (`/rmap-initiate`)

**Endpoint:** `POST /rmap-initiate`

**Request:**
```json
{
  "payload": "<base64-encoded-message>"
}
```

**Decoded Message Format:**
```json
{
  "nonceClient": 12345678901234567890,
  "identity": "Group13"
}
```

**Response (Success):**
```json
{
  "payload": "<base64-encoded-response>"
}
```

**Decoded Response Format:**
```json
{
  "nonceClient": 12345678901234567890,
  "nonceServer": 9876543210987654321
}
```

**Response (Error):**
```json
{
  "error": "payload is required"
}
```

### Step 2: Session Link Generation (`/rmap-get-link`)

**Endpoint:** `POST /rmap-get-link`

**Request:**
```json
{
  "payload": "<base64-encoded-message>"
}
```

**Decoded Message Format:**
```json
{
  "nonceServer": 9876543210987654321
}
```

**Response (Success):**
```json
{
  "result": "ab54a98ceb1f0ad29d72a124196115c7"
}
```

The `result` is a 32-character hexadecimal session secret created by concatenating the client and server nonces.

**Response (Error):**
```json
{
  "error": "Invalid server nonce"
}
```

## Session Secret Format

The session secret is generated as follows:
1. Convert client nonce to 16-character hex string
2. Convert server nonce to 16-character hex string  
3. Concatenate: `clientHex + serverHex` (32 characters total)

Example:
- Client nonce: `12345678901234567890` → `ab54a98ceb1f0ad2`
- Server nonce: `9876543210987654321` → `8e51c2c9a52e7551`
- Session secret: `ab54a98ceb1f0ad28e51c2c9a52e7551`

## Integration with Watermarking

The session secret can be used as a watermark secret with the `robust-xmp` watermarking method:

```python
import watermarking_utils as WMUtils

# Use session secret from RMAP
session_secret = "ab54a98ceb1f0ad29d72a124196115c7"
key = "user-specific-key"

# Watermark PDF
watermarked_bytes = WMUtils.apply_watermark(
    method="robust-xmp",
    pdf="input.pdf",
    secret=session_secret,
    key=key
)

# Verify watermark
recovered_secret = WMUtils.read_watermark(
    method="robust-xmp", 
    pdf=watermarked_bytes,
    key=key
)
```

## Error Handling

### HTTP Status Codes

- `200`: Success
- `400`: Bad request (missing required fields)
- `503`: Service error (invalid payload format, RMAP system failure)

### Common Errors

1. **Missing payload**: `{"error": "payload is required"}`
2. **Invalid base64**: `{"error": "Invalid payload format"}`
3. **Invalid JSON**: `{"error": "Invalid payload format"}`
4. **Missing fields**: `{"error": "Invalid message format - missing nonceClient or identity"}`
5. **Invalid nonce**: `{"error": "Invalid server nonce"}`

## Testing

### Quick Test Script
```bash
# Test basic endpoints
./test_rmap_curl.sh
```

### Complete Protocol Test
```bash
# Test full two-step authentication
python3 test_rmap_complete.py
```

### Integration Test
```bash
# Test RMAP + PDF watermarking integration
python3 test_rmap_integration.py
```

## Implementation Details

### Session Storage
- Sessions are stored in-memory using the `SimpleRMAP` class
- Session keys: `{identity}_{clientNonce}_{serverNonce}`
- Sessions include metadata about watermarked PDFs

### Security Notes
- This is a simplified implementation for educational purposes
- In production, implement proper GPG encryption/decryption
- Add session timeouts and cleanup
- Validate client identities against a PKI
- Use persistent storage for sessions

### Files
- `simple_rmap.py`: Core RMAP implementation
- `test_rmap_curl.sh`: Basic endpoint testing
- `test_rmap_complete.py`: Complete protocol test
- `test_rmap_integration.py`: RMAP + watermarking integration test

## API Examples

### Complete Flow Example

```python
import requests, base64, json

# Step 1: Initiate authentication
message1 = {"nonceClient": 123456789, "identity": "Group13"}
payload1 = base64.b64encode(json.dumps(message1).encode()).decode()

response1 = requests.post("http://localhost:5000/rmap-initiate", 
                         json={"payload": payload1})

# Extract server nonce
response1_data = json.loads(base64.b64decode(response1.json()["payload"]))
server_nonce = response1_data["nonceServer"]

# Step 2: Get session secret
message2 = {"nonceServer": server_nonce}
payload2 = base64.b64encode(json.dumps(message2).encode()).decode()

response2 = requests.post("http://localhost:5000/rmap-get-link",
                         json={"payload": payload2})

session_secret = response2.json()["result"]
print(f"Session secret: {session_secret}")
```