# RMAP Implementation Documentation

## Overview

This document describes the enhanced implementation of the Roger Michael Authentication Protocol (RMAP) for the Tatou PDF watermarking platform. The RMAP implementation provides a secure two-step authentication protocol using GPG encryption that generates session secrets for creating watermarked PDFs.

## Key Features

### ✅ GPG-Based Encryption
- **Real GPG encryption/decryption** using server and client key pairs
- **Client identity validation** through public key infrastructure
- **Secure nonce exchange** with proper cryptographic protection
- **ASCII-armored PGP message format** as specified in RMAP protocol

### ✅ Complete Key Infrastructure
- **Server keypair**: `server_pub.asc` and `server_priv.asc`
- **Client public keys**: Stored in `public-keys/pki/` directory
- **Identity mapping**: `Group13` → `group13@tatou.example.com`
- **Automatic key import** and validation

### ✅ Two-Step Authentication Protocol
1. **Step 1**: Client sends encrypted `{nonceClient, identity}` → Server responds with encrypted `{nonceClient, nonceServer}`
2. **Step 2**: Client sends encrypted `{nonceServer}` → Server responds with session secret

### ✅ Watermarking Integration
- **Session secrets** generated from concatenated nonces (32-hex chars)
- **Robust-XMP method** for watermarking with session secrets
- **End-to-end verification** of watermarks in PDFs

## RMAP Protocol Flow

### Step 1: Authentication Initiation (`/rmap-initiate`)

**Endpoint:** `POST /rmap-initiate`

**Request:**
```json
{
  "payload": "<base64-encoded-gpg-encrypted-message>"
}
```

**Encrypted Message Content:**
```json
{
  "nonceClient": 12345678901234567890,
  "identity": "Group13"
}
```

**Process:**
1. Server decrypts payload using server private key
2. Validates client identity exists in `public-keys/pki/Group13.asc`
3. Generates server nonce using `secrets.randbits(64)`
4. Stores session with both nonces
5. Encrypts response for client using their public key

**Response (Success):**
```json
{
  "payload": "<base64-encoded-gpg-encrypted-response>"
}
```

**Encrypted Response Content:**
```json
{
  "nonceClient": 12345678901234567890,
  "nonceServer": 9876543210987654321
}
```

### Step 2: Session Link Generation (`/rmap-get-link`)

**Endpoint:** `POST /rmap-get-link`

**Request:**
```json
{
  "payload": "<base64-encoded-gpg-encrypted-message>"
}
```

**Encrypted Message Content:**
```json
{
  "nonceServer": 9876543210987654321
}
```

**Process:**
1. Server decrypts payload using server private key
2. Finds matching session by server nonce
3. Generates session secret: `hex(nonceClient) + hex(nonceServer)`
4. Stores watermark metadata for the session
5. Returns session secret as link

**Response (Success):**
```json
{
  "result": "ab54a98ceb1f0ad26a526b7f25a0eb46"
}
```

## Key Directory Structure

```
server/
├── server_pub.asc              # Server public key
├── server_priv.asc             # Server private key  
├── Group13_priv.asc            # Client private key (for testing)
└── public-keys/pki/
    └── Group13.asc             # Client public key
```

## GPG Key Management

### Server Key Generation
```bash
# Server key generated with:
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 2048
Name-Real: Tatou RMAP Server
Name-Email: server@tatou.example.com
Expire-Date: 0
%no-protection
%commit
EOF

# Export keys
gpg --armor --export "server@tatou.example.com" > server_pub.asc
gpg --armor --export-secret-keys "server@tatou.example.com" > server_priv.asc
```

### Client Key Generation
```bash
# Client key generated with:
gpg --batch --gen-key <<EOF
Key-Type: RSA
Key-Length: 2048
Name-Real: Group13
Name-Email: group13@tatou.example.com
Expire-Date: 0
%no-protection
%commit
EOF

# Export keys
gpg --armor --export "group13@tatou.example.com" > public-keys/pki/Group13.asc
gpg --armor --export-secret-keys "group13@tatou.example.com" > Group13_priv.asc
```

## Error Handling

### HTTP Status Codes
- `200`: Success with encrypted response
- `400`: Bad request (missing payload)
- `503`: Service error (decryption failure, invalid identity, invalid nonce)

### Common Errors
1. **Missing payload**: `{"error": "payload is required"}`
2. **GPG decryption failure**: `{"error": "Invalid payload format: Failed to decrypt message: ..."}`
3. **Unknown identity**: `{"error": "Unknown identity: Group13"}`
4. **Invalid server nonce**: `{"error": "Invalid server nonce"}`

## Testing

### Complete GPG-based Test
```bash
# Test complete RMAP protocol with GPG encryption
python3 test_rmap_complete_client.py
```

### Basic GPG Test
```bash
# Test GPG encryption/decryption capabilities
python3 test_rmap_gpg.py
```

### Curl Test (shows proper error handling)
```bash
# Test endpoints with non-encrypted payloads (shows proper errors)
./test_rmap_curl.sh
```

### Integration Test
```bash
# Test RMAP + watermarking integration
python3 test_rmap_integration.py
```

## Implementation Details

### GPG Operations
- **Encryption**: `gpg --encrypt --armor --recipient <email>`
- **Decryption**: `gpg --decrypt --quiet --batch --yes`
- **Key Import**: Automatic import of server and client keys
- **Trust Model**: `--trust-model always` for testing

### Session Management
- **In-memory storage**: Sessions stored with key format `{identity}_{clientNonce}_{serverNonce}`
- **Session secret format**: 32-character hex string from concatenated nonces
- **Watermark metadata**: Links session secrets to PDF watermarking parameters

### Security Features
- **Client authentication**: Public key must exist in PKI directory
- **Nonce validation**: Server nonces must match stored sessions
- **Encrypted communication**: All payloads encrypted with GPG
- **Identity mapping**: Secure mapping from identity to email addresses

## API Examples

### Complete GPG-based Client Example

```python
from test_rmap_complete_client import RMAPClient

# Initialize client
client = RMAPClient(
    identity="Group13",
    private_key_path="Group13_priv.asc",
    server_public_key_path="server_pub.asc"
)

# Step 1: Authenticate
message1 = client.encrypt_for_server({
    "nonceClient": 12345678901234567890,
    "identity": "Group13"
})

response1 = requests.post("http://localhost:5000/rmap-initiate", 
                         json={"payload": message1})

# Decrypt server response
server_response = client.decrypt_from_server(response1.json()["payload"])
server_nonce = server_response["nonceServer"]

# Step 2: Get session secret
message2 = client.encrypt_for_server({
    "nonceServer": server_nonce
})

response2 = requests.post("http://localhost:5000/rmap-get-link",
                         json={"payload": message2})

session_secret = response2.json()["result"]

# Use session secret for PDF watermarking
watermarked_bytes = WMUtils.apply_watermark(
    method="robust-xmp",
    pdf="document.pdf", 
    secret=session_secret,
    key=f"rmap-key-{session_secret[:8]}"
)
```

## Migration from Simple Implementation

The enhanced GPG-based implementation replaces the previous simple base64 implementation:

### Previous (Simple)
- Base64-encoded JSON payloads
- No encryption or client validation
- Mock identity acceptance

### Current (GPG-based)
- GPG-encrypted ASCII-armored payloads
- Real cryptographic security
- Client public key validation
- Proper error handling for decryption failures

### Backward Compatibility
- API endpoints remain the same (`/rmap-initiate`, `/rmap-get-link`)
- Response format unchanged (JSON with `payload` or `result`)
- Session secret format preserved (32-character hex)
- Watermarking integration unchanged

The implementation now meets the full RMAP specification requirements with proper GPG-based encryption and client authentication.