
# RMAP Testing Guide

## Prerequisites

1. **Server Keys**: 
   - server_pub.asc (server public key)
   - server_priv.asc (server private key)

2. **Client Keys**:
   - Public keys in server/src/client_keys/pki/
   - Corresponding private key for the client you want to test

3. **Server Running**:
   - Start: `cd server/src && python server.py`
   - Endpoints: http://localhost:5000/rmap-initiate and /rmap-get-link

## Testing Steps

### 1. Basic Infrastructure Test
```bash
python3 test_rmap_infrastructure.py
```

### 2. GPG-based Protocol Test (requires matching private key)
```python
# Example for testing with a group that has a private key
from test_rmap_client_library import IdentityManager, RMAP

client_identity_manager = IdentityManager(
    client_keys_dir="server/src/client_keys/pki",
    client_private_key_path="path/to/GroupX_priv.asc",  # Must match public key
    client_public_key_path="server/src/client_keys/pki/Group_X.asc",
    server_public_key_path="server/server_pub.asc"
)

client_rmap = RMAP(client_identity_manager)

# Test Message 1
message1 = client_rmap.create_message1("Group_X")
response = requests.post('http://localhost:5000/rmap-initiate', 
                        json={"payload": message1['payload']})

# Process response and create Message 2
result = client_rmap.process_response1(response.json())
message2 = client_rmap.create_message2(result)
response2 = requests.post('http://localhost:5000/rmap-get-link',
                         json={"payload": message2['payload']})

# Get session secret for PDF watermarking
session_secret = response2.json().get('result')
```

### 3. Watermarked PDF Creation
```python
import watermarking_utils as WMUtils

# Use session secret from RMAP authentication
watermarked_bytes = WMUtils.apply_watermark(
    method="robust-xmp",
    pdf="input.pdf",
    secret=session_secret,
    key="group-specific-key"
)

# Verify watermark
recovered_secret = WMUtils.read_watermark(
    method="robust-xmp",
    pdf=watermarked_bytes,
    key="group-specific-key"
)
```

## Security Notes

- Private keys should never be shared or committed to repositories
- Each group should only have access to their own private key
- Server validates client identity through public key infrastructure
- All communication is encrypted with GPG
- Session secrets are unique per authentication session

## Troubleshooting

1. **"Unknown identity" error**: Check that the group's public key exists in client_keys/pki/
2. **Decryption failed**: Ensure the private key matches the public key
3. **Server not responding**: Check that server is running on http://localhost:5000
4. **GPG errors**: Verify GPG is installed and keys are properly formatted

## Implementation Details

The RMAP implementation provides:
- Real GPG encryption/decryption using ASCII-armored PGP messages
- Client identity validation through public key infrastructure
- Secure nonce exchange with proper cryptographic protection
- Session secret generation for PDF watermarking
- Integration with robust-xmp watermarking method
