"""
Enhanced RMAP (Roger Michael Authentication Protocol) implementation with GPG support.

This implementation provides proper GPG-based encryption/decryption as expected
by the RMAP protocol specification.
"""

import base64
import json
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional


class GPGRMAPError(Exception):
    """Custom exception for RMAP GPG operations."""
    pass


class GPGRMAP:
    """GPG-based RMAP implementation for proper encryption/decryption."""

    def __init__(self, 
                 storage_dir: str,
                 server_public_key_path: str,
                 server_private_key_path: str,
                 client_keys_dir: str,
                 server_private_key_passphrase: Optional[str] = None):
        self.storage_dir = storage_dir
        self.server_public_key_path = server_public_key_path
        self.server_private_key_path = server_private_key_path
        self.client_keys_dir = client_keys_dir
        self.server_private_key_passphrase = server_private_key_passphrase
        self.sessions = {}  # In-memory session storage
        self.watermarked_pdfs = {}  # Store metadata about watermarked PDFs
        
        # Import server keys into GPG keyring
        self._import_server_keys()
        self._import_client_keys()
        
    def _import_server_keys(self):
        """Import server keys into GPG keyring."""
        try:
            # Import server public key
            subprocess.run(['gpg', '--import', self.server_public_key_path], 
                         check=True, capture_output=True)
            # Import server private key  
            subprocess.run(['gpg', '--import', self.server_private_key_path],
                         check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            # Keys might already be imported, continue
            pass
            
    def _import_client_keys(self):
        """Import all client public keys from the PKI directory."""
        client_keys_path = Path(self.client_keys_dir)
        if not client_keys_path.exists():
            return
            
        for key_file in client_keys_path.glob("*.asc"):
            try:
                subprocess.run(['gpg', '--import', str(key_file)],
                             check=True, capture_output=True)
            except subprocess.CalledProcessError:
                # Key might already be imported or invalid, continue
                pass
                
    def _decrypt_message(self, encrypted_base64: str) -> Dict[str, Any]:
        """Decrypt a GPG-encrypted base64 message."""
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_base64)
            
            # Write to temp file for GPG
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                f.write(encrypted_data)
                temp_file = f.name
                
            try:
                # Decrypt using GPG
                result = subprocess.run([
                    'gpg', '--decrypt', '--quiet', '--batch', '--yes', temp_file
                ], capture_output=True, text=True, check=True)
                
                decrypted_text = result.stdout
                return json.loads(decrypted_text)
                
            finally:
                os.unlink(temp_file)
                
        except (subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as e:
            raise GPGRMAPError(f"Failed to decrypt message: {e}")
            
    def _encrypt_message(self, message_data: Dict[str, Any], recipient_identity: str) -> str:
        """Encrypt a message for a specific recipient using GPG."""
        try:
            message_json = json.dumps(message_data)
            
            # Write message to temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(message_json)
                temp_input = f.name
                
            with tempfile.NamedTemporaryFile(mode='rb', delete=False) as f:
                temp_output = f.name
                
            try:
                # Encrypt for recipient
                result = subprocess.run([
                    'gpg', '--encrypt', '--armor', '--batch', '--yes', '--trust-model', 'always',
                    '--recipient', recipient_identity, '--output', temp_output, temp_input
                ], capture_output=True, text=True, check=True)
                
                # Read encrypted data
                with open(temp_output, 'rb') as f:
                    encrypted_data = f.read()
                    
                return base64.b64encode(encrypted_data).decode('utf-8')
                
            finally:
                if os.path.exists(temp_input):
                    os.unlink(temp_input)
                if os.path.exists(temp_output):
                    os.unlink(temp_output)
                    
        except subprocess.CalledProcessError as e:
            raise GPGRMAPError(f"Failed to encrypt message for {recipient_identity}: {e}")
            
    def _get_client_email(self, identity: str) -> str:
        """Get client email from identity by looking up in GPG keyring."""
        try:
            # Try to find the key by searching for the identity in the keyring
            result = subprocess.run([
                'gpg', '--list-keys', '--with-colons'
            ], capture_output=True, text=True, check=True)
            
            # Parse the output to find keys that match the identity
            lines = result.stdout.split('\n')
            for line in lines:
                if line.startswith('uid:') and identity.lower() in line.lower():
                    # Extract email from uid line (format: uid:...:...:...:...:Name <email>:...)
                    parts = line.split(':')
                    if len(parts) >= 10:
                        user_id = parts[9]  # The user ID field
                        # Extract email using regex
                        import re
                        email_match = re.search(r'<([^>]+)>', user_id)
                        if email_match:
                            return email_match.group(1)
            
            # Fallback: try different identity formats
            fallback_patterns = [
                f"group{identity.lower().replace('group', '').replace('_', '')}",
                f"group_{identity.lower().replace('group', '').replace('_', '')}",
                identity.lower()
            ]
            
            for pattern in fallback_patterns:
                for line in lines:
                    if line.startswith('uid:') and pattern in line.lower():
                        parts = line.split(':')
                        if len(parts) >= 10:
                            user_id = parts[9]
                            import re
                            email_match = re.search(r'<([^>]+)>', user_id)
                            if email_match:
                                return email_match.group(1)
            
            # Final fallback to original format for compatibility
            return f"{identity.lower()}@tatou.example.com"
            
        except subprocess.CalledProcessError:
            # If GPG fails, use fallback
            return f"{identity.lower()}@tatou.example.com"
        
    def handle_message1(self, incoming: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle first RMAP message (rmap-initiate).
        
        Expected incoming: {"payload": "<base64(GPG-encrypted-data)>"}
        Expected decrypted content: {"nonceClient": <u64>, "identity": "<str>"}
        
        Returns: {"payload": "<base64(GPG-encrypted-response)>"} or {"error": "<reason>"}
        """
        try:
            if "payload" not in incoming:
                return {"error": "payload is required"}
            
            payload = incoming["payload"]
            if not payload:
                return {"error": "payload cannot be empty"}
            
            # Decrypt the GPG-encrypted payload
            try:
                message_data = self._decrypt_message(payload)
            except GPGRMAPError as e:
                return {"error": f"Invalid payload format: {e}"}
            
            if "nonceClient" not in message_data or "identity" not in message_data:
                return {"error": "Invalid message format - missing nonceClient or identity"}
            
            nonce_client = message_data["nonceClient"]
            identity = message_data["identity"]
            
            # Validate identity (check if we have their public key)
            if not isinstance(identity, str) or not identity:
                return {"error": "Invalid identity"}
                
            client_email = self._get_client_email(identity)
            
            # Try multiple possible key file names
            possible_key_files = [
                Path(self.client_keys_dir) / f"{identity}.asc",
                Path(self.client_keys_dir) / f"Group_{identity.replace('Group', '').replace('group', '')}.asc",
                Path(self.client_keys_dir) / f"Group{identity.replace('Group', '').replace('group', '')}.asc",
            ]
            
            client_key_file = None
            for key_file in possible_key_files:
                if key_file.exists():
                    client_key_file = key_file
                    break
            
            if not client_key_file:
                return {"error": f"Unknown identity: {identity}"}
            
            # Generate server nonce
            nonce_server = secrets.randbits(64)
            
            # Store session
            session_key = f"{identity}_{nonce_client}_{nonce_server}"
            self.sessions[session_key] = {
                "identity": identity,
                "nonceClient": nonce_client,
                "nonceServer": nonce_server,
                "client_email": client_email,
                "created": True
            }
            
            # Create response
            response_data = {
                "nonceClient": nonce_client,
                "nonceServer": nonce_server
            }
            
            # Encrypt response for the client
            try:
                encrypted_payload = self._encrypt_message(response_data, client_email)
            except GPGRMAPError as e:
                return {"error": f"Failed to encrypt response: {e}"}
            
            return {"payload": encrypted_payload}
            
        except Exception as e:
            return {"error": f"RMAP system initialization failed: {str(e)}"}
    
    def handle_message2(self, incoming: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle second RMAP message (rmap-get-link).
        
        Expected incoming: {"payload": "<base64(GPG-encrypted-data)>"}
        Expected decrypted content: {"nonceServer": <u64>}
        
        Returns: {"result": "<session_secret>"} or {"error": "<reason>"}
        """
        try:
            if "payload" not in incoming:
                return {"error": "payload is required"}
            
            payload = incoming["payload"]
            if not payload:
                return {"error": "payload cannot be empty"}
            
            # Decrypt the GPG-encrypted payload
            try:
                message_data = self._decrypt_message(payload)
            except GPGRMAPError as e:
                return {"error": f"Invalid payload format: {e}"}
            
            if "nonceServer" not in message_data:
                return {"error": "Invalid message format - missing nonceServer"}
            
            nonce_server = message_data["nonceServer"]
            
            # Find matching session
            matching_session = None
            session_key = None
            for key, session_data in self.sessions.items():
                if session_data["nonceServer"] == nonce_server:
                    matching_session = session_data
                    session_key = key
                    break
            
            if not matching_session:
                return {"error": "Invalid server nonce"}
            
            # Create session secret (concatenation of client and server nonces)
            nonce_client = matching_session["nonceClient"]
            identity = matching_session["identity"]
            
            # Convert nonces to hex representation (32 chars total)
            client_hex = f"{nonce_client:016x}"  # 16 hex chars for 64-bit int
            server_hex = f"{nonce_server:016x}"  # 16 hex chars for 64-bit int
            session_secret = client_hex + server_hex  # 32 hex chars total
            
            # Store watermark metadata for this session
            self.watermarked_pdfs[session_secret] = {
                "identity": identity,
                "nonceClient": nonce_client,
                "nonceServer": nonce_server,
                "method": "robust-xmp",
                "created": True,
                "session_key": session_key
            }
            
            # Mark session as completed
            if session_key in self.sessions:
                self.sessions[session_key]["completed"] = True
            
            return {"result": session_secret}
            
        except Exception as e:
            return {"error": f"RMAP system initialization failed: {str(e)}"}
    
    def get_session_info(self, session_secret: str) -> Optional[Dict[str, Any]]:
        """Get session information by session secret."""
        return self.watermarked_pdfs.get(session_secret)


# For backward compatibility and testing purposes
def create_test_gpg_payload(nonce_client: int, identity: str, recipient_email: str = "server@tatou.example.com") -> str:
    """Create a GPG-encrypted test payload for testing purposes."""
    data = {
        "nonceClient": nonce_client,
        "identity": identity
    }
    message_json = json.dumps(data)
    
    # Write message to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(message_json)
        temp_input = f.name
        
    with tempfile.NamedTemporaryFile(mode='rb', delete=False) as f:
        temp_output = f.name
        
    try:
        # Encrypt for server
        result = subprocess.run([
            'gpg', '--encrypt', '--armor', '--batch', '--yes', '--trust-model', 'always',
            '--recipient', recipient_email, '--output', temp_output, temp_input
        ], capture_output=True, text=True, check=True)
        
        # Read encrypted data
        with open(temp_output, 'rb') as f:
            encrypted_data = f.read()
            
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    finally:
        if os.path.exists(temp_input):
            os.unlink(temp_input)
        if os.path.exists(temp_output):
            os.unlink(temp_output)


def create_test_gpg_payload2(nonce_server: int, recipient_email: str = "server@tatou.example.com") -> str:
    """Create a GPG-encrypted test payload for message 2."""
    data = {
        "nonceServer": nonce_server
    }
    message_json = json.dumps(data)
    
    # Write message to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write(message_json)
        temp_input = f.name
        
    with tempfile.NamedTemporaryFile(mode='rb', delete=False) as f:
        temp_output = f.name
        
    try:
        # Encrypt for server
        result = subprocess.run([
            'gpg', '--encrypt', '--armor', '--batch', '--yes', '--trust-model', 'always',
            '--recipient', recipient_email, '--output', temp_output, temp_input
        ], capture_output=True, text=True, check=True)
        
        # Read encrypted data
        with open(temp_output, 'rb') as f:
            encrypted_data = f.read()
            
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    finally:
        if os.path.exists(temp_input):
            os.unlink(temp_input)
        if os.path.exists(temp_output):
            os.unlink(temp_output)