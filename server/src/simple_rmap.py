"""
Simple RMAP (Roger Michael Authentication Protocol) implementation for Tatou.

This is a minimal implementation that provides the basic RMAP functionality
without requiring external dependencies.
"""

import base64
import hashlib
import json
import os
import random
import secrets
from typing import Any, Dict, Optional


class SimpleRMAP:
    """Simple RMAP implementation for educational purposes."""

    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        self.sessions = {}  # In-memory session storage
        
    def handle_message1(self, incoming: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle first RMAP message (rmap-initiate).
        
        Expected incoming: {"payload": "<base64(encrypted_data)>"}
        Expected decrypted content: {"nonceClient": <u64>, "identity": "<str>"}
        
        Returns: {"payload": "<base64(encrypted_response)>"} or {"error": "<reason>"}
        """
        try:
            if "payload" not in incoming:
                return {"error": "payload is required"}
            
            payload = incoming["payload"]
            if not payload:
                return {"error": "payload cannot be empty"}
            
            # For this simple implementation, we'll decode the base64 payload
            # and expect it to be a JSON string (without real encryption for now)
            try:
                decoded_payload = base64.b64decode(payload).decode('utf-8')
                message_data = json.loads(decoded_payload)
            except (ValueError, json.JSONDecodeError):
                return {"error": "Invalid payload format"}
            
            if "nonceClient" not in message_data or "identity" not in message_data:
                return {"error": "Invalid message format - missing nonceClient or identity"}
            
            nonce_client = message_data["nonceClient"]
            identity = message_data["identity"]
            
            # Validate identity (for now, accept any identity)
            if not isinstance(identity, str) or not identity:
                return {"error": "Invalid identity"}
            
            # Generate server nonce
            nonce_server = secrets.randbits(64)
            
            # Store session
            session_key = f"{identity}_{nonce_client}_{nonce_server}"
            self.sessions[session_key] = {
                "identity": identity,
                "nonceClient": nonce_client,
                "nonceServer": nonce_server,
                "created": True
            }
            
            # Create response
            response_data = {
                "nonceClient": nonce_client,
                "nonceServer": nonce_server
            }
            
            # Encode response
            response_json = json.dumps(response_data)
            response_payload = base64.b64encode(response_json.encode('utf-8')).decode('utf-8')
            
            return {"payload": response_payload}
            
        except Exception as e:
            return {"error": f"RMAP system initialization failed: {str(e)}"}
    
    def handle_message2(self, incoming: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle second RMAP message (rmap-get-link).
        
        Expected incoming: {"payload": "<base64(encrypted_data)>"}
        Expected decrypted content: {"nonceServer": <u64>}
        
        Returns: {"result": "<32-hex NonceClient||NonceServer>"} or {"error": "<reason>"}
        """
        try:
            if "payload" not in incoming:
                return {"error": "payload is required"}
            
            payload = incoming["payload"]
            if not payload:
                return {"error": "payload cannot be empty"}
            
            # Decode the payload
            try:
                decoded_payload = base64.b64decode(payload).decode('utf-8')
                message_data = json.loads(decoded_payload)
            except (ValueError, json.JSONDecodeError):
                return {"error": "Invalid payload format"}
            
            if "nonceServer" not in message_data:
                return {"error": "Invalid message format - missing nonceServer"}
            
            nonce_server = message_data["nonceServer"]
            
            # Find matching session
            matching_session = None
            for session_key, session_data in self.sessions.items():
                if session_data["nonceServer"] == nonce_server:
                    matching_session = session_data
                    break
            
            if not matching_session:
                return {"error": "Invalid server nonce"}
            
            # Create session secret (concatenation of client and server nonces)
            nonce_client = matching_session["nonceClient"]
            
            # Convert nonces to hex representation (32 chars total)
            client_hex = f"{nonce_client:016x}"  # 16 hex chars for 64-bit int
            server_hex = f"{nonce_server:016x}"  # 16 hex chars for 64-bit int
            session_secret = client_hex + server_hex  # 32 hex chars total
            
            return {"result": session_secret}
            
        except Exception as e:
            return {"error": f"RMAP system initialization failed: {str(e)}"}


def create_test_payload(nonce_client: int, identity: str) -> str:
    """Create a test payload for testing purposes."""
    data = {
        "nonceClient": nonce_client,
        "identity": identity
    }
    json_data = json.dumps(data)
    return base64.b64encode(json_data.encode('utf-8')).decode('utf-8')


def create_test_payload2(nonce_server: int) -> str:
    """Create a test payload for message 2."""
    data = {
        "nonceServer": nonce_server
    }
    json_data = json.dumps(data)
    return base64.b64encode(json_data.encode('utf-8')).decode('utf-8')