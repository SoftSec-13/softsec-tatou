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
from pathlib import Path
from typing import Any, Dict, Optional


class SimpleRMAP:
    """Simple RMAP implementation for educational purposes."""

    def __init__(self, storage_dir: str):
        self.storage_dir = storage_dir
        self.sessions = {}  # In-memory session storage
        self.watermarked_pdfs = {}  # Store metadata about watermarked PDFs
        
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
        
        Returns: {"result": "<session_secret>"} or {"error": "<reason>"}
        where session_secret is a link to a watermarked PDF created using the robust-xmp method.
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
    
    def create_watermarked_pdf_link(self, session_secret: str, document_id: int, app_config: Dict[str, Any]) -> Optional[str]:
        """
        Create a watermarked PDF using the session secret and return a link to it.
        
        This integrates with the existing watermarking system to create a PDF
        watermarked with the session secret using the robust-xmp method.
        """
        session_info = self.get_session_info(session_secret)
        if not session_info:
            return None
            
        # For now, return the session secret as the link
        # In a real implementation, this would create an actual watermarked PDF
        # and store it, then return a link to download it
        return session_secret


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