"""
RMAP Handler - Complete RMAP functionality for Tatou server.

This module handles all RMAP (Roger Michael Authentication Protocol) operations:
- RMAP initialization and configuration
- Message 1 handling (rmap-initiate)
- Message 2 handling (rmap-get-link)
- Watermarked PDF creation for RMAP sessions
- Integration with the main server application
"""

from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from sqlalchemy import text

import watermarking_utils as WMUtils
from simple_rmap import SimpleRMAP


class RMAPHandler:
    """Handles all RMAP-related operations for the Tatou server."""

    def __init__(self, app: Flask, storage_dir: str, get_engine_func):
        """
        Initialize the RMAP handler.

        Args:
            app: Flask application instance
            storage_dir: Directory for storing files
            get_engine_func: Function to get database engine
        """
        self.app = app
        self.storage_dir = storage_dir
        self.get_engine = get_engine_func

        # Initialize RMAP instance
        self.rmap_instance = self._initialize_rmap()

        # Register RMAP routes
        self._register_routes()

    def _initialize_rmap(self) -> SimpleRMAP:
        """Initialize the RMAP instance with proper key paths."""
        # Set up paths for keys
        public_keys_dir = str(Path(__file__).parent.parent / "public-keys" / "pki")
        server_private_key = str(Path(__file__).parent / "server_priv.asc")

        return SimpleRMAP(
            self.storage_dir,
            public_keys_dir=public_keys_dir,
            server_private_key=server_private_key,
        )

    def _register_routes(self):
        """Register RMAP routes with the Flask app."""
        self.app.add_url_rule(
            "/rmap-initiate",
            "rmap_initiate",
            self.handle_rmap_initiate,
            methods=["POST"],
        )

        self.app.add_url_rule(
            "/rmap-get-link",
            "rmap_get_link",
            self.handle_rmap_get_link,
            methods=["POST"],
        )

    def handle_rmap_initiate(self):
        """Handle RMAP message 1 (initiate authentication)."""
        try:
            payload = request.get_json(silent=True) or {}
            result = self.rmap_instance.handle_message1(payload)

            if "error" in result:
                return jsonify(result), 400 if "required" in result["error"] else 503

            return jsonify(result), 200

        except Exception as e:
            return jsonify(
                {"error": f"RMAP system initialization failed: {str(e)}"}
            ), 503

    def handle_rmap_get_link(self):
        """Handle RMAP message 2 (get session link)."""
        try:
            payload = request.get_json(silent=True) or {}
            result = self.rmap_instance.handle_message2(payload)

            if "error" in result:
                return jsonify(result), 400 if "required" in result["error"] else 503

            # If RMAP authentication succeeded, create watermarked PDF
            if "result" in result:
                session_secret = result["result"]

                # Try to create watermarked PDF
                pdf_result = self._create_watermarked_pdf_for_session(session_secret)
                if pdf_result is not None:
                    return pdf_result  # Return error response if PDF creation failed

            return jsonify(result), 200

        except Exception as e:
            return jsonify({"error": f"RMAP system error: {str(e)}"}), 503

    def _create_watermarked_pdf_for_session(self, session_secret: str) -> Any | None:
        """
        Create a watermarked PDF for the RMAP session.

        Args:
            session_secret: The session secret from RMAP authentication

        Returns:
            Error response if creation fails, None if successful
        """
        try:
            with self.get_engine().connect() as conn:
                # Find the most recent document to watermark
                doc_row = conn.execute(
                    text(
                        """
                        SELECT id, name, path FROM Documents
                        ORDER BY creation DESC
                        LIMIT 1
                        """
                    )
                ).first()

                if not doc_row:
                    return jsonify(
                        {"error": "No documents available to watermark"}
                    ), 500

                # Check if we already created a watermarked version for this session
                existing_version = conn.execute(
                    text(
                        """
                        SELECT id, link FROM Versions
                        WHERE link = :link LIMIT 1
                        """
                    ),
                    {"link": session_secret},
                ).first()

                if existing_version:
                    # Already created, just return success
                    return None

        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500

        # Create watermarked PDF
        try:
            # Resolve file path
            storage_root = Path(self.storage_dir).resolve()
            file_path = Path(doc_row.path)
            if not file_path.is_absolute():
                file_path = storage_root / file_path
            file_path = file_path.resolve()

            if not file_path.exists():
                return jsonify({"error": "Source PDF not found"}), 500

            # Use robust-xmp watermarking (best technique)
            method = "robust-xmp"
            secret = session_secret  # Use session secret as watermark
            key = "rmap-watermark-key"  # Fixed key for RMAP watermarks

            # Check if watermarking is applicable
            applicable = WMUtils.is_watermarking_applicable(
                method=method, pdf=str(file_path), position=None
            )
            if not applicable:
                return jsonify({"error": "Watermarking not applicable to PDF"}), 500

            # Apply watermark
            wm_bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                position=None,
            )

            if not isinstance(wm_bytes, bytes | bytearray) or len(wm_bytes) == 0:
                return jsonify({"error": "Watermarking produced no output"}), 500

            # Create destination directory and file
            rmap_dir = storage_root / "rmap_watermarks"
            rmap_dir.mkdir(parents=True, exist_ok=True)

            dest_filename = f"rmap_{session_secret}.pdf"
            dest_path = rmap_dir / dest_filename

            # Write watermarked PDF
            with dest_path.open("wb") as f:
                f.write(wm_bytes)

            # Store in database
            with self.get_engine().begin() as conn:
                # Get the identity for this session from the RMAP instance
                intended_for = self.rmap_instance.get_session_identity(session_secret)
                if intended_for is None:
                    intended_for = "RMAP_CLIENT"  # Fallback to original behavior
                
                conn.execute(
                    text(
                        """
                        INSERT INTO Versions (documentid, link, intended_for,
                                            secret, method, position, path)
                        VALUES (:documentid, :link, :intended_for, :secret,
                               :method, :position, :path)
                        """
                    ),
                    {
                        "documentid": doc_row.id,
                        "link": session_secret,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": "",
                        "path": str(dest_path),
                    },
                )

            self.app.logger.info(f"Created RMAP watermarked PDF: {dest_filename}")
            return None  # Success

        except Exception as e:
            return jsonify(
                {"error": f"Failed to create watermarked PDF: {str(e)}"}
            ), 500
