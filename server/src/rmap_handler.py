"""
RMAP Handler - Complete RMAP functionality for Tatou server.

This module handles all RMAP (Roger Michael Authentication Protocol) operations:
- RMAP initialization and configuration
- Message 1 handling (rmap-initiate)
- Message 2 handling (rmap-get-link)
- Watermarked PDF creation for RMAP sessions
- Integration with the main server application
"""

import hashlib
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
                # Check if we already created a watermarked version for this session
                existing_version = conn.execute(
                    text(
                        """
                        SELECT id, link, path FROM Versions
                        WHERE link = :link LIMIT 1
                        """
                    ),
                    {"link": session_secret},
                ).first()

                if existing_version:
                    # Check if the file actually exists on disk
                    existing_path = Path(existing_version.path)
                    if existing_path.exists():
                        self.app.logger.info(
                            f"RMAP watermarked PDF already exists: {session_secret}"
                        )
                        return None
                    else:
                        # File is missing, delete the database entry and recreate
                        with self.get_engine().begin() as delete_conn:
                            delete_conn.execute(
                                text("DELETE FROM Versions WHERE id = :id"),
                                {"id": existing_version.id},
                            )
                        self.app.logger.warning(
                            f"Deleted missing RMAP watermarked PDF entry:"
                            f" {session_secret}"
                        )

        except Exception as e:
            return jsonify({"error": f"Database error: {str(e)}"}), 500

        # Create watermarked PDF
        try:
            # Resolve file path
            storage_root = Path(self.storage_dir).resolve()
            # Always use static/Group_13.pdf for watermarking
            file_path = Path(__file__).parent / "static" / "Group_13.pdf"
            file_path = file_path.resolve()

            if not file_path.exists():
                self.app.logger.error(f"Source PDF not found: {file_path}")
                return jsonify({"error": "Source PDF not found"}), 500

            # Add file to database if not already present
            try:
                with self.get_engine().begin() as conn:
                    existing_file = conn.execute(
                        text(
                            """
                            SELECT id FROM Documents WHERE path = :path LIMIT 1
                            """
                        ),
                        {"path": str(file_path)},
                    ).first()

                    if not existing_file:
                        # Need to insert a full Documents row following schema:
                        # (name, path, ownerid, sha256, size)
                        # We don't have an authenticated user in RMAP flow, so we
                        # assign ownership to the earliest (lowest id) existing user
                        # to satisfy the FK. If no users exist, we cannot proceed.
                        owner_row = conn.execute(
                            text("SELECT id FROM Users WHERE email = 'service@rmap.su'")
                        ).first()
                        if not owner_row:
                            raise RuntimeError(
                                "No users exist to own RMAP base document; "
                                "create a user first"
                            )
                        owner_id = int(owner_row.id)

                        # Gather file metadata
                        try:
                            pdf_bytes = file_path.read_bytes()
                        except Exception as fe:
                            raise RuntimeError(
                                f"Failed reading source PDF for RMAP insertion: {fe}"
                            ) from fe
                        sha_hex = hashlib.sha256(pdf_bytes).hexdigest()
                        size = len(pdf_bytes)
                        name = file_path.name

                        # Attempt insert; tolerate race where another thread
                        # inserted meanwhile
                        try:
                            conn.execute(
                                text(
                                    """
                                    INSERT INTO Documents (name, path, ownerid,
                                                          sha256, size)
                                    VALUES (:name, :path, :ownerid,
                                            UNHEX(:sha256hex), :size)
                                    """
                                ),
                                {
                                    "name": name,
                                    "path": str(file_path),
                                    "ownerid": owner_id,
                                    "sha256hex": sha_hex,
                                    "size": int(size),
                                },
                            )
                        except Exception as race_e:
                            # If due to unique path constraint, fetch existing id;
                            # otherwise re-raise
                            try:
                                existing_file = conn.execute(
                                    text(
                                        "SELECT id FROM Documents WHERE path = :path "
                                        "LIMIT 1"
                                    ),
                                    {"path": str(file_path)},
                                ).first()
                                if not existing_file:
                                    raise race_e
                            except Exception:
                                raise
            except Exception as db_e:
                self.app.logger.error(f"Failed to add source PDF to database: {db_e}")
                return jsonify({"error": f"Database error: {str(db_e)}"}), 500

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

            # Store in database with proper error handling
            try:
                with self.get_engine().begin() as conn:
                    # Get the identity for this session from the RMAP instance
                    intended_for = self.rmap_instance.get_session_identity(
                        session_secret
                    )
                    if intended_for is None or intended_for == "Unknown_Group":
                        # Use a more descriptive fallback that
                        # indicates RMAP authentication
                        intended_for = "RMAP_CLIENT"

                    # Get file ID
                    file_record = conn.execute(
                        text(
                            """
                            SELECT id FROM Documents WHERE path = :path LIMIT 1
                            """
                        ),
                        {"path": str(file_path)},
                    ).first()
                    if file_record is None:
                        return jsonify({"error": "File record not found"}), 500
                    did = file_record.id

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
                            "documentid": did,
                            "link": session_secret,
                            "intended_for": intended_for,
                            "secret": secret,
                            "method": method,
                            "position": "",
                            "path": str(dest_path),
                        },
                    )

                self.app.logger.info(
                    f"Created RMAP watermarked PDF: "
                    f"{dest_filename} for session: {session_secret}"
                )
                return None  # Success

            except Exception as db_e:
                # If database insert fails, clean up the file
                try:
                    dest_path.unlink(missing_ok=True)
                except Exception as cleanup_e:
                    self.app.logger.error(
                        f"Failed to cleanup file after DB error: {cleanup_e}"
                    )

                self.app.logger.error(
                    f"Database insertion failed for RMAP session"
                    f" {session_secret}: {db_e}"
                )
                return jsonify(
                    {"error": f"Database insertion failed: {str(db_e)}"}
                ), 500

        except Exception as e:
            self.app.logger.error(
                f"Failed to create watermarked PDF for session"
                f" {session_secret}: {str(e)}"
            )
            return jsonify(
                {"error": f"Failed to create watermarked PDF: {str(e)}"}
            ), 500
