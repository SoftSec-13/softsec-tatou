"""
Tests for RMAP authentication endpoints.

These tests cover the RMAP (Roger Michael Authentication Protocol) implementation
including both the initiate and get-link endpoints.
"""

import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add the src directory to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from server import create_app


class TestRMAPRoutes:
    """Test cases for RMAP authentication endpoints."""

    @pytest.fixture
    def app(self):
        """Create test Flask app with temporary directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create temporary directories
            storage_dir = temp_path / "storage"
            client_keys_dir = temp_path / "client_keys"
            storage_dir.mkdir()
            client_keys_dir.mkdir()

            # Create mock key files
            server_pub = temp_path / "server_pub.asc"
            server_priv = temp_path / "server_priv.asc"
            server_pub.write_text(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                "mock_public_key\n"  # pragma: allowlist secret
                "-----END PGP PUBLIC KEY BLOCK-----"
            )
            server_priv.write_text(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
                "mock_private_key\n"  # pragma: allowlist secret
                "-----END PGP PRIVATE KEY BLOCK-----"
            )

            # Create a mock client key
            group7_key = client_keys_dir / "Group7.asc"
            group7_key.write_text(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
                "mock_client_key\n"  # pragma: allowlist secret
                "-----END PGP PUBLIC KEY BLOCK-----"
            )

            app = create_app()
            app.config.update(
                {
                    "TESTING": True,
                    "SECRET_KEY": "test-secret-key",  # pragma: allowlist secret
                    "STORAGE_DIR": storage_dir,
                    "RMAP_CLIENT_KEYS_DIR": client_keys_dir,
                    "RMAP_SERVER_PUBLIC_KEY": server_pub,
                    "RMAP_SERVER_PRIVATE_KEY": server_priv,
                    "DB_HOST": "localhost",
                    "DB_PORT": "3306",
                    "DB_USER": "test",
                    "DB_PASSWORD": "test",  # pragma: allowlist secret
                    "DB_NAME": "test_db",
                }
            )
            yield app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    @pytest.fixture
    def mock_rmap_system(self):
        """Create a mock RMAP system."""
        mock_rmap = Mock()
        mock_rmap.process_message_1.return_value = "mock_response_payload"
        mock_rmap.process_message_2.return_value = (
            "mock_session_secret"  # pragma: allowlist secret
        )
        mock_rmap.get_session_identity.return_value = "Group7"
        return mock_rmap

    @pytest.fixture
    def mock_db_connection(self):
        """Create a mock database connection."""
        mock_conn = Mock()
        mock_row = Mock()
        mock_row.id = 1
        mock_row.name = "test_document.pdf"
        mock_row.path = "test_document.pdf"
        mock_conn.execute.return_value.first.return_value = mock_row
        return mock_conn

    def test_rmap_initiate_success(self, client, mock_rmap_system):
        """Test successful RMAP initiate request."""
        with patch("server._get_rmap_system", return_value=mock_rmap_system):
            response = client.post(
                "/rmap-initiate", json={"payload": "encrypted_message_1_base64"}
            )

            assert response.status_code == 200
            data = response.get_json()
            assert "payload" in data
            assert data["payload"] == "mock_response_payload"
            mock_rmap_system.process_message_1.assert_called_once_with(
                "encrypted_message_1_base64"
            )

    def test_rmap_initiate_missing_payload(self, client):
        """Test RMAP initiate request with missing payload."""
        response = client.post("/rmap-initiate", json={})

        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "payload is required"

    def test_rmap_initiate_invalid_json(self, client):
        """Test RMAP initiate request with invalid JSON."""
        response = client.post("/rmap-initiate", data="invalid json")

        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "payload is required"

    def test_rmap_initiate_rmap_system_failure(self, client):
        """Test RMAP initiate when RMAP system initialization fails."""
        with patch(
            "server._get_rmap_system", side_effect=Exception("RMAP init failed")
        ):
            response = client.post(
                "/rmap-initiate", json={"payload": "encrypted_message_1_base64"}
            )

            assert response.status_code == 503
            data = response.get_json()
            assert data["error"] == "RMAP system initialization failed"

    def test_rmap_initiate_invalid_message(self, client, mock_rmap_system):
        """Test RMAP initiate with invalid message."""
        mock_rmap_system.process_message_1.side_effect = Exception("Invalid message")

        with patch("server._get_rmap_system", return_value=mock_rmap_system):
            response = client.post(
                "/rmap-initiate", json={"payload": "invalid_encrypted_message"}
            )

            assert response.status_code == 400
            data = response.get_json()
            assert data["error"] == "Invalid RMAP message or unknown identity"

    def test_rmap_get_link_success(
        self, client, mock_rmap_system, mock_db_connection, app
    ):
        """Test successful RMAP get-link request."""
        # Create a test PDF file
        storage_dir = Path(app.config["STORAGE_DIR"])
        test_pdf = storage_dir / "test_document.pdf"
        test_pdf.write_bytes(b"%PDF-1.4\ntest pdf content")

        mock_watermark_bytes = b"%PDF-1.4\nwatermarked pdf content"

        with (
            patch("server._get_rmap_system", return_value=mock_rmap_system),
            patch("server.get_engine") as mock_engine,
            patch("server._get_best_watermarking_method", return_value="method1"),
            patch("server.WMUtils.apply_watermark", return_value=mock_watermark_bytes),
        ):
            # Setup database mock
            mock_engine.return_value.connect.return_value.__enter__.return_value = (
                mock_db_connection
            )
            mock_engine.return_value.begin.return_value.__enter__.return_value = (
                mock_db_connection
            )

            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 200
            data = response.get_json()
            assert "result" in data
            assert len(data["result"]) == 32  # 32-hex string
            mock_rmap_system.process_message_2.assert_called_once_with(
                "encrypted_message_2_base64"
            )

    def test_rmap_get_link_missing_payload(self, client):
        """Test RMAP get-link request with missing payload."""
        response = client.post("/rmap-get-link", json={})

        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "payload is required"

    def test_rmap_get_link_rmap_system_failure(self, client):
        """Test RMAP get-link when RMAP system initialization fails."""
        with patch(
            "server._get_rmap_system", side_effect=Exception("RMAP init failed")
        ):
            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 503
            data = response.get_json()
            assert data["error"] == "RMAP system initialization failed"

    def test_rmap_get_link_invalid_message(self, client, mock_rmap_system):
        """Test RMAP get-link with invalid message."""
        mock_rmap_system.process_message_2.side_effect = Exception("Invalid message")

        with patch("server._get_rmap_system", return_value=mock_rmap_system):
            response = client.post(
                "/rmap-get-link", json={"payload": "invalid_encrypted_message"}
            )

            assert response.status_code == 400
            data = response.get_json()
            assert data["error"] == "Invalid RMAP message or session expired"

    def test_rmap_get_link_no_session_secret(self, client, mock_rmap_system):
        """Test RMAP get-link when no session secret is returned."""
        mock_rmap_system.process_message_2.return_value = None

        with patch("server._get_rmap_system", return_value=mock_rmap_system):
            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 400
            data = response.get_json()
            assert data["error"] == "Invalid RMAP message or session expired"

    def test_rmap_get_link_no_watermarking_method(self, client, mock_rmap_system):
        """Test RMAP get-link when no watermarking method is available."""
        with (
            patch("server._get_rmap_system", return_value=mock_rmap_system),
            patch("server._get_best_watermarking_method", return_value=None),
        ):
            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 503
            data = response.get_json()
            assert data["error"] == "No watermarking methods available"

    def test_rmap_get_link_no_documents(
        self, client, mock_rmap_system, mock_db_connection
    ):
        """Test RMAP get-link when no documents are available."""
        mock_db_connection.execute.return_value.first.return_value = None

        with (
            patch("server._get_rmap_system", return_value=mock_rmap_system),
            patch("server.get_engine") as mock_engine,
            patch("server._get_best_watermarking_method", return_value="method1"),
        ):
            mock_engine.return_value.connect.return_value.__enter__.return_value = (
                mock_db_connection
            )

            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 404
            data = response.get_json()
            assert data["error"] == "No documents available for watermarking"

    def test_rmap_get_link_document_not_found(
        self, client, mock_rmap_system, mock_db_connection, app
    ):
        """Test RMAP get-link when document file doesn't exist."""
        with (
            patch("server._get_rmap_system", return_value=mock_rmap_system),
            patch("server.get_engine") as mock_engine,
            patch("server._get_best_watermarking_method", return_value="method1"),
        ):
            mock_engine.return_value.connect.return_value.__enter__.return_value = (
                mock_db_connection
            )

            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 410
            data = response.get_json()
            assert data["error"] == "Document file not found"

    def test_rmap_get_link_watermarking_failure(
        self, client, mock_rmap_system, mock_db_connection, app
    ):
        """Test RMAP get-link when watermarking fails."""
        # Create a test PDF file
        storage_dir = Path(app.config["STORAGE_DIR"])
        test_pdf = storage_dir / "test_document.pdf"
        test_pdf.write_bytes(b"%PDF-1.4\ntest pdf content")

        with (
            patch("server._get_rmap_system", return_value=mock_rmap_system),
            patch("server.get_engine") as mock_engine,
            patch("server._get_best_watermarking_method", return_value="method1"),
            patch(
                "server.WMUtils.apply_watermark",
                side_effect=Exception("Watermarking failed"),
            ),
        ):
            mock_engine.return_value.connect.return_value.__enter__.return_value = (
                mock_db_connection
            )

            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 500
            data = response.get_json()
            assert data["error"] == "Watermarking failed"

    def test_rmap_get_link_empty_watermark_output(
        self, client, mock_rmap_system, mock_db_connection, app
    ):
        """Test RMAP get-link when watermarking produces empty output."""
        # Create a test PDF file
        storage_dir = Path(app.config["STORAGE_DIR"])
        test_pdf = storage_dir / "test_document.pdf"
        test_pdf.write_bytes(b"%PDF-1.4\ntest pdf content")

        with (
            patch("server._get_rmap_system", return_value=mock_rmap_system),
            patch("server.get_engine") as mock_engine,
            patch("server._get_best_watermarking_method", return_value="method1"),
            patch("server.WMUtils.apply_watermark", return_value=b""),
        ):
            mock_engine.return_value.connect.return_value.__enter__.return_value = (
                mock_db_connection
            )

            response = client.post(
                "/rmap-get-link", json={"payload": "encrypted_message_2_base64"}
            )

            assert response.status_code == 500
            data = response.get_json()
            assert data["error"] == "Watermarking produced no output"
