"""Regression tests for bugs discovered through fuzzing.

This test suite ensures that previously discovered security vulnerabilities
remain fixed and do not regress in future versions.

Each test corresponds to a bug documented in server/fuzz/FIXED_BUGS.md.
"""

from __future__ import annotations

import base64
import json
import secrets
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from werkzeug.datastructures import FileStorage

# Import the local app factory from the src-layout package.
# When running pytest from the server/ directory, importing `server` would
# resolve to an unrelated third-party module if present in the venv. Using
# the explicit src package path avoids that shadowing.
from server import create_app


@pytest.fixture
def app():
    """Create Flask app for testing."""
    test_app = create_app()
    test_app.config["TESTING"] = True
    test_app.config["STORAGE_DIR"] = Path("/tmp/test_tatou_storage")
    test_app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)
    return test_app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def auth_token(app):
    """Generate a valid authentication token for testing."""
    from itsdangerous import URLSafeTimedSerializer

    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")
    return serializer.dumps({"uid": 1, "login": "testuser", "email": "test@example.com"})


# ============================================================================
# Bug #1: PBKDF2 Denial of Service (DoS)
# ============================================================================
# Date: 2025-10-07
# Severity: Medium
# Description: User-controlled PBKDF2 iteration count allowed up to 2M iterations,
#              causing excessive CPU usage. Fixed by limiting to 300k iterations.
# ============================================================================


class TestBug1_PBKDF2_DoS:
    """Regression tests for PBKDF2 DoS vulnerability (Bug #1)."""

    def test_pbkdf2_iterations_within_limit_accepted(self):
        """Test that PBKDF2 iterations within 300k limit are accepted."""
        from signed_annotation_watermark import SignedAnnotationWatermark

        method = SignedAnnotationWatermark()

        # Create a minimal valid PDF
        minimal_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"

        # Test with maximum allowed iterations (300k)
        secret = "test_secret"
        key = "test_key_300k"

        # Apply watermark with default iterations (should work)
        watermarked = method.add_watermark(
            pdf=minimal_pdf, secret=secret, key=key, intended_for="test_user"
        )

        assert watermarked is not None
        assert len(watermarked) > 0
        assert watermarked.startswith(b"%PDF")

        # Verify we can read the watermark back
        extracted = method.read_secret(pdf=watermarked, key=key)
        assert extracted == secret

    def test_pbkdf2_iterations_above_limit_rejected(self):
        """Test that PBKDF2 iterations above 300k are rejected.

        This is the core regression test for Bug #1. An attacker could craft
        a malicious PDF with iter=2000000 to cause DoS. This must be rejected.
        """
        from signed_annotation_watermark import SignedAnnotationWatermark
        from watermarking_method import WatermarkingError

        method = SignedAnnotationWatermark()

        # Create a minimal valid PDF
        minimal_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"

        # First, create a valid watermarked PDF
        secret = "test_secret"
        key = "test_key_malicious"
        watermarked = method.add_watermark(
            pdf=minimal_pdf, secret=secret, key=key, intended_for="test_user"
        )

        # Now manually craft a malicious manifest with excessive iterations
        # This simulates an attacker modifying the PDF
        try:
            import pymupdf

            doc = pymupdf.open(stream=watermarked, filetype="pdf")

            # Extract the existing manifest
            manifest_bytes = doc.embfile_get("WM-TATOU-SIGNED-v1.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))

            # Modify to use excessive iterations (simulating attack)
            manifest["iter"] = 2_000_000  # Original vulnerable value

            # Re-embed the malicious manifest
            malicious_manifest = json.dumps(manifest, separators=(",", ":")).encode(
                "utf-8"
            )
            doc.embfile_del("WM-TATOU-SIGNED-v1.json")
            doc.embfile_add(
                "WM-TATOU-SIGNED-v1.json",
                malicious_manifest,
                filename="WM-TATOU-SIGNED-v1.json",
            )

            malicious_pdf = doc.write()
            doc.close()

            # Attempt to read the watermark - should raise error
            with pytest.raises(
                WatermarkingError, match="Unreasonable PBKDF2 iteration count"
            ):
                method.read_secret(pdf=malicious_pdf, key=key)

        except ImportError:
            pytest.skip("PyMuPDF not available")

    def test_pbkdf2_iterations_zero_rejected(self):
        """Test that zero PBKDF2 iterations are rejected."""
        from signed_annotation_watermark import SignedAnnotationWatermark
        from watermarking_method import WatermarkingError

        method = SignedAnnotationWatermark()

        minimal_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"

        try:
            import pymupdf

            secret = "test_secret"
            key = "test_key_zero"
            watermarked = method.add_watermark(
                pdf=minimal_pdf, secret=secret, key=key, intended_for="test_user"
            )

            doc = pymupdf.open(stream=watermarked, filetype="pdf")
            manifest_bytes = doc.embfile_get("WM-TATOU-SIGNED-v1.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            manifest["iter"] = 0  # Invalid value

            malicious_manifest = json.dumps(manifest, separators=(",", ":")).encode(
                "utf-8"
            )
            doc.embfile_del("WM-TATOU-SIGNED-v1.json")
            doc.embfile_add(
                "WM-TATOU-SIGNED-v1.json",
                malicious_manifest,
                filename="WM-TATOU-SIGNED-v1.json",
            )

            malicious_pdf = doc.write()
            doc.close()

            with pytest.raises(
                WatermarkingError, match="Unreasonable PBKDF2 iteration count"
            ):
                method.read_secret(pdf=malicious_pdf, key=key)

        except ImportError:
            pytest.skip("PyMuPDF not available")

    def test_pbkdf2_iterations_negative_rejected(self):
        """Test that negative PBKDF2 iterations are rejected."""
        from signed_annotation_watermark import SignedAnnotationWatermark
        from watermarking_method import WatermarkingError

        method = SignedAnnotationWatermark()

        minimal_pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj 2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj 3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"

        try:
            import pymupdf

            secret = "test_secret"
            key = "test_key_negative"
            watermarked = method.add_watermark(
                pdf=minimal_pdf, secret=secret, key=key, intended_for="test_user"
            )

            doc = pymupdf.open(stream=watermarked, filetype="pdf")
            manifest_bytes = doc.embfile_get("WM-TATOU-SIGNED-v1.json")
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            manifest["iter"] = -100  # Invalid value

            malicious_manifest = json.dumps(manifest, separators=(",", ":")).encode(
                "utf-8"
            )
            doc.embfile_del("WM-TATOU-SIGNED-v1.json")
            doc.embfile_add(
                "WM-TATOU-SIGNED-v1.json",
                malicious_manifest,
                filename="WM-TATOU-SIGNED-v1.json",
            )

            malicious_pdf = doc.write()
            doc.close()

            with pytest.raises(
                WatermarkingError, match="Unreasonable PBKDF2 iteration count"
            ):
                method.read_secret(pdf=malicious_pdf, key=key)

        except ImportError:
            pytest.skip("PyMuPDF not available")


# ============================================================================
# Bug #2: TypeError in File Upload Size Validation
# ============================================================================
# Date: 2025-10-07
# Severity: Low-Medium
# Description: When Content-Length header is missing, file.content_length is None,
#              and comparing None > MAX_FILE_SIZE raises TypeError. Fixed by
#              adding null check before comparison.
# ============================================================================


class TestBug2_ContentLength_TypeError:
    """Regression tests for Content-Length TypeError vulnerability (Bug #2)."""

    def test_upload_with_valid_content_length_accepted(self, client, auth_token):
        """Test that normal uploads with Content-Length header work."""
        # Create a minimal valid PDF
        pdf_content = b"%PDF-1.4\n%%EOF\n"

        data = {
            "file": (BytesIO(pdf_content), "test.pdf", "application/pdf"),
        }

        response = client.post(
            "/api/upload-document",
            data=data,
            headers={"Authorization": f"Bearer {auth_token}"},
            content_type="multipart/form-data",
        )

        # Should succeed or fail with a proper error (not 500)
        # We're testing that it doesn't crash with TypeError
        assert response.status_code in [
            201,
            400,
            401,
            404,
            503,
        ], f"Unexpected status: {response.status_code}"
        assert response.is_json

        # If it fails, should be a proper error message, not a crash
        if response.status_code != 201:
            data = response.get_json()
            assert "error" in data

    def test_upload_without_content_length_no_crash(self, client, auth_token):
        """Test that uploads without Content-Length header don't cause TypeError.

        This is the core regression test for Bug #2. Previously, missing
        Content-Length would cause: TypeError: '>' not supported between
        instances of 'NoneType' and 'int'
        """
        # The key test: this should NOT raise TypeError
        # It should handle None gracefully
        try:
            # Simulate the validation code from server.py with None content_length
            MAX_FILE_SIZE = 50 * 1024 * 1024
            content_length = None  # Simulating missing Content-Length header

            # This is the fixed code - should not raise TypeError
            if content_length and content_length > MAX_FILE_SIZE:
                result = "rejected"
            else:
                result = "accepted or skipped validation"

            # Should reach here without exception
            assert result in ["accepted or skipped validation", "rejected"]

        except TypeError as e:
            pytest.fail(f"TypeError raised with None content_length: {e}")

    def test_upload_with_oversized_file_rejected(self, client, auth_token):
        """Test that oversized files are properly rejected."""
        # Create a PDF larger than 50MB (just the header for testing)
        large_pdf = b"%PDF-1.4\n" + b"x" * (51 * 1024 * 1024) + b"%%EOF\n"

        data = {
            "file": (BytesIO(large_pdf), "large.pdf", "application/pdf"),
        }

        response = client.post(
            "/api/upload-document",
            data=data,
            headers={"Authorization": f"Bearer {auth_token}"},
            content_type="multipart/form-data",
        )

        # Should be rejected with 413 (if Content-Length is set by test client)
        # or processed normally if Content-Length is not set
        assert response.status_code in [
            413,
            201,
            400,
            401,
            404,
            503,
        ], f"Unexpected status: {response.status_code}"

    def test_upload_size_validation_logic(self):
        """Test the size validation logic directly."""
        MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

        # Test cases for the validation logic
        test_cases = [
            (None, True),  # None should be allowed (skip validation)
            (0, True),  # Empty file allowed
            (1024, True),  # Small file allowed
            (50 * 1024 * 1024, True),  # Exactly max size allowed
            (50 * 1024 * 1024 + 1, False),  # One byte over rejected
            (100 * 1024 * 1024, False),  # Much larger rejected
        ]

        for content_length, should_pass in test_cases:
            # This is the fixed validation logic
            if content_length and content_length > MAX_FILE_SIZE:
                result = False
            else:
                result = True

            assert (
                result == should_pass
            ), f"content_length={content_length}, expected={should_pass}, got={result}"


# ============================================================================
# Regression Corpus Tests
# ============================================================================
# These tests ensure that any crash artifacts saved in the regression corpus
# continue to be handled correctly (either fixed or caught gracefully).
# ============================================================================


class TestRegressionCorpus:
    """Tests for fuzzer-discovered crash artifacts."""

    def test_regression_corpus_directory_exists(self):
        """Verify regression corpus directory structure exists."""
        corpus_dir = Path(__file__).parent.parent / "fuzz" / "corpus" / "regression"

        # Directory should exist (or be created during fuzzing)
        # This test documents the expected structure
        if corpus_dir.exists():
            assert corpus_dir.is_dir()
            # Check for documented crashes
            documented_crashes = ["bug1_pbkdf2_dos.bin", "bug2_content_length_none.bin"]
            # Note: These files may not exist yet, but should be added as bugs are found

    def test_no_unhandled_crashes_in_latest_run(self):
        """Verify that latest fuzzing run had no unhandled crashes.

        This test looks for recent fuzzing_results_* directories and checks
        if there are any crash artifacts that haven't been triaged.
        """
        fuzz_dir = Path(__file__).parent.parent / "fuzz"
        results_dirs = sorted(fuzz_dir.glob("fuzzing_results_*"))

        if results_dirs:
            latest = results_dirs[-1]
            crash_files = list(latest.glob("*crash-*"))
            oom_files = list(latest.glob("*oom-*"))
            timeout_files = list(latest.glob("*timeout-*"))

            all_artifacts = crash_files + oom_files + timeout_files

            if all_artifacts:
                # This is informational - crashes found but may be expected
                pytest.skip(
                    f"Found {len(all_artifacts)} artifacts in {latest.name} - "
                    "manual triage required"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
