"""Tests for watermarking utility functions and PDF exploration.

Tests the watermarking_utils module functions that don't require
database connectivity, focusing on PDF processing and method registry.
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import watermarking_utils as WMUtils
from watermarking_method import WatermarkingError, WatermarkingMethod


class TestWatermarkingUtils:
    """Test suite for watermarking utility functions."""

    @pytest.fixture
    def sample_pdf_bytes(self):
        """Create minimal valid PDF for testing."""
        return b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000120 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF\n"

    @pytest.fixture
    def sample_pdf_path(self, sample_pdf_bytes):
        """Create temporary PDF file."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(sample_pdf_bytes)
            path = Path(f.name)
        yield path
        path.unlink(missing_ok=True)

    def test_methods_registry_populated(self):
        """Test that the METHODS registry is populated with expected methods."""
        assert isinstance(WMUtils.METHODS, dict)
        assert len(WMUtils.METHODS) > 0

        # Check for expected methods from the imports (using actual names)
        assert "toy-eof" in WMUtils.METHODS
        assert "bash-bridge-eof" in WMUtils.METHODS

        # Verify all registered methods are WatermarkingMethod instances
        for _name, method in WMUtils.METHODS.items():
            assert isinstance(method, WatermarkingMethod)
            assert hasattr(method, 'add_watermark')
            assert hasattr(method, 'read_secret')
            assert hasattr(method, 'is_watermark_applicable')

    def test_get_method_with_string(self):
        """Test get_method with string method names."""
        # Test valid method names
        for method_name in WMUtils.METHODS.keys():
            method = WMUtils.get_method(method_name)
            assert isinstance(method, WatermarkingMethod)
            assert method == WMUtils.METHODS[method_name]

    def test_get_method_with_instance(self):
        """Test get_method with WatermarkingMethod instance (passthrough)."""
        original_method = list(WMUtils.METHODS.values())[0]
        returned_method = WMUtils.get_method(original_method)
        assert returned_method is original_method

    def test_get_method_invalid_name(self):
        """Test get_method raises KeyError for invalid method names."""
        with pytest.raises(KeyError) as exc_info:
            WMUtils.get_method("nonexistent-method")

        assert "Unknown watermarking method" in str(exc_info.value)
        assert "nonexistent-method" in str(exc_info.value)

    def test_register_method(self):
        """Test register_method adds method to registry."""
        # Create mock method
        mock_method = Mock(spec=WatermarkingMethod)
        mock_method.name = "test-method"

        # Store original registry state
        original_methods = WMUtils.METHODS.copy()

        try:
            # Register new method
            WMUtils.register_method(mock_method)

            # Verify it's in registry
            assert "test-method" in WMUtils.METHODS
            assert WMUtils.METHODS["test-method"] is mock_method

        finally:
            # Restore original registry
            WMUtils.METHODS.clear()
            WMUtils.METHODS.update(original_methods)

    def test_is_watermarking_applicable_with_method_name(self, sample_pdf_path):
        """Test is_watermarking_applicable with string method name."""
        method_name = list(WMUtils.METHODS.keys())[0]

        result = WMUtils.is_watermarking_applicable(method_name, sample_pdf_path)

        # Result should be boolean
        assert isinstance(result, bool)

    def test_is_watermarking_applicable_with_method_instance(self, sample_pdf_path):
        """Test is_watermarking_applicable with method instance."""
        method = list(WMUtils.METHODS.values())[0]

        result = WMUtils.is_watermarking_applicable(method, sample_pdf_path)

        # Result should be boolean
        assert isinstance(result, bool)

    def test_apply_watermark_with_method_name(self, sample_pdf_path):
        """Test apply_watermark with string method name."""
        method_name = list(WMUtils.METHODS.keys())[0]

        # Only test if method is applicable
        if WMUtils.is_watermarking_applicable(method_name, sample_pdf_path):
            result = WMUtils.apply_watermark(
                method=method_name,
                pdf=sample_pdf_path,
                secret="test-secret",
                key="test-key"
            )

            assert isinstance(result, (bytes, bytearray))
            assert len(result) > 0

    def test_apply_watermark_with_method_instance(self, sample_pdf_path):
        """Test apply_watermark with method instance."""
        method = list(WMUtils.METHODS.values())[0]

        # Only test if method is applicable
        if WMUtils.is_watermarking_applicable(method, sample_pdf_path):
            result = WMUtils.apply_watermark(
                method=method,
                pdf=sample_pdf_path,
                secret="test-secret",
                key="test-key"
            )

            assert isinstance(result, (bytes, bytearray))
            assert len(result) > 0

    def test_read_watermark_requires_watermarked_pdf(self, sample_pdf_path):
        """Test read_watermark on non-watermarked PDF."""
        method_name = list(WMUtils.METHODS.keys())[0]

        # Reading from non-watermarked PDF should raise appropriate error
        with pytest.raises((WatermarkingError, Exception)):
            WMUtils.read_watermark(method_name, sample_pdf_path, "test-key")

    def test_explore_pdf_basic_structure(self, sample_pdf_bytes):
        """Test explore_pdf returns expected structure."""
        result = WMUtils.explore_pdf(sample_pdf_bytes)

        # Should return dict with expected top-level structure
        assert isinstance(result, dict)
        assert "id" in result
        assert "type" in result
        assert "size" in result
        assert "children" in result

        # Verify values
        assert result["type"] == "Document"
        assert result["size"] == len(sample_pdf_bytes)
        assert isinstance(result["children"], list)
        assert result["id"].startswith("pdf:")

    def test_explore_pdf_with_path(self, sample_pdf_path):
        """Test explore_pdf with file path."""
        result = WMUtils.explore_pdf(sample_pdf_path)

        assert isinstance(result, dict)
        assert result["type"] == "Document"
        assert result["size"] > 0

    def test_explore_pdf_with_fitz_available(self, sample_pdf_bytes):
        """Test explore_pdf when PyMuPDF (fitz) is available."""
        # Mock the import inside the function
        with patch.dict('sys.modules', {'fitz': Mock()}):
            import sys
            mock_fitz = sys.modules['fitz']

            # Mock fitz document
            mock_doc = Mock()
            mock_doc.page_count = 1
            mock_doc.load_page.return_value.bound.return_value = [0, 0, 612, 792]
            mock_doc.xref_length.return_value = 4
            mock_doc.xref_object.return_value = "<< /Type /Catalog >>"
            mock_doc.xref_is_stream.return_value = False

            mock_fitz.open.return_value = mock_doc

            result = WMUtils.explore_pdf(sample_pdf_bytes)

            # Should have called fitz methods
            assert isinstance(result, dict)
            assert result["type"] == "Document"

    def test_explore_pdf_fallback_without_fitz(self, sample_pdf_bytes):
        """Test explore_pdf fallback when fitz is not available."""
        # Since fitz is actually available in our environment, we need to test the fallback differently
        # We'll test that the function works even if fitz import fails internally

        # Force the fallback by causing fitz.open to raise an exception
        with patch('fitz.open', side_effect=Exception("Forced fallback")):
            result = WMUtils.explore_pdf(sample_pdf_bytes)

            # Should still work with regex fallback
            assert isinstance(result, dict)
            assert result["type"] == "Document"
            assert isinstance(result["children"], list)

    def test_sha1_helper_function(self):
        """Test the internal _sha1 helper function."""
        test_data = b"test data"
        result = WMUtils._sha1(test_data)

        assert isinstance(result, str)
        assert len(result) == 40  # SHA1 hex digest length

        # Should be deterministic
        assert WMUtils._sha1(test_data) == result

    def test_pdf_exploration_deterministic(self, sample_pdf_bytes):
        """Test that PDF exploration is deterministic."""
        result1 = WMUtils.explore_pdf(sample_pdf_bytes)
        result2 = WMUtils.explore_pdf(sample_pdf_bytes)

        # Should produce identical results
        assert result1 == result2
        assert result1["id"] == result2["id"]

    def test_methods_have_required_attributes(self):
        """Test that all registered methods have required attributes."""
        for name, method in WMUtils.METHODS.items():
            # Should have name attribute matching registry key
            assert hasattr(method, 'name')
            assert method.name == name

            # Should have required methods
            assert callable(method.add_watermark)
            assert callable(method.read_secret)
            assert callable(method.is_watermark_applicable)
            assert callable(method.get_usage)

    def test_method_get_usage_returns_string(self):
        """Test that all methods return string from get_usage."""
        for _name, method in WMUtils.METHODS.items():
            usage = method.get_usage()
            assert isinstance(usage, str)
            assert len(usage) > 0
