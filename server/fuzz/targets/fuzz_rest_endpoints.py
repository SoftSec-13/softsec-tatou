#!/usr/bin/env python3
"""Unified REST API fuzzer with endpoint-specific builders.

This target replaces api_fuzzer.py and inputs_fuzzer.py with a cleaner
architecture that uses typed models and builders for each endpoint.
"""

from __future__ import annotations

import io
import logging
import sys
import time
from pathlib import Path

# Add fuzz directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import atheris

with atheris.instrument_imports():
    from builders import (
        build_auth_header,
        build_create_user,
        build_create_watermark,
        build_delete_document,
        build_fuzzed_auth,
        build_login,
        build_read_watermark,
        build_upload_document,
    )
    from harness import cleanup_storage, get_app
    from models import PDFInput
    from oracles import check_endpoint_invariants, check_security_vulnerabilities

logger = logging.getLogger(__name__)


def fuzz_one_input(data: bytes) -> None:
    """Fuzz REST API endpoints with endpoint-specific builders.

    Args:
        data: Fuzzed bytes for endpoint selection and payload generation
    """
    if not data:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Select endpoint (now includes get-version and metrics)
    endpoint_choice = fdp.ConsumeIntInRange(0, 9)

    app = get_app()

    try:
        with app.test_client() as client:
            start_time = time.time()

            if endpoint_choice == 0:
                # create-user
                payload = build_create_user(fdp)
                resp = client.post("/api/create-user", json=payload.to_dict())
                check_endpoint_invariants(resp, "/api/create-user")
                check_security_vulnerabilities(resp, "/api/create-user", start_time)

            elif endpoint_choice == 1:
                # login
                payload = build_login(fdp)
                resp = client.post("/api/login", json=payload.to_dict())
                check_endpoint_invariants(resp, "/api/login")
                check_security_vulnerabilities(resp, "/api/login", start_time)

            elif endpoint_choice == 2:
                # upload-document
                pdf_bytes = fdp.ConsumeBytes(4096) or b"%PDF-1.4\n%%EOF\n"
                filename = fdp.ConsumeUnicodeNoSurrogates(100) or "fuzz.pdf"
                pdf_input = PDFInput.from_bytes(pdf_bytes, filename)
                pdf_input, payload = build_upload_document(pdf_input, fdp)

                auth_header = build_auth_header()
                resp = client.post(
                    "/api/upload-document",
                    headers={"Authorization": auth_header},
                    data={
                        "file": (
                            io.BytesIO(pdf_input.content),
                            pdf_input.filename,
                            pdf_input.mimetype,
                        ),
                        **payload.to_form_data(),
                    },
                    content_type="multipart/form-data",
                )
                check_endpoint_invariants(resp, "/api/upload-document")
                check_security_vulnerabilities(resp, "/api/upload-document", start_time)

            elif endpoint_choice == 3:
                # list-documents
                auth_header = build_fuzzed_auth(fdp)
                resp = client.get(
                    "/api/list-documents", headers={"Authorization": auth_header}
                )
                check_endpoint_invariants(resp, "/api/list-documents")
                check_security_vulnerabilities(resp, "/api/list-documents", start_time)

            elif endpoint_choice == 4:
                # get-document
                doc_id = fdp.ConsumeIntInRange(1, 1000)
                auth_header = build_fuzzed_auth(fdp)
                resp = client.get(
                    "/api/get-document",
                    headers={"Authorization": auth_header},
                    query_string={"id": doc_id},
                )
                check_endpoint_invariants(resp, "/api/get-document")
                check_security_vulnerabilities(resp, "/api/get-document", start_time)

            elif endpoint_choice == 5:
                # delete-document
                doc_id = fdp.ConsumeIntInRange(1, 1000)
                payload = build_delete_document(doc_id, fdp)
                auth_header = build_fuzzed_auth(fdp)
                resp = client.delete(
                    "/api/delete-document",
                    headers={"Authorization": auth_header},
                    json=payload.to_dict(),
                )
                check_endpoint_invariants(resp, "/api/delete-document")
                check_security_vulnerabilities(resp, "/api/delete-document", start_time)

            elif endpoint_choice == 6:
                # create-watermark
                doc_id = fdp.ConsumeIntInRange(1, 1000)
                payload = build_create_watermark(doc_id, fdp)
                auth_header = build_auth_header()
                resp = client.post(
                    "/api/create-watermark",
                    headers={"Authorization": auth_header},
                    json=payload.to_dict(),
                )
                check_endpoint_invariants(resp, "/api/create-watermark")
                check_security_vulnerabilities(
                    resp, "/api/create-watermark", start_time
                )

            elif endpoint_choice == 7:
                # read-watermark
                doc_id = fdp.ConsumeIntInRange(1, 1000)
                payload = build_read_watermark(doc_id, fdp)
                auth_header = build_auth_header()
                resp = client.post(
                    "/api/read-watermark",
                    headers={"Authorization": auth_header},
                    json=payload.to_dict(),
                )
                check_endpoint_invariants(resp, "/api/read-watermark")
                check_security_vulnerabilities(resp, "/api/read-watermark", start_time)

            elif endpoint_choice == 8:
                # get-version/<link> - fuzz path parameter with valid/invalid hex
                link_length = fdp.PickValueInArray([32, 64])

                # Generate hex string with potential mutations
                if fdp.remaining_bytes() > link_length and fdp.ConsumeBool():
                    # Valid hex
                    link = fdp.ConsumeBytes(link_length // 2).hex()
                else:
                    # Invalid: non-hex, wrong length, mixed case, special chars
                    mutation_type = fdp.ConsumeIntInRange(0, 4)
                    if mutation_type == 0:
                        # Non-hex characters
                        link = (
                            fdp.ConsumeUnicodeNoSurrogates(link_length)
                            or "g" * link_length
                        )
                    elif mutation_type == 1:
                        # Wrong length
                        link = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 128)).hex()
                    elif mutation_type == 2:
                        # Mixed case (should be lowercase)
                        link = fdp.ConsumeBytes(link_length // 2).hex().upper()
                    elif mutation_type == 3:
                        # Special characters
                        link = "../" * (link_length // 3) + "a" * (link_length % 3)
                    else:
                        # Empty or very short
                        link = fdp.ConsumeUnicodeNoSurrogates(
                            fdp.ConsumeIntInRange(0, 5)
                        )

                auth_header = build_fuzzed_auth(fdp)
                resp = client.get(
                    f"/api/get-version/{link}",
                    headers={"Authorization": auth_header},
                )
                check_endpoint_invariants(resp, "/api/get-version")
                check_security_vulnerabilities(resp, "/api/get-version", start_time)

            else:  # endpoint_choice == 9
                # /metrics - fuzz X-Metrics-Token header
                if fdp.remaining_bytes() and fdp.ConsumeBool():
                    # Try valid-looking token
                    metrics_token = fdp.ConsumeUnicodeNoSurrogates(64) or "test-token"
                else:
                    # Invalid tokens
                    mutation_type = fdp.ConsumeIntInRange(0, 3)
                    if mutation_type == 0:
                        metrics_token = ""
                    elif mutation_type == 1:
                        metrics_token = "' OR 1=1--"
                    elif mutation_type == 2:
                        metrics_token = "../../../etc/passwd"
                    else:
                        metrics_token = None  # type: ignore[assignment]

                headers = {}
                if metrics_token is not None:
                    headers["X-Metrics-Token"] = metrics_token

                resp = client.get("/metrics", headers=headers)
                check_endpoint_invariants(resp, "/metrics")
                check_security_vulnerabilities(resp, "/metrics", start_time)

    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug(f"REST endpoint fuzzing failed: {exc}")
    finally:
        cleanup_storage()


def main() -> None:
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
