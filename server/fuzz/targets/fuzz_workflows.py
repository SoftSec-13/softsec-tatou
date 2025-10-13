#!/usr/bin/env python3
"""Stateful workflow fuzzer with IDOR and ownership checks.

This target executes multi-step workflows combining authentication,
document operations, and watermarking while checking for IDOR vulnerabilities.
"""

from __future__ import annotations

import io
import json
import logging
import sys
from pathlib import Path
from typing import Any

# Add fuzz directory to path for local imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import atheris

with atheris.instrument_imports():
    from harness import cleanup_storage, get_app
    from models import PDFInput
    from oracles import check_ownership_invariant

logger = logging.getLogger(__name__)

# Supported actions
ACTIONS = [
    "create_user",
    "login",
    "upload",
    "list_documents",
    "get_document",
    "delete_document",
    "create_watermark",
    "read_watermark",
]


def _decode_workflow(data: bytes) -> list[dict[str, Any]] | None:
    """Decode workflow from JSON bytes."""
    try:
        parsed = json.loads(data.decode("utf-8"))
        if isinstance(parsed, list) and all(isinstance(item, dict) for item in parsed):
            return parsed  # type: ignore[return-value]
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    return None


def execute_workflow(client, workflow: list[dict[str, Any]], seed: bytes) -> None:
    """Execute workflow steps with ownership tracking.

    Args:
        client: Flask test client
        workflow: List of action dictionaries
        seed: Raw seed bytes for PDF generation
    """
    token: str | None = None
    owned_docs: set[int] = set()

    for idx, step in enumerate(workflow):
        if not isinstance(step, dict):
            continue

        action = step.get("action", "")

        if action == "create_user":
            email = step.get("email") or f"user{idx}@test.com"
            password = step.get("password") or "pass"
            login = email.split("@")[0]
            client.post(
                "/api/create-user",
                json={"email": email, "password": password, "login": login},
            )

        elif action == "login":
            email = step.get("email") or "user@test.com"
            password = step.get("password") or "pass"
            resp = client.post(
                "/api/login", json={"email": email, "password": password}
            )
            if resp.status_code == 200:
                data = resp.get_json(silent=True) or {}
                raw_token = data.get("token")
                if isinstance(raw_token, str):
                    token = f"Bearer {raw_token}"
                    # Reset owned docs on login (new user)
                    owned_docs.clear()

        elif action == "upload":
            if not token:
                # Auto-create token for upload
                from builders import build_auth_header

                token = build_auth_header()

            pdf_bytes = seed[:4096] or b"%PDF-1.4\n%%EOF\n"
            filename = (step.get("filename") or "workflow.pdf").strip()
            pdf_input = PDFInput.from_bytes(pdf_bytes, filename)

            resp = client.post(
                "/api/upload-document",
                headers={"Authorization": token},
                data={
                    "file": (
                        io.BytesIO(pdf_input.content),
                        pdf_input.filename,
                        pdf_input.mimetype,
                    ),
                    "intended_for": step.get("intended_for", "recipient@test.com"),
                    "method": step.get("method", "basic"),
                },
                content_type="multipart/form-data",
            )

            if resp.status_code in {200, 201}:
                data = resp.get_json(silent=True) or {}
                doc_id = data.get("id")
                if isinstance(doc_id, int):
                    owned_docs.add(doc_id)

        elif action == "list_documents" and token:
            client.get("/api/list-documents", headers={"Authorization": token})

        elif action == "get_document" and token:
            doc_id = int(step.get("documentid", 1))
            resp = client.get(
                "/api/get-document",
                headers={"Authorization": token},
                query_string={"id": doc_id},
            )
            check_ownership_invariant(resp, "/api/get-document", owned_docs, doc_id)

        elif action == "delete_document" and token:
            doc_id = int(step.get("documentid", 1))
            resp = client.delete(
                "/api/delete-document",
                headers={"Authorization": token},
                json={"documentid": doc_id},
            )
            check_ownership_invariant(resp, "/api/delete-document", owned_docs, doc_id)
            if resp.status_code in {200, 204}:
                owned_docs.discard(doc_id)

        elif action == "create_watermark" and token and owned_docs:
            doc_id = int(step.get("documentid", next(iter(owned_docs))))
            resp = client.post(
                "/api/create-watermark",
                headers={"Authorization": token},
                json={
                    "documentid": doc_id,
                    "method": step.get("method", "basic"),
                    "intended_for": step.get("intended_for", "recipient@test.com"),
                    "secret": step.get("secret", "workflow-secret"),
                    "key": step.get("key", "workflow-key"),
                },
            )
            if resp.status_code == 201:
                data = resp.get_json(silent=True) or {}
                version_id = data.get("documentid")
                if isinstance(version_id, int):
                    owned_docs.add(version_id)

        elif action == "read_watermark" and token and owned_docs:
            doc_id = int(step.get("documentid", next(iter(owned_docs))))
            client.post(
                "/api/read-watermark",
                headers={"Authorization": token},
                json={
                    "documentid": doc_id,
                    "method": step.get("method", "basic"),
                    "key": step.get("key", "workflow-key"),
                },
            )


def fuzz_one_input(data: bytes) -> None:
    """Fuzz stateful workflows.

    Args:
        data: Fuzzed bytes for workflow definition
    """
    if not data:
        return

    # Try decoding as JSON workflow, fallback to default
    workflow = _decode_workflow(data)

    if workflow is None:
        # Generate simple workflow from bytes
        fdp = atheris.FuzzedDataProvider(data)
        num_steps = fdp.ConsumeIntInRange(1, 8)
        workflow = []
        for _ in range(num_steps):
            if not fdp.remaining_bytes():
                break
            action_idx = fdp.ConsumeIntInRange(0, len(ACTIONS) - 1)
            workflow.append({"action": ACTIONS[action_idx]})

    app = get_app()

    try:
        with app.test_client() as client:
            execute_workflow(client, workflow, data)
    except (SystemExit, KeyboardInterrupt):
        raise
    except AssertionError:
        raise
    except Exception as exc:
        logger.debug(f"Workflow fuzzing failed: {exc}")
    finally:
        cleanup_storage()


def main() -> None:
    atheris.Setup(sys.argv, fuzz_one_input, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
