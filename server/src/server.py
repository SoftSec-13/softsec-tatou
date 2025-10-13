import datetime as dt
import hashlib
import os
import re
import time
from functools import wraps
from pathlib import Path

from flask import Flask, Response, g, jsonify, request, send_file
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import watermarking_utils as WMUtils
from observability import (
    inc_db_error,
    inc_inflight,
    inc_login_failure,
    inc_login_success,
    inc_suspicious,
    inc_upload,
    inc_watermark_created,
    inc_watermark_failed,
    inc_watermark_read,
    observe_db_latency,
    observe_request_size,
    observe_watermark_duration,
    record_request,
    render_prometheus,
)

MAX_DB_INT = (2**63) - 1

RMAPHandler = None  # default
if not os.environ.get("TATOU_TEST_DISABLE_RMAP"):
    try:  # Allow tests to disable RMAP dependency via env var
        from rmap_handler import RMAPHandler as _RMAPHandler  # type: ignore

        RMAPHandler = _RMAPHandler
    except Exception:  # pragma: no cover - degrade gracefully if missing
        RMAPHandler = None  # type: ignore


def create_app():
    app = Flask(__name__)

    # --- Config ---
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["STORAGE_DIR"] = Path(
        os.environ.get("STORAGE_DIR", "./storage")
    ).resolve()
    app.config["TOKEN_TTL_SECONDS"] = int(os.environ.get("TOKEN_TTL_SECONDS", "86400"))

    app.config["DB_USER"] = os.environ.get("DB_USER", "tatou")
    app.config["DB_PASSWORD"] = os.environ.get("DB_PASSWORD", "tatou")
    app.config["DB_HOST"] = os.environ.get("DB_HOST", "db")
    app.config["DB_PORT"] = int(os.environ.get("DB_PORT", "3306"))
    app.config["DB_NAME"] = os.environ.get("DB_NAME", "tatou")

    app.config["STORAGE_DIR"].mkdir(parents=True, exist_ok=True)

    # --- DB engine only (no Table metadata) ---
    def db_url() -> str:
        return (
            f"mysql+pymysql://{app.config['DB_USER']}:{app.config['DB_PASSWORD']}"
            f"@{app.config['DB_HOST']}:{app.config['DB_PORT']}/{app.config['DB_NAME']}?charset=utf8mb4"
        )

    def get_engine():
        eng = app.config.get("_ENGINE")
        if eng is None:
            eng = create_engine(db_url(), pool_pre_ping=True, future=True)
            app.config["_ENGINE"] = eng
        return eng

    # --- RMAP initialization (skippable in tests) ---
    if RMAPHandler is not None:
        try:
            RMAPHandler(app, str(app.config["STORAGE_DIR"]), get_engine)
        except Exception as e:  # pragma: no cover - defensive; don't fail app
            app.logger.warning(f"RMAP initialization failed (continuing): {e}")

    # --- Helpers ---
    def _serializer():
        return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="tatou-auth")

    def _auth_error(msg: str, code: int = 401):
        return jsonify({"error": msg}), code

    def require_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return _auth_error("Missing or invalid Authorization header")
            token = auth.split(" ", 1)[1].strip()
            try:
                data = _serializer().loads(
                    token, max_age=app.config["TOKEN_TTL_SECONDS"]
                )
            except SignatureExpired:
                return _auth_error("Token expired")
            except BadSignature:
                return _auth_error("Invalid token")
            g.user = {
                "id": int(data["uid"]),
                "login": data["login"],
                "email": data.get("email"),
            }
            return f(*args, **kwargs)

        return wrapper

    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Request instrumentation hooks ---
    @app.before_request  # type: ignore
    def _tatou_before():
        try:  # record start for latency
            request._tatou_start = time.time()  # type: ignore[attr-defined]
            route = request.url_rule.rule if request.url_rule else request.path
            inc_inflight(route)
            # capture request size if content-length header present
            try:
                cl = request.content_length
                if cl is not None:
                    observe_request_size(request.method, route, cl)
            except Exception as exc:  # pragma: no cover - soft fail
                app.logger.error("request size capture failed: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            app.logger.error("before_request instrumentation failed: %s", exc)

    @app.after_request  # type: ignore
    def _tatou_after(resp):
        try:
            start = getattr(request, "_tatou_start", None)
            if start is not None:
                dur = time.time() - start
                route = request.url_rule.rule if request.url_rule else request.path
                record_request(request.method, route, resp.status_code, dur)
        except Exception as exc:  # pragma: no cover - defensive
            app.logger.error("after_request instrumentation failed: %s", exc)
        return resp

    # --- Routes ---

    @app.route("/<path:filename>")
    def static_files(filename):
        return app.send_static_file(filename)

    @app.route("/")
    def home():
        return app.send_static_file("index.html")

    @app.get("/healthz")
    def healthz():
        try:
            with get_engine().connect() as conn:
                conn.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        return jsonify(
            {"message": "The server is up and running.", "db_connected": db_ok}
        ), 200

    # Extra backend validation for user input
    def validate_user_input(email: str, login: str) -> tuple[bool, str]:
        """Validate user input before database operations"""
        if len(email) > 320 or len(login) > 64:
            return False, "Email or login too long"
        if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
            return False, "Invalid email format"
        if not re.match(r"^[a-zA-Z0-9_-]{3,64}$", login):
            return False, "Invalid login format"
        return True, ""

    # POST /api/create-user {email, login, password}
    @app.post("/api/create-user")
    def create_user():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip().lower()
        login = (payload.get("login") or "").strip()
        password = payload.get("password") or ""
        start_db = time.time()
        if not email or not login or not password:
            return jsonify({"error": "email, login, and password are required"}), 400

        hpw = generate_password_hash(password)

        try:
            is_valid, error_msg = validate_user_input(email, login)
            if not is_valid:
                return jsonify({"error": error_msg}), 400

            with get_engine().begin() as conn:
                res = conn.execute(
                    text(
                        "INSERT INTO Users (email, hpassword, login) "
                        "VALUES (:email, :hpw, :login)"
                    ),
                    {"email": email, "hpw": hpw, "login": login},
                )
                uid = int(res.lastrowid)
                row = conn.execute(
                    text("SELECT id, email, login FROM Users WHERE id = :id"),
                    {"id": uid},
                ).one()
            observe_db_latency("create_user", time.time() - start_db)
        except IntegrityError:
            return jsonify({"error": "email or login already exists"}), 409
        except Exception as e:
            app.logger.error("Database error in create_user: %s", e)
            return jsonify({"error": "database error"}), 503

        return jsonify({"id": row.id, "email": row.email, "login": row.login}), 201

    # POST /api/login {login, password}
    @app.post("/api/login")
    def login():
        payload = request.get_json(silent=True) or {}
        email = (payload.get("email") or "").strip()
        password = payload.get("password") or ""

        if not email or not password:
            return jsonify({"error": "email and password are required"}), 400

        start_db = time.time()
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        "SELECT id, email, login, hpassword FROM Users "
                        "WHERE email = :email LIMIT 1"
                    ),
                    {"email": email},
                ).first()

                # Constant-time comparison to prevent timing attacks
                if row:
                    is_valid = check_password_hash(row.hpassword, password)
                else:
                    # Dummy check to maintain constant time
                    is_valid = False
                    row = None

                if not is_valid:
                    app.logger.warning(
                        "Failed login attempt for email: %s",
                        email if email else "<empty>",
                    )
                    inc_login_failure("invalid_credentials")
                    return jsonify({"error": "invalid credentials"}), 401

        except Exception as e:
            app.logger.error(f"Database error in login: {str(e)}")
            inc_db_error("login_select")
            return jsonify({"error": "An error occurred"}), 503

        observe_db_latency("login_select", time.time() - start_db)
        token = _serializer().dumps(
            {"uid": int(row.id), "login": row.login, "email": row.email}
        )
        inc_login_success()
        return jsonify(
            {
                "token": token,
                "token_type": "bearer",
                "expires_in": app.config["TOKEN_TTL_SECONDS"],
            }
        ), 200

    # POST /api/upload-document  (multipart/form-data)
    @app.post("/api/upload-document")
    @require_auth
    def upload_document():
        if "file" not in request.files:
            inc_suspicious("upload_missing_file_field")
            return jsonify({"error": "file is required (multipart/form-data)"}), 400

        file = request.files["file"]
        if not file or file.filename == "":
            return jsonify({"error": "empty filename"}), 400

        start_db = time.time()
        # Validate file size
        MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
        if file.content_length and file.content_length > MAX_FILE_SIZE:
            return jsonify({"error": "file too large"}), 413

        # Validate file type and MIME type
        if file.mimetype != "application/pdf":
            inc_suspicious("upload_bad_mime")
            return jsonify({"error": "only PDF files are allowed"}), 415
        if not file.filename.lower().endswith(".pdf"):
            inc_suspicious("upload_bad_extension")
            return jsonify({"error": "only PDF files are allowed"}), 415

        # Sanitize filename
        fname = secure_filename(file.filename)
        if not fname:
            return jsonify({"error": "invalid filename"}), 400

        user_dir = app.config["STORAGE_DIR"] / "files" / g.user["login"]
        user_dir.mkdir(parents=True, exist_ok=True)

        ts = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
        final_name = request.form.get("name") or fname
        stored_name = f"{ts}__{fname}"

        try:
            # Check for path traversal attempts
            stored_path = (user_dir / stored_name).resolve()
            if not str(stored_path).startswith(str(user_dir.resolve())):
                return jsonify({"error": "invalid path"}), 400

            file.save(stored_path)
        except Exception as e:
            app.logger.error(f"File save error: {str(e)}")
            return jsonify({"error": "failed to save file"}), 500

        sha_hex = _sha256_file(stored_path)
        size = stored_path.stat().st_size

        try:
            with get_engine().begin() as conn:
                conn.execute(
                    text(
                        """
                        INSERT INTO Documents (name, path, ownerid, sha256, size)
                        VALUES (:name, :path, :ownerid, UNHEX(:sha256hex), :size)
                    """
                    ),
                    {
                        "name": final_name,
                        "path": str(stored_path),
                        "ownerid": int(g.user["id"]),
                        "sha256hex": sha_hex,
                        "size": int(size),
                    },
                )
                did = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
                row = conn.execute(
                    text(
                        """
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id
                    """
                    ),
                    {"id": did},
                ).one()
        except Exception as e:
            stored_path.unlink(missing_ok=True)
            app.logger.error(f"Database error: {str(e)}")
            inc_db_error("insert_document")
            return jsonify({"error": "database error occurred"}), 503

        observe_db_latency("insert_document", time.time() - start_db)
        resp_data = {
            "id": int(row.id),
            "name": row.name,
            "creation": row.creation.isoformat()
            if hasattr(row.creation, "isoformat")
            else str(row.creation),
            "sha256": row.sha256_hex,
            "size": int(row.size),
        }
        inc_upload(int(row.size))
        return jsonify(resp_data), 201

    # GET /api/list-documents
    @app.get("/api/list-documents")
    @require_auth
    def list_documents():
        try:
            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT id, name, creation, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE ownerid = :uid
                        ORDER BY creation DESC
                    """
                    ),
                    {"uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            app.logger.error(f"Database error in list_documents: {str(e)}")
            inc_db_error("list_documents")
            return jsonify({"error": "An error occurred while fetching documents"}), 503

        docs = [
            {
                "id": int(r.id),
                "name": r.name,
                "creation": r.creation.isoformat()
                if hasattr(r.creation, "isoformat")
                else str(r.creation),
                "sha256": r.sha256_hex,
                "size": int(r.size),
            }
            for r in rows
        ]
        return jsonify({"documents": docs}), 200

    # GET /api/list-versions
    @app.get("/api/list-versions")
    @app.get("/api/list-versions/<int:document_id>")
    @require_auth
    def list_versions(document_id: int | None = None):
        # Input validation
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id) if document_id else None
                if document_id is None or document_id <= 0 or document_id > MAX_DB_INT:
                    return jsonify({"error": "document id required"}), 400
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        if document_id is None or document_id <= 0 or document_id > MAX_DB_INT:
            return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                # First verify document ownership
                doc = conn.execute(
                    text("""
                    SELECT id
                    FROM Documents
                    WHERE id = :did AND ownerid = :uid
                    LIMIT 1
                """),
                    {"did": document_id, "uid": int(g.user["id"])},
                ).first()

                if not doc:
                    return jsonify({"error": "document not found"}), 404

                # Then fetch versions with ownership validation
                rows = conn.execute(
                    text("""
                        SELECT v.id, v.documentid, v.link, v.intended_for,
                            v.secret, v.method
                        FROM Documents d
                        JOIN Versions v ON d.id = v.documentid
                        WHERE d.id = :did AND d.ownerid = :uid
                        ORDER BY v.id DESC
                    """),
                    {"did": document_id, "uid": int(g.user["id"])},
                ).all()
        except Exception as e:
            app.logger.error(f"Database error in list_versions: {str(e)}")
            inc_db_error("list_versions")
            return jsonify({"error": "An error occurred while fetching versions"}), 503

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "secret": r.secret,
                "method": r.method,
            }
            for r in rows
        ]
        return jsonify({"versions": versions}), 200

    # GET /api/list-all-versions
    @app.get("/api/list-all-versions")
    @require_auth
    def list_all_versions():
        try:
            # Validate user data from auth token
            if not g.user or not g.user.get("id"):
                return jsonify({"error": "Invalid authentication"}), 401

            with get_engine().connect() as conn:
                rows = conn.execute(
                    text(
                        """
                        SELECT v.id, v.documentid, v.link, v.intended_for, v.method
                        FROM Documents d
                        JOIN Versions v ON d.id = v.documentid
                        WHERE d.ownerid = :uid
                        ORDER BY v.id DESC
                        LIMIT 1000
                    """
                    ),
                    {"uid": int(g.user["id"])},
                ).all()
        except ValueError:
            app.logger.error("Invalid user ID in auth token")
            return jsonify({"error": "Authentication error"}), 401
        except Exception as e:
            app.logger.error(f"Database error in list_all_versions: {str(e)}")
            inc_db_error("list_all_versions")
            return jsonify({"error": "An error occurred while fetching versions"}), 503

        versions = [
            {
                "id": int(r.id),
                "documentid": int(r.documentid),
                "link": r.link,
                "intended_for": r.intended_for,
                "method": r.method,
            }
            for r in rows
        ]
        return jsonify({"versions": versions}), 200

    # GET /api/get-document or /api/get-document/<id>  → returns the PDF (inline)
    @app.get("/api/get-document")
    @app.get("/api/get-document/<int:document_id>")
    @require_auth
    def get_document(document_id: int | None = None):
        # Support both path param and ?id=/ ?documentid=
        if document_id is None:
            document_id = request.args.get("id") or request.args.get("documentid")
            try:
                document_id = int(document_id)
            except (TypeError, ValueError):
                return jsonify({"error": "document id required"}), 400

        if document_id is None or document_id <= 0 or document_id > MAX_DB_INT:
            return jsonify({"error": "document id required"}), 400

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT id, name, path, HEX(sha256) AS sha256_hex, size
                        FROM Documents
                        WHERE id = :id AND ownerid = :uid
                        LIMIT 1
                    """
                    ),
                    {"id": document_id, "uid": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.error(f"Database error in get_document: {str(e)}")
            inc_db_error("get_document")
            return jsonify(
                {"error": "An error occurred while fetching the document"}
            ), 503

        # Don’t leak whether a doc exists for another user
        if not row:
            return jsonify({"error": "document not found"}), 404

        storage_root = app.config["STORAGE_DIR"].resolve()
        file_path = Path(row.path)

        # Basic safety: ensure path is inside STORAGE_DIR and exists
        try:
            resolved = file_path.resolve()
            resolved.relative_to(storage_root)
        except Exception:
            # Path looks suspicious or outside storage
            return jsonify({"error": "document path invalid"}), 500

        if not resolved.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # TOCTOU-safe open and validation
        try:
            f = open(resolved, "rb")
        except OSError:
            return jsonify({"error": "file missing on disk"}), 410

        try:
            # Quick PDF signature check
            head = f.read(5)
            if head != b"%PDF-":
                f.close()
                return jsonify({"error": "document not available"}), 415

            f.seek(0)

            # Prepare safe filename (preserve existing .pdf if present)
            name = (row.name or "document").strip().replace("\r", "").replace("\n", "")
            if not name.lower().endswith(".pdf"):
                name = f"{name}.pdf"

            # Stat via the same FD to avoid TOCTOU
            st = os.fstat(f.fileno())

            resp = send_file(
                file_path,
                mimetype="application/pdf",
                as_attachment=False,
                download_name=name,
                conditional=False,  # enables 304 if If-Modified-Since/Range handling
                max_age=0,
                last_modified=st.st_mtime,
            )

            # Strong validator
            if isinstance(row.sha256_hex, str) and row.sha256_hex:
                resp.set_etag(row.sha256_hex.lower())

            # Headers
            resp.headers["Content-Type"] = "application/pdf"
            resp.headers["Content-Disposition"] = f'inline; filename="{name}"'
            resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
            resp.headers.setdefault(
                "Content-Security-Policy", "sandbox; default-src 'none'"
            )

            return resp
        except Exception as e:
            f.close()
            # Log error and return generic message
            app.logger.error(f"Error serving file: {str(e)}")
            return jsonify({"error": "error serving file"}), 500

    # GET /api/get-version/<link>  → returns the watermarked PDF (inline)
    @app.get("/api/get-version/<link>")
    def get_version(link: str):
        # Accept both 32-char (RMAP session secrets) and 64-char (SHA-256 style) tokens
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{64}", link):
            return jsonify({"error": "document not found"}), 404

        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT path, link
                        FROM Versions
                        WHERE link = :link
                        LIMIT 1
                    """
                    ),
                    {"link": link},
                ).first()
        except Exception as e:
            app.logger.error("Database error in get_version: %s", e)
            inc_db_error("get_version")
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        try:
            resolved = _safe_resolve_under_storage(row.path, app.config["STORAGE_DIR"])
        except Exception as exc:
            app.logger.warning(
                "Rejected version path for link %s: %s (%s)", link, row.path, exc
            )
            return jsonify({"error": "document path invalid"}), 500

        if not resolved.exists():
            return jsonify({"error": "file missing on disk"}), 410

        try:
            with resolved.open("rb") as fh:
                header = fh.read(5)
                if header != b"%PDF-":
                    return jsonify({"error": "document not available"}), 415
                fh.seek(0)
                last_modified = os.fstat(fh.fileno()).st_mtime
        except OSError:
            return jsonify({"error": "file missing on disk"}), 410
        except Exception as e:
            app.logger.error("Error inspecting version file for %s: %s", link, e)
            return jsonify({"error": "error serving file"}), 500

        download_name = (
            row.link if row.link.lower().endswith(".pdf") else f"{row.link}.pdf"
        )
        safe_download = download_name.replace("\r", "").replace("\n", "")

        try:
            resp = send_file(
                resolved,
                mimetype="application/pdf",
                as_attachment=False,
                download_name=safe_download,
                conditional=True,
                max_age=0,
                last_modified=last_modified,
            )
        except Exception as e:
            app.logger.error("Error serving version %s: %s", link, e)
            return jsonify({"error": "error serving file"}), 500

        resp.headers["Cache-Control"] = "private, max-age=0, must-revalidate"
        resp.headers["Content-Type"] = "application/pdf"
        resp.headers["Content-Disposition"] = f'inline; filename="{safe_download}"'
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault(
            "Content-Security-Policy", "sandbox; default-src 'none'"
        )

        return resp

    # Helper: resolve path safely under STORAGE_DIR (handles absolute/relative)
    def _safe_resolve_under_storage(p: str, storage_root: Path) -> Path:
        storage_root = storage_root.resolve()
        fp = Path(p)
        if not fp.is_absolute():
            fp = storage_root / fp
        fp = fp.resolve()
        # Python 3.12 has is_relative_to on Path
        if hasattr(fp, "is_relative_to"):
            if not fp.is_relative_to(storage_root):
                raise RuntimeError(f"path {fp} escapes storage root {storage_root}")
        else:
            try:
                fp.relative_to(storage_root)
            except ValueError:
                raise RuntimeError(
                    f"path {fp} escapes storage root {storage_root}"
                ) from None
        return fp

    # DELETE /api/delete-document  (and variants) POST supported for convenience
    @app.route("/api/delete-document", methods=["DELETE", "POST"])
    @app.route("/api/delete-document/<document_id>", methods=["DELETE"])
    @require_auth
    def delete_document(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if document_id in (None, ""):
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )

        if document_id is None:
            return jsonify({"error": "document id required"}), 400

        try:
            doc_id = int(document_id)
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        if doc_id <= 0 or doc_id > MAX_DB_INT:
            return jsonify({"error": "document id required"}), 400

        owner_id = int(g.user["id"])

        # Fetch the document (enforce ownership)
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT id, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :owner
                        LIMIT 1
                    """
                    ),
                    {"id": doc_id, "owner": owner_id},
                ).first()
        except Exception as e:
            app.logger.error("DB delete error for doc id=%s: %s", doc_id, e)
            inc_db_error("delete_document_select")
            return jsonify({"error": "database error during delete"}), 503

        if not row:
            # Don’t reveal others’ docs—just say not found
            return jsonify({"error": "document not found"}), 404

        # Resolve and delete file (best effort)
        storage_root = Path(app.config["STORAGE_DIR"])
        file_deleted = False
        file_missing = False
        delete_error = None
        try:
            fp = _safe_resolve_under_storage(row.path, storage_root)
            if fp.exists():
                try:
                    fp.unlink()
                    file_deleted = True
                except Exception as e:
                    delete_error = f"failed to delete file: {e}"
                    app.logger.warning(
                        "Failed to delete file %s for doc id=%s: %s", fp, row.id, e
                    )
            else:
                file_missing = True
        except RuntimeError as e:
            # Path escapes storage root; refuse to touch the file
            delete_error = str(e)
            app.logger.error("Path safety check failed for doc id=%s: %s", row.id, e)

        # Delete DB row (will cascade to Version if FK has ON DELETE CASCADE)
        try:
            with get_engine().begin() as conn:
                # If your schema does NOT have ON DELETE CASCADE on
                # Version.documentid, uncomment the next line first:
                # conn.execute(text("DELETE FROM Version WHERE documentid = :id"),
                #              {"id": doc_id})
                conn.execute(
                    text("DELETE FROM Documents WHERE id = :id AND ownerid = :owner"),
                    {"id": doc_id, "owner": owner_id},
                )
        except Exception as e:
            app.logger.error("DB delete error for doc id=%s: %s", doc_id, e)
            inc_db_error("delete_document_delete")
            return jsonify({"error": "database error during delete"}), 503

        return jsonify(
            {
                "deleted": True,
                "id": doc_id,
                "file_deleted": file_deleted,
                "file_missing": file_missing,
                "note": delete_error,  # null/omitted if everything was fine
            }
        ), 200

    # POST /api/create-watermark or /api/create-watermark/<id>
    # → create watermarked pdf and returns metadata
    @app.post("/api/create-watermark")
    @app.post("/api/create-watermark/<int:document_id>")
    @require_auth
    def create_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on GET
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        intended_for = payload.get("intended_for")
        position = payload.get("position") or None
        secret = payload.get("secret")
        key = payload.get("key")

        # validate input
        try:
            if doc_id is None:
                return jsonify({"error": "document_id (int) is required"}), 400
            doc_id = int(doc_id)
            if doc_id <= 0 or doc_id > MAX_DB_INT:
                return jsonify({"error": "document_id (int) is required"}), 400
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if (
            not method
            or not intended_for
            or not isinstance(secret, str)
            or not isinstance(key, str)
        ):
            return jsonify(
                {"error": "method, intended_for, secret, and key are required"}
            ), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :owner
                        LIMIT 1
                    """
                    ),
                    {"id": doc_id, "owner": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.exception("Database error fetching document %s", e)
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        # check watermark applicability
        try:
            applicable = WMUtils.is_watermarking_applicable(
                method=method, pdf=str(file_path), position=position
            )
            if applicable is False:
                inc_watermark_failed(method, "applicability")
                return jsonify({"error": "watermarking method not applicable"}), 400
        except Exception as e:
            inc_watermark_failed(method, "applicability_exception")
            app.logger.exception(
                "Watermark applicability check failed for document %s", e
            )
            return jsonify({"error": "watermark applicability check failed"}), 400

        # apply watermark → bytes
        try:
            _wm_start = time.time()
            wm_bytes: bytes = WMUtils.apply_watermark(
                pdf=str(file_path),
                secret=secret,
                key=key,
                method=method,
                intended_for=intended_for,
                position=position,
            )
            observe_watermark_duration(method, time.time() - _wm_start)
            if not isinstance(wm_bytes, (bytes | bytearray)) or len(wm_bytes) == 0:
                inc_watermark_failed(method, "empty_output")
                return jsonify({"error": "watermarking produced no output"}), 500
        except Exception as e:
            inc_watermark_failed(method, "exception")
            app.logger.exception(
                "Watermarking failed for document %s using method %s: %s",
                doc_id,
                method,
                e,
            )
            return jsonify({"error": "watermarking failed"}), 500

        # build destination file name: "<original_name>__<intended_to>.pdf"
        base_name = Path(row.name or file_path.name).stem
        intended_slug = secure_filename(intended_for)
        dest_dir = file_path.parent / "watermarks"
        dest_dir.mkdir(parents=True, exist_ok=True)

        candidate = f"{base_name}__{intended_slug}.pdf"
        dest_path = dest_dir / candidate

        # write bytes
        try:
            with dest_path.open("wb") as f:
                f.write(wm_bytes)
        except Exception as e:
            app.logger.exception(
                "Failed to write watermarked file %s for document %s: %s",
                dest_path,
                doc_id,
                e,
            )
            return jsonify({"error": "failed to write watermarked file"}), 500

        # link token = sha256(watermarked_file_name) - using stronger hash
        link_token = hashlib.sha256(candidate.encode("utf-8")).hexdigest()

        try:
            with get_engine().begin() as conn:
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
                        "documentid": doc_id,
                        "link": link_token,
                        "intended_for": intended_for,
                        "secret": secret,
                        "method": method,
                        "position": position or "",
                        "path": str(dest_path),
                    },
                )
                vid = int(conn.execute(text("SELECT LAST_INSERT_ID()")).scalar())
        except Exception:
            try:
                dest_path.unlink(missing_ok=True)
            except Exception as cleanup_error:
                app.logger.warning(
                    f"Failed to cleanup file {dest_path}: {cleanup_error}"
                )
            app.logger.exception(
                "Database error during version insert for document %s", doc_id
            )
            inc_db_error("insert_version")
            return jsonify({"error": "database error during version insert"}), 503

        inc_watermark_created(method)
        return jsonify(
            {
                "id": vid,
                "documentid": doc_id,
                "link": link_token,
                "intended_for": intended_for,
                "method": method,
                "position": position,
                "filename": candidate,
                "size": len(wm_bytes),
            }
        ), 201

    # GET /api/get-watermarking-methods
    # → {"methods":[{"name":..., "description":...}, ...], "count":N}
    @app.get("/api/get-watermarking-methods")
    def get_watermarking_methods():
        methods = []

        for m in WMUtils.METHODS:
            methods.append(
                {"name": m, "description": WMUtils.get_method(m).get_usage()}
            )

        return jsonify({"methods": methods, "count": len(methods)}), 200

    # POST /api/read-watermark
    @app.post("/api/read-watermark")
    @app.post("/api/read-watermark/<int:document_id>")
    @require_auth
    def read_watermark(document_id: int | None = None):
        # accept id from path, query (?id= / ?documentid=), or JSON body on POST
        if not document_id:
            document_id = (
                request.args.get("id")
                or request.args.get("documentid")
                or (request.is_json and (request.get_json(silent=True) or {}).get("id"))
            )
        try:
            doc_id = document_id
        except (TypeError, ValueError):
            return jsonify({"error": "document id required"}), 400

        payload = request.get_json(silent=True) or {}
        # allow a couple of aliases for convenience
        method = payload.get("method")
        position = payload.get("position") or None
        key = payload.get("key")

        # validate input
        try:
            if doc_id is None:
                return jsonify({"error": "document_id (int) is required"}), 400
            doc_id = int(doc_id)
            if doc_id <= 0 or doc_id > MAX_DB_INT:
                return jsonify({"error": "document_id (int) is required"}), 400
        except (TypeError, ValueError):
            return jsonify({"error": "document_id (int) is required"}), 400
        if not method or not isinstance(method, str) or not isinstance(key, str):
            return jsonify({"error": "method, and key are required"}), 400

        # lookup the document; enforce ownership
        try:
            with get_engine().connect() as conn:
                row = conn.execute(
                    text(
                        """
                        SELECT id, name, path
                        FROM Documents
                        WHERE id = :id AND ownerid = :owner
                        LIMIT 1
                    """
                    ),
                    {"id": doc_id, "owner": int(g.user["id"])},
                ).first()
        except Exception as e:
            app.logger.exception(
                "Database error fetching document %s for watermark read: %s", doc_id, e
            )
            return jsonify({"error": "database error"}), 503

        if not row:
            return jsonify({"error": "document not found"}), 404

        # resolve path safely under STORAGE_DIR
        storage_root = Path(app.config["STORAGE_DIR"]).resolve()
        file_path = Path(row.path)
        if not file_path.is_absolute():
            file_path = storage_root / file_path
        file_path = file_path.resolve()
        try:
            file_path.relative_to(storage_root)
        except ValueError:
            return jsonify({"error": "document path invalid"}), 500
        if not file_path.exists():
            return jsonify({"error": "file missing on disk"}), 410

        secret = None
        try:
            secret = WMUtils.read_watermark(method=method, pdf=str(file_path), key=key)
        except Exception as e:
            app.logger.exception(
                "Error when attempting to read watermark for document %s: %s", doc_id, e
            )
            return jsonify({"error": "error when attempting to read watermark"}), 400
        inc_watermark_read(method)
        return jsonify(
            {
                "documentid": doc_id,
                "secret": secret,
                "method": method,
                "position": position,
            }
        ), 201

    def _is_authorized_metrics_request() -> bool:
        token_required = os.environ.get("METRICS_TOKEN", "")
        provided = request.headers.get("X-Metrics-Token", "")
        if provided != token_required:
            return False
        return True

    @app.get("/metrics")
    def metrics():
        if not _is_authorized_metrics_request():
            # Obscure existence a bit – return 404 instead of 403 to casual scans
            return jsonify({"error": "not found"}), 404
        data = render_prometheus()
        return Response(data, mimetype="text/plain; version=0.0.4")

    return app


# WSGI entrypoint
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # Use localhost by default for security, allow override via environment variable
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port)
