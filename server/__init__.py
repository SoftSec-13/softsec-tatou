"""Top-level package initializer for the Tatou server.

This package exposes the Flask app factory and the default WSGI app so that
static type checkers (mypy) and imports like ``from server import create_app``
work reliably without depending on runtime sys.path tweaks.

Exports:
- create_app: the Flask application factory
- app: the default WSGI application instance
"""

from __future__ import annotations

# Re-export from the implementation module under server/src/
from .src.server import app, create_app  # noqa: F401

__all__ = ["create_app", "app"]
