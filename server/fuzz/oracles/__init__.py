"""Oracle functions for detecting bugs and vulnerabilities."""

from .invariants import check_endpoint_invariants, check_ownership_invariant
from .security import check_security_vulnerabilities

__all__ = [
    "check_security_vulnerabilities",
    "check_endpoint_invariants",
    "check_ownership_invariant",
]
