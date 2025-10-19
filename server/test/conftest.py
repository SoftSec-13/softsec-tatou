from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repository root is on sys.path so that 'import server'
# resolves to the local package instead of any third-party module.
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
