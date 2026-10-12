"""
index.py
Vercel Serverless Function entrypoint for /api and web routes.
Exports top-level `app`, `handler`, and `application` for Vercel Python runtime.
"""

import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
_triage = _root / "triage"
for p in [str(_root), str(_triage)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from triage.web import app, application, handler

__all__ = ["app", "application", "handler"]
