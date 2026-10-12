"""
main.py
AI-Powered SOC Dashboard - Root Entrypoint for Vercel and Local Server.

Exports top-level `app`, `handler`, and `application` for Vercel Python runtime.
Runs local development server with uvicorn when executed directly.
"""

import sys
from pathlib import Path

# Add root and triage directory to Python path
_root = Path(__file__).resolve().parent
_triage = _root / "triage"
for p in [str(_root), str(_triage)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from triage.web import app, application, handler

__all__ = ["app", "application", "handler"]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
