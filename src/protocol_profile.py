"""Build-specific protocol profile loader.

Profiles describe observed wire constants and analysis addresses only; they do
not contain account secrets or precomputed credentials.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_profile(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data.get("build"):
        raise ValueError(f"invalid protocol profile: {p}")
    return data
