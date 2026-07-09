"""Optional JSON configuration for tuning rules and coverage bands.

JSON (not TOML) is used so the tool stays dependency-free on Python 3.8, which
has no tomllib. Recognised keys, all optional:

    {
      "sensitive_tools": ["Bash", "Write", ...],
      "sensitive_patterns": [".ssh", ".env", ...],
      "min_app_version": "1.1.4173",
      "bands": {"pass": 95, "partial": 70}
    }
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .errors import InputFormatError
from .ingest import load_json_file
from .security import DEFAULT_MAX_BYTES

_ALLOWED = {"sensitive_tools", "sensitive_patterns", "min_app_version", "bands"}


def load_config(path: Optional[str], max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    if not path:
        return {}
    data = load_json_file(path, max_bytes)
    if not isinstance(data, dict):
        raise InputFormatError(f"{path}: config must be a JSON object")
    unknown = set(data) - _ALLOWED
    if unknown:
        raise InputFormatError(f"{path}: unknown config keys: {sorted(unknown)}")
    return data
