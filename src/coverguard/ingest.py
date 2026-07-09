"""Loading events and JSON inputs with size and count guards."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from .errors import InputFormatError, InputTooLargeError
from .models import Event
from .security import DEFAULT_MAX_BYTES, check_size


def load_json_file(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    check_size(path, max_bytes)
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise InputFormatError(f"{path}: invalid JSON ({exc})") from exc
    except UnicodeDecodeError as exc:
        raise InputFormatError(f"{path}: not valid UTF-8 ({exc})") from exc
    except OSError as exc:
        raise InputFormatError(f"cannot read {path}: {exc}") from exc


def load_events(path: str, max_bytes: int = DEFAULT_MAX_BYTES,
                max_events: Optional[int] = None) -> List[Event]:
    """Load Cowork OTel events from JSONL or a JSON array, bounded in size."""
    check_size(path, max_bytes)
    events: List[Event] = []
    try:
        with open(path, encoding="utf-8") as fh:
            first = _first_nonspace(fh)
            fh.seek(0)
            if first == "[":
                try:
                    data = json.load(fh)
                except json.JSONDecodeError as exc:
                    raise InputFormatError(f"{path}: invalid JSON array ({exc})") from exc
                if not isinstance(data, list):
                    raise InputFormatError(f"{path}: expected a JSON array of events")
                for obj in data:
                    _cap(events, max_events, path)
                    events.append(Event.from_obj(obj))
            elif first == "":
                return events  # empty file
            else:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    _cap(events, max_events, path)
                    try:
                        events.append(Event.from_obj(json.loads(line)))
                    except json.JSONDecodeError as exc:
                        raise InputFormatError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
    except UnicodeDecodeError as exc:
        raise InputFormatError(f"{path}: not valid UTF-8 ({exc})") from exc
    except OSError as exc:
        raise InputFormatError(f"cannot read {path}: {exc}") from exc
    return events


def _first_nonspace(fh) -> str:
    while True:
        ch = fh.read(1)
        if not ch:
            return ""
        if not ch.isspace():
            return ch


def _cap(events: List[Event], max_events: Optional[int], path: str) -> None:
    if max_events is not None and len(events) >= max_events:
        raise InputTooLargeError(f"{path}: exceeds --max-events={max_events}")
