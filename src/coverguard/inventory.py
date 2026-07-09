"""The pinned component inventory: the source of truth for names and versions."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .errors import InputFormatError
from .ingest import load_json_file
from .models import Component
from .security import DEFAULT_MAX_BYTES


class Inventory:
    def __init__(self, components: List[Component]):
        self._by_name = {c.name: c for c in components}

    @staticmethod
    def load(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> "Inventory":
        data = load_json_file(path, max_bytes)
        rows = data["components"] if isinstance(data, dict) and "components" in data else data
        if not isinstance(rows, list):
            raise InputFormatError(f"{path}: expected a list of components or {{'components': [...]}}")
        fields = Component.__dataclass_fields__
        comps = []
        for r in rows:
            if not isinstance(r, dict) or "name" not in r:
                raise InputFormatError(f"{path}: each component must be an object with a 'name'")
            kwargs: Dict[str, Any] = {k: r[k] for k in fields if k in r}
            comps.append(Component(**kwargs))
        return Inventory(comps)

    def get(self, name: Optional[str]) -> Optional[Component]:
        return self._by_name.get(name) if name else None

    def is_approved(self, name: Optional[str]) -> bool:
        return name in self._by_name

    def all(self) -> List[Component]:
        return list(self._by_name.values())
