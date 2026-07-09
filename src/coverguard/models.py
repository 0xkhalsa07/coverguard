"""Core data types: Event, Component, Finding, Alert, RuleResult."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from .errors import InputFormatError

# Map common Package URL types and lowercase names to OSV ecosystem names.
_ECOSYSTEM_ALIASES = {
    "npm": "npm", "node": "npm",
    "pypi": "PyPI", "pip": "PyPI", "python": "PyPI",
    "go": "Go", "golang": "Go",
    "cargo": "crates.io", "crates": "crates.io", "rust": "crates.io",
    "maven": "Maven", "gem": "RubyGems", "rubygems": "RubyGems",
    "nuget": "NuGet", "composer": "Packagist", "packagist": "Packagist",
    "hex": "Hex", "pub": "Pub",
}


def normalize_ecosystem(ecosystem: Optional[str]) -> Optional[str]:
    if not ecosystem:
        return ecosystem
    return _ECOSYSTEM_ALIASES.get(ecosystem.strip().lower(), ecosystem)


def parse_purl(purl: Optional[str]):
    """Best-effort Package URL parse: returns (ecosystem, package, version)."""
    if not purl or not purl.startswith("pkg:"):
        return (None, None, None)
    body = purl[4:]
    version = None
    if "@" in body:
        body, version = body.rsplit("@", 1)
        version = unquote(version)
    body = body.split("?", 1)[0].split("#", 1)[0]
    parts = [p for p in body.split("/") if p != ""]
    if not parts:
        return (None, None, version)
    name = unquote("/".join(parts[1:])) if len(parts) > 1 else None
    return (normalize_ecosystem(parts[0]), name, version)


@dataclass
class Event:
    """One Cowork OTel log/event record.

    Expected shape (one JSON object per line, or a JSON array):
        {"event_name": "tool_result",
         "attributes": {...},   # event + standard attributes
         "resource":   {...}}   # service.name, service.version, os.*, ...
    Flat records (all keys in one object) are tolerated for convenience.
    """

    event_name: str
    attributes: Dict[str, Any]
    resource: Dict[str, Any]

    @staticmethod
    def from_obj(obj: Any) -> "Event":
        if not isinstance(obj, dict):
            raise InputFormatError("event record must be a JSON object")
        name = obj.get("event_name") or obj.get("event.name") or obj.get("name") or "unknown"
        attrs = dict(obj.get("attributes", {}) or {})
        res = dict(obj.get("resource", {}) or {})
        if not obj.get("attributes"):
            for k, val in obj.items():
                if k in ("event_name", "event.name", "name", "resource"):
                    continue
                target = res if k.startswith(("service.", "os.", "host.")) else attrs
                target[k] = val
        return Event(event_name=name, attributes=attrs, resource=res)

    def attr(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    @property
    def user(self) -> str:
        return self.attr("user.account_uuid") or self.attr("user.email") or "unknown"

    @property
    def app_version(self) -> Optional[str]:
        return self.resource.get("service.version")

    @property
    def tool_name(self) -> Optional[str]:
        return self.attr("tool_name")

    def _tool_params(self) -> Dict[str, Any]:
        raw = self.attr("tool_parameters")
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    @property
    def mcp_server_name(self) -> Optional[str]:
        return self._tool_params().get("mcp_server_name")

    @property
    def mcp_tool_name(self) -> Optional[str]:
        return self._tool_params().get("mcp_tool_name")

    @property
    def component(self) -> Optional[str]:
        """The identity we hold accountable: MCP server if present, else tool."""
        return self.mcp_server_name or self.tool_name

    @property
    def is_mcp(self) -> bool:
        return self.mcp_server_name is not None

    @property
    def decision_source(self) -> Optional[str]:
        return self.attr("decision_source") or self.attr("source")

    @property
    def touched_text(self) -> str:
        """Free text likely to contain paths/args, for sensitive-data matching."""
        bits = [str(self.attr("tool_input", "")), str(self.attr("tool_parameters", ""))]
        hp = self.attr("workspace.host_paths") or self.resource.get("workspace.host_paths")
        if isinstance(hp, (list, tuple)):
            bits.extend(str(x) for x in hp)
        elif hp:
            bits.append(str(hp))
        return " ".join(bits).lower()


@dataclass
class Component:
    name: str
    type: str = "mcp_server"
    ecosystem: Optional[str] = None
    package: Optional[str] = None
    pinned_version: Optional[str] = None
    purl: Optional[str] = None
    owner: Optional[str] = None
    justification: Optional[str] = None

    def __post_init__(self) -> None:
        if self.purl and not (self.ecosystem and self.package and self.pinned_version):
            eco, name, ver = parse_purl(self.purl)
            self.ecosystem = self.ecosystem or eco
            self.package = self.package or name
            self.pinned_version = self.pinned_version or ver
        self.ecosystem = normalize_ecosystem(self.ecosystem)

    @property
    def has_coordinates(self) -> bool:
        return bool(self.ecosystem and self.package and self.pinned_version)


@dataclass
class Finding:
    id: str
    severity: str
    fixed_version: Optional[str]
    summary: str
    epss: Optional[float] = None
    kev: bool = False


@dataclass
class Alert:
    rule: str
    severity: str
    component: Optional[str]
    tool_name: Optional[str]
    user: str
    session_id: Optional[str]
    prompt_id: Optional[str]
    detail: str


@dataclass
class RuleResult:
    rule: str
    title: str
    evaluated: bool
    alerts: List[Alert] = field(default_factory=list)
    skipped_reason: Optional[str] = None
