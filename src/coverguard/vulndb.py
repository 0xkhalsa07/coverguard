"""CVE matching: offline OSV-shaped snapshot, plus optional live OSV.dev lookups.

The OSV endpoint is hardcoded to api.osv.dev. It is never taken from input data,
so untrusted events cannot redirect outbound requests (no SSRF surface).
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any, Dict, List, Optional

from .ingest import load_json_file
from .models import Component, Finding, normalize_ecosystem
from .security import DEFAULT_MAX_BYTES
from .versions import version_in_range

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_log = logging.getLogger("coverguard.vulndb")


class VulnDB:
    """OSV-shaped advisory set, matched by (ecosystem, package, version)."""

    def __init__(self, advisories: List[Dict[str, Any]], generated_at: Optional[str], source: str):
        self.advisories = advisories
        self.generated_at = generated_at
        self.source = source

    @staticmethod
    def load(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> "VulnDB":
        data = load_json_file(path, max_bytes)
        return VulnDB(
            data.get("advisories", []),
            data.get("generated_at"),
            data.get("source", os.path.basename(path)),
        )

    def match(self, comp: Component) -> List[Finding]:
        if not comp.has_coordinates:
            return []
        return match_advisories(self.advisories, comp.ecosystem, comp.package, comp.pinned_version)


def match_advisories(advisories, ecosystem, package, version) -> List[Finding]:
    target_eco = normalize_ecosystem(ecosystem)
    findings: List[Finding] = []
    for adv in advisories:
        for aff in adv.get("affected", []):
            pkg = aff.get("package", {})
            if normalize_ecosystem(pkg.get("ecosystem")) != target_eco or pkg.get("name") != package:
                continue
            if _affected(aff, version):
                findings.append(Finding(
                    id=adv.get("id", "UNKNOWN"),
                    severity=str(adv.get("severity", "UNKNOWN")).upper(),
                    fixed_version=_first_fixed(aff),
                    summary=adv.get("summary", ""),
                ))
                break
    return findings


def _affected(aff: Dict[str, Any], version: Any) -> bool:
    explicit = aff.get("versions")
    if explicit and str(version) in [str(v) for v in explicit]:
        return True
    for rng in aff.get("ranges", []):
        introduced = fixed = None
        for ev in rng.get("events", []):
            if "introduced" in ev:
                introduced = ev["introduced"]
            if "fixed" in ev:
                fixed = ev["fixed"]
        if rng.get("events") and version_in_range(version, introduced, fixed):
            return True
    # No ranges and no explicit versions => advisory applies to all versions.
    return not aff.get("ranges") and not explicit


def _first_fixed(aff: Dict[str, Any]) -> Optional[str]:
    for rng in aff.get("ranges", []):
        for ev in rng.get("events", []):
            if "fixed" in ev:
                return ev["fixed"]
    return None


def _osv_post(payload: Dict[str, Any], timeout: float) -> Optional[Dict[str, Any]]:
    body = json.dumps(payload).encode("utf-8")
    # OSV endpoint is a constant https URL, never taken from input data (no SSRF).
    req = urllib.request.Request(  # nosec B310
        _OSV_QUERY_URL, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - live lookups are best effort, never fatal
        _log.warning("OSV lookup failed: %s", exc)
        return None


def osv_online_scan(components: List[Component], timeout: float = 10.0) -> Dict[str, List[Finding]]:
    out: Dict[str, List[Finding]] = {}
    for comp in components:
        if not comp.has_coordinates:
            continue
        data = _osv_post(
            {"package": {"ecosystem": comp.ecosystem, "name": comp.package},
             "version": comp.pinned_version}, timeout)
        if not data:
            continue
        findings = [
            Finding(id=v.get("id", "UNKNOWN"), severity=_osv_severity(v),
                    fixed_version=_osv_first_fixed(v), summary=v.get("summary", ""))
            for v in data.get("vulns", [])
        ]
        if findings:
            out[comp.name] = findings
    return out


def refresh_advisories(components: List[Component], timeout: float = 15.0) -> List[Dict[str, Any]]:
    """Fetch full advisories for an offline snapshot."""
    advisories: List[Dict[str, Any]] = []
    seen = set()
    for comp in components:
        if not comp.has_coordinates:
            continue
        data = _osv_post({"package": {"ecosystem": comp.ecosystem, "name": comp.package}}, timeout)
        if not data:
            continue
        for vuln in data.get("vulns", []):
            vid = vuln.get("id")
            if vid and vid not in seen:
                seen.add(vid)
                advisories.append(vuln)
    return advisories


def _osv_severity(vuln: Dict[str, Any]) -> str:
    ds = vuln.get("database_specific", {})
    if isinstance(ds, dict) and ds.get("severity"):
        return str(ds["severity"]).upper()
    for sev in vuln.get("severity", []):
        if sev.get("score"):
            return str(sev["score"])
    return "UNKNOWN"


def _osv_first_fixed(vuln: Dict[str, Any]) -> Optional[str]:
    for aff in vuln.get("affected", []):
        fixed = _first_fixed(aff)
        if fixed:
            return fixed
    return None
