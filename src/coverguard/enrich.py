"""Optional enrichment of findings with EPSS scores and CISA KEV flags.

EPSS (Exploit Prediction Scoring System, FIRST.org) estimates the probability a
CVE will be exploited. CISA KEV is the catalog of Known Exploited
Vulnerabilities. Both are optional and never fatal: online lookups degrade to a
no-op on failure, and a local KEV file can be used for offline runs.

Endpoints are constant https hosts and are never taken from input data.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from typing import Dict, Iterable, List, Optional, Set

from .ingest import load_json_file
from .models import Finding
from .security import DEFAULT_MAX_BYTES

_EPSS_URL = "https://api.first.org/data/v1/epss"
_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_log = logging.getLogger("coverguard.enrich")


def all_cve_ids(vuln_map: Dict[str, List[Finding]]) -> Set[str]:
    return {
        f.id.upper()
        for findings in vuln_map.values()
        for f in findings
        if f.id.upper().startswith("CVE-")
    }


def load_kev_ids(path: Optional[str], online: bool, max_bytes: int = DEFAULT_MAX_BYTES) -> Set[str]:
    """KEV CVE IDs from a local catalog file and/or the live CISA catalog."""
    ids: Set[str] = set()
    if path:
        ids |= _kev_ids(load_json_file(path, max_bytes))
    if online:
        data = _get_json(_KEV_URL)
        if data:
            ids |= _kev_ids(data)
    return ids


def _kev_ids(data) -> Set[str]:
    out: Set[str] = set()
    if isinstance(data, dict):
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID") or v.get("cve_id")
            if cid:
                out.add(str(cid).upper())
    elif isinstance(data, list):
        for v in data:
            if isinstance(v, str):
                out.add(v.upper())
            elif isinstance(v, dict) and v.get("cveID"):
                out.add(str(v["cveID"]).upper())
    return out


def fetch_epss(cve_ids: Iterable[str]) -> Dict[str, float]:
    """Best-effort EPSS scores by CVE id. Returns an empty dict on any failure."""
    ids = sorted(c.upper() for c in set(cve_ids) if c.upper().startswith("CVE-"))
    scores: Dict[str, float] = {}
    for batch in _chunks(ids, 100):
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        data = _get_json(f"{_EPSS_URL}?{query}")
        if not data:
            continue
        for row in data.get("data", []):
            cid = str(row.get("cve", "")).upper()
            try:
                scores[cid] = float(row.get("epss"))
            except (TypeError, ValueError):
                continue
    return scores


def annotate(vuln_map: Dict[str, List[Finding]], kev_ids: Set[str], epss: Dict[str, float]) -> None:
    """Mutate findings in place with a KEV flag and an EPSS score."""
    for findings in vuln_map.values():
        for f in findings:
            cid = f.id.upper()
            if cid in kev_ids:
                f.kev = True
            if cid in epss:
                f.epss = epss[cid]


def _chunks(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def _get_json(url: str):
    # Host is a constant https endpoint; only the query string varies (no SSRF).
    req = urllib.request.Request(url, headers={"Accept": "application/json"})  # nosec B310
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - enrichment is best effort, never fatal
        _log.warning("enrichment fetch failed: %s", exc)
        return None
