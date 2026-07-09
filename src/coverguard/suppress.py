"""Suppressions (allowlist) for findings a team has reviewed and accepted.

A suppression is a JSON object matched against an alert. It must set at least one
of "rule", "component", or "tool"; an optional "expires" (YYYY-MM-DD) makes it
lapse. Suppressions never delete data: they remove matched alerts from the
active list and are counted in the coverage report.

    {"suppressions": [
      {"rule": "R2", "component": "internal-mcp", "reason": "vetted internally",
       "expires": "2026-12-31"}
    ]}
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from .errors import InputFormatError
from .ingest import load_json_file
from .models import Alert, RuleResult
from .security import DEFAULT_MAX_BYTES


def load_suppressions(path: Optional[str], max_bytes: int = DEFAULT_MAX_BYTES) -> List[Dict[str, Any]]:
    if not path:
        return []
    data = load_json_file(path, max_bytes)
    rows = data.get("suppressions") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise InputFormatError(f"{path}: suppressions must be a list or {{'suppressions': [...]}}")
    return [r for r in rows if isinstance(r, dict)]


def _active(rule: Dict[str, Any]) -> bool:
    expires = rule.get("expires")
    if not expires:
        return True
    try:
        parts = [int(x) for x in str(expires).split("-")[:3]]
        return date.today() <= date(parts[0], parts[1], parts[2])
    except (ValueError, IndexError, TypeError):
        return True  # a malformed date does not silently disable the suppression


def is_suppressed(alert: Alert, rules: List[Dict[str, Any]]) -> bool:
    for r in rules:
        if not (r.get("rule") or r.get("component") or r.get("tool")):
            continue  # a rule with no criteria must not match everything
        if not _active(r):
            continue
        if r.get("rule") and r["rule"] != alert.rule:
            continue
        if r.get("component") and r["component"] != (alert.component or ""):
            continue
        if r.get("tool") and r["tool"] != (alert.tool_name or ""):
            continue
        return True
    return False


def apply_suppressions(
    results: List[RuleResult], rules: List[Dict[str, Any]]
) -> Tuple[List[RuleResult], int]:
    if not rules:
        return results, 0
    out: List[RuleResult] = []
    suppressed = 0
    for res in results:
        kept: List[Alert] = []
        for alert in res.alerts:
            if is_suppressed(alert, rules):
                suppressed += 1
            else:
                kept.append(alert)
        out.append(replace(res, alerts=kept))
    return out, suppressed
