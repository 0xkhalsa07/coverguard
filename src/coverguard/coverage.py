"""Compute the capability coverage the tool is judged on."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import RuleResult
from .rules import AUTO_DECISION_SOURCES, MIN_APP_VERSION
from .versions import cmp_version


def compute_coverage(events, inventory, vuln_map, rule_results: List[RuleResult],
                     roster: Optional[List[str]],
                     min_app_version: str = MIN_APP_VERSION,
                     bands: Optional[Dict[str, float]] = None,
                     suppressed: int = 0) -> Dict[str, Any]:
    tool_events = [e for e in events if e.event_name == "tool_result"]
    observed = Counter(e.component for e in tool_events if e.component)
    observed_mcp = {e.component for e in tool_events if e.is_mcp and e.component}
    approved_mcp = {c for c in observed_mcp if inventory.is_approved(c)}
    unknown_mcp = sorted(observed_mcp - approved_mcp)

    inv_all = inventory.all()
    inv_with_coords = [c for c in inv_all if c.has_coordinates]
    vulnerable = sorted(vuln_map.keys())
    kev_components = sorted(k for k, v in vuln_map.items() if any(f.kev for f in v))
    epss_values = [f.epss for v in vuln_map.values() for f in v if f.epss is not None]
    max_epss = max(epss_values) if epss_values else None

    decisions = [e.decision_source for e in tool_events if e.decision_source]
    auto = sum(1 for d in decisions if d in AUTO_DECISION_SOURCES)
    human = len(decisions) - auto

    versions = Counter(e.app_version for e in events if e.app_version)
    below_min = {v: n for v, n in versions.items() if cmp_version(v, min_app_version) < 0}

    users = {e.user for e in events}
    pipeline_healthy = any(e.mcp_server_name for e in tool_events)

    def pct(n, d):
        return round(100.0 * n / d, 1) if d else None

    inv_match_rate = pct(len(approved_mcp), len(observed_mcp)) if observed_mcp else None
    cve_scan_rate = pct(len(inv_with_coords), len(inv_all)) if inv_all else None
    fleet_cov = pct(len(users), len(roster)) if roster else None

    vuln_note = f"{len(vulnerable)} vulnerable now"
    if kev_components:
        vuln_note += f", {len(kev_components)} in CISA KEV"

    matrix = [
        {"gap": "1. Telemetry configured and flowing",
         "measure": "tool_result events with mcp_server_name present",
         "status": "PASS" if pipeline_healthy else "FAIL",
         "value": f"{len(tool_events)} tool events, {len(observed_mcp)} distinct MCP components"},
        {"gap": "2. Invoked component is identifiable and versioned",
         "measure": "observed MCP components matched to pinned inventory",
         "status": _band(inv_match_rate, bands),
         "value": f"{inv_match_rate}% matched ({len(approved_mcp)}/{len(observed_mcp)}); "
                  f"versions come from inventory, not telemetry"},
        {"gap": "3. CVE-aware detection is live",
         "measure": "inventory components with resolvable coordinates + R1 active",
         "status": _band(cve_scan_rate, bands),
         "value": f"{cve_scan_rate}% scannable ({len(inv_with_coords)}/{len(inv_all)}); "
                  f"{vuln_note}"},
        {"gap": "4. Preventive posture (org-wide toggle is the only lever)",
         "measure": "unknown-component rate and auto-approval of sensitive tools",
         "status": "REVIEW",
         "value": f"{len(unknown_mcp)} unknown MCP components; "
                  f"{auto}/{len(decisions)} decisions auto-approved"},
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pipeline_healthy": pipeline_healthy,
        "suppressed": suppressed,
        "counts": {
            "events": len(events),
            "tool_events": len(tool_events),
            "distinct_users": len(users),
            "distinct_components": len(observed),
            "distinct_mcp_components": len(observed_mcp),
        },
        "inventory": {
            "total": len(inv_all),
            "with_coordinates": len(inv_with_coords),
            "match_rate_pct": inv_match_rate,
            "unknown_observed": unknown_mcp,
        },
        "cve": {
            "scannable_pct": cve_scan_rate,
            "vulnerable_components": vulnerable,
            "kev_components": kev_components,
            "max_epss": max_epss,
            "vulnerable_detail": {k: [asdict(f) for f in v] for k, v in vuln_map.items()},
        },
        "approvals": {"auto": auto, "human": human, "total": len(decisions)},
        "fleet": {
            "distinct_versions": dict(versions),
            "below_min_version": below_min,
            "roster_size": len(roster) if roster else None,
            "fleet_coverage_pct": fleet_cov,
        },
        "rules": {r.rule: {"title": r.title, "evaluated": r.evaluated,
                           "alerts": len(r.alerts), "skipped_reason": r.skipped_reason}
                  for r in rule_results},
        "capability_matrix": matrix,
        "top_components": observed.most_common(10),
    }


def _band(value: Optional[float], bands: Optional[Dict[str, float]] = None) -> str:
    if value is None:
        return "N/A"
    bands = bands or {}
    if value >= bands.get("pass", 95):
        return "PASS"
    if value >= bands.get("partial", 70):
        return "PARTIAL"
    return "FAIL"
