"""Human and machine reports. All user-controlled values are HTML-escaped."""

from __future__ import annotations

import html
from typing import List

from .models import RuleResult

# UI colours. The status key "PASS" would trip bandit B105 (hardcoded password);
# B105 is skipped in .bandit.yaml because coverguard handles no credentials.
_BADGE = {"PASS": "#1a7f37", "PARTIAL": "#9a6700", "FAIL": "#cf222e",
          "REVIEW": "#0969da", "N/A": "#6e7781"}
_SEV = {"CRITICAL": "#cf222e", "HIGH": "#cf222e", "MEDIUM": "#9a6700",
        "LOW": "#0969da", "UNKNOWN": "#6e7781"}


def render_text(coverage, rule_results: List[RuleResult]) -> str:
    out: List[str] = []
    out.append("coverguard scan report")
    out.append("=" * 60)
    out.append(f"generated: {coverage['generated_at']}")
    out.append(f"pipeline healthy (MCP telemetry present): {coverage['pipeline_healthy']}")
    c = coverage["counts"]
    out.append(f"events={c['events']} tool_events={c['tool_events']} "
               f"users={c['distinct_users']} mcp_components={c['distinct_mcp_components']}")
    out.append("")
    out.append("Capability coverage")
    out.append("-" * 60)
    for row in coverage["capability_matrix"]:
        out.append(f"[{row['status']:<7}] {row['gap']}")
        out.append(f"           {row['value']}")
    out.append("")
    out.append("Detection rules")
    out.append("-" * 60)
    total = 0
    for r in rule_results:
        total += len(r.alerts)
        state = f"{len(r.alerts)} alerts" if r.evaluated else f"SKIPPED ({r.skipped_reason})"
        out.append(f"{r.rule}  {r.title:<45} {state}")
        for a in r.alerts:
            out.append(f"     - [{a.severity}] {a.detail} (user={a.user})")
    out.append("")
    out.append(f"TOTAL ALERTS: {total}")
    if coverage.get("suppressed"):
        out.append(f"SUPPRESSED: {coverage['suppressed']} (allowlisted, not shown)")
    kev = coverage.get("cve", {}).get("kev_components") or []
    if kev:
        out.append(f"IN CISA KEV (known exploited): {', '.join(kev)}")
    prov = coverage.get("provenance")
    if prov:
        out.append("")
        out.append(f"provenance: tool={prov.get('tool_version')} "
                   f"redacted={prov.get('redacted')}")
    return "\n".join(out)


def render_html(coverage, rule_results: List[RuleResult]) -> str:
    def esc(x):
        return html.escape(str(x))

    matrix = "\n".join(
        f"<tr><td><b>{esc(row['gap'])}</b><br><span class='muted'>{esc(row['measure'])}</span></td>"
        f"<td><span class='badge' style='background:{_BADGE.get(row['status'], '#6e7781')}'>"
        f"{esc(row['status'])}</span></td><td>{esc(row['value'])}</td></tr>"
        for row in coverage["capability_matrix"])

    rules = "\n".join(
        f"<tr><td>{esc(r.rule)}</td><td>{esc(r.title)}</td>"
        f"<td>{(str(len(r.alerts)) + ' alerts') if r.evaluated else '<span class=muted>skipped: ' + esc(r.skipped_reason) + '</span>'}</td></tr>"
        for r in rule_results)

    alert_rows = [
        f"<tr><td>{esc(a.rule)}</td>"
        f"<td><span class='badge' style='background:{_SEV.get(a.severity, '#6e7781')}'>{esc(a.severity)}</span></td>"
        f"<td>{esc(a.component or a.tool_name or '-')}</td>"
        f"<td>{esc(a.user)}</td><td>{esc(a.detail)}</td></tr>"
        for r in rule_results for a in r.alerts]
    alerts = "\n".join(alert_rows) or "<tr><td colspan=5 class='muted'>No alerts.</td></tr>"

    unknown = coverage["inventory"]["unknown_observed"]
    unknown_html = ", ".join(esc(u) for u in unknown) if unknown else "<span class='muted'>none</span>"
    vuln = coverage["cve"]["vulnerable_components"]
    vuln_html = ", ".join(esc(v) for v in vuln) if vuln else "<span class='muted'>none</span>"
    kev = coverage["cve"].get("kev_components", [])
    suppressed = coverage.get("suppressed", 0)

    ap, fl, c = coverage["approvals"], coverage["fleet"], coverage["counts"]
    prov = coverage.get("provenance", {})

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>coverguard report</title>
<style>
:root {{ color-scheme: light; }}
body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
        margin: 0; padding: 32px; background: #f6f8fa; color: #1f2328; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
h2 {{ font-size: 15px; margin: 28px 0 8px; text-transform: uppercase; letter-spacing: .04em; color: #57606a; }}
.card {{ background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 16px 18px; margin-bottom: 16px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13.5px; }}
th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #eaeef2; vertical-align: top; }}
th {{ color: #57606a; font-weight: 600; }}
.badge {{ color: #fff; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }}
.muted {{ color: #6e7781; }}
.kpis {{ display: flex; gap: 12px; flex-wrap: wrap; }}
.kpi {{ flex: 1; min-width: 130px; background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px 14px; }}
.kpi .n {{ font-size: 24px; font-weight: 700; }}
.kpi .l {{ font-size: 12px; color: #57606a; }}
code {{ background: #eff1f3; padding: 1px 5px; border-radius: 4px; }}
</style></head><body>
<h1>coverguard scan report</h1>
<div class="muted">generated {esc(coverage['generated_at'])} &middot; pipeline healthy: <b>{esc(coverage['pipeline_healthy'])}</b>
&middot; redacted: <b>{esc(prov.get('redacted', False))}</b> &middot; suppressed: <b>{esc(suppressed)}</b></div>

<h2>Snapshot</h2>
<div class="kpis">
  <div class="kpi"><div class="n">{c['tool_events']}</div><div class="l">tool calls seen</div></div>
  <div class="kpi"><div class="n">{c['distinct_mcp_components']}</div><div class="l">distinct MCP components</div></div>
  <div class="kpi"><div class="n">{len(vuln)}</div><div class="l">vulnerable components</div></div>
  <div class="kpi"><div class="n">{len(kev)}</div><div class="l">in CISA KEV</div></div>
  <div class="kpi"><div class="n">{len(unknown)}</div><div class="l">unknown components</div></div>
  <div class="kpi"><div class="n">{ap['auto']}/{ap['total']}</div><div class="l">auto-approved calls</div></div>
  <div class="kpi"><div class="n">{len(fl['below_min_version'])}</div><div class="l">versions below min</div></div>
</div>

<h2>Capability coverage (mapped to the four gaps)</h2>
<div class="card"><table>
<tr><th>Gap / measure</th><th>Status</th><th>Value</th></tr>
{matrix}
</table></div>

<h2>Detection rules</h2>
<div class="card"><table>
<tr><th>Rule</th><th>Title</th><th>Result</th></tr>
{rules}
</table></div>

<h2>Alerts</h2>
<div class="card"><table>
<tr><th>Rule</th><th>Severity</th><th>Component / tool</th><th>User</th><th>Detail</th></tr>
{alerts}
</table></div>

<h2>Detail</h2>
<div class="card">
<p><b>Vulnerable components:</b> {vuln_html}</p>
<p><b>Unknown MCP components (not in inventory):</b> {unknown_html}</p>
<p><b>Fleet versions:</b> <code>{esc(fl['distinct_versions'])}</code>; below minimum: <code>{esc(fl['below_min_version'])}</code></p>
<p><b>Fleet coverage:</b> {esc(fl['fleet_coverage_pct'])}% (roster size {esc(fl['roster_size'])})</p>
</div>

<div class="muted" style="font-size:12px">
coverguard {esc(prov.get('tool_version', ''))} &middot; detective control, not preventive &middot;
version fidelity comes from the pinned inventory, not the OTel stream.
</div>
</body></html>"""
