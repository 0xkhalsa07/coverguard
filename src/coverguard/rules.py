"""Detection rules R1-R6 over Cowork OTel events."""

from __future__ import annotations

from typing import Dict, List, Optional

from .inventory import Inventory
from .models import Alert, Event, Finding, RuleResult
from .versions import cmp_version

# Tools whose auto-approval (no human in the loop) is worth reviewing.
DEFAULT_SENSITIVE_TOOLS = {
    "Bash", "Shell", "Exec", "Terminal", "Command",
    "Write", "Edit", "NotebookEdit",
    "WebFetch", "web_fetch", "WebSearch",
}
# decision_source values that mean "no human confirmed this call".
AUTO_DECISION_SOURCES = {"config", "hook"}
# Substrings that flag a sensitive path or secret being touched.
DEFAULT_SENSITIVE_PATTERNS = [
    ".ssh", "id_rsa", "id_ed25519", ".aws", ".env", "secrets", "secret",
    "credentials", ".kube", "/etc/shadow", "/etc/passwd", ".npmrc",
    ".git-credentials", ".netrc", "private_key", "token",
]

# App builds below this do not emit (complete) OTel telemetry.
MIN_APP_VERSION = "1.1.4173"


class Detector:
    def __init__(self, inventory: Inventory, vuln_map: Dict[str, List[Finding]],
                 sensitive_tools: Optional[set] = None,
                 sensitive_patterns: Optional[List[str]] = None,
                 roster: Optional[List[str]] = None,
                 min_app_version: Optional[str] = None):
        self.inv = inventory
        self.vuln_map = vuln_map
        self.sensitive_tools = sensitive_tools or set(DEFAULT_SENSITIVE_TOOLS)
        self.sensitive_patterns = sensitive_patterns or list(DEFAULT_SENSITIVE_PATTERNS)
        self.roster = roster
        self.min_app_version = min_app_version or MIN_APP_VERSION

    def run(self, events: List[Event]) -> List[RuleResult]:
        tool_events = [e for e in events if e.event_name == "tool_result"]
        return [
            self._r1(tool_events),
            self._r2(tool_events),
            self._r3(tool_events),
            self._r4(events),
            self._r5(tool_events),
            self._r6(events),
        ]

    def _mk(self, e: Event, rule: str, severity: str, detail: str) -> Alert:
        return Alert(rule=rule, severity=severity, component=e.component,
                     tool_name=e.tool_name, user=e.user,
                     session_id=e.attr("session.id"), prompt_id=e.attr("prompt.id"),
                     detail=detail)

    def _r1(self, tool_events: List[Event]) -> RuleResult:
        res = RuleResult("R1", "Known-vulnerable component invoked", True)
        for e in tool_events:
            findings = self.vuln_map.get(e.component or "")
            if e.component and findings:
                ids = ", ".join(f.id for f in findings)
                worst = max((f.severity for f in findings), default="UNKNOWN")
                kev = any(f.kev for f in findings)
                epss = max((f.epss for f in findings if f.epss is not None), default=None)
                fixed = next((f.fixed_version for f in findings if f.fixed_version), None)
                detail = f"{e.component} matches {ids}"
                if fixed:
                    detail += f"; fixed in {fixed}"
                if kev:
                    detail += "; in CISA KEV (known exploited)"
                if epss is not None:
                    detail += f"; EPSS {epss:.2f}"
                res.alerts.append(self._mk(e, "R1", "CRITICAL" if kev else worst, detail))
        return res

    def _r2(self, tool_events: List[Event]) -> RuleResult:
        res = RuleResult("R2", "Unapproved / unknown component invoked", True)
        for e in tool_events:
            if e.component and e.is_mcp and not self.inv.is_approved(e.component):
                res.alerts.append(self._mk(
                    e, "R2", "HIGH",
                    f"MCP server '{e.component}' not in approved inventory "
                    f"(possible shadow or unvetted connector)"))
        return res

    def _r3(self, tool_events: List[Event]) -> RuleResult:
        res = RuleResult("R3", "Sensitive action auto-approved (no human)", True)
        for e in tool_events:
            if e.tool_name in self.sensitive_tools and e.decision_source in AUTO_DECISION_SOURCES:
                res.alerts.append(self._mk(
                    e, "R3", "MEDIUM",
                    f"'{e.tool_name}' auto-approved via decision_source='{e.decision_source}'"))
        return res

    def _r4(self, events: List[Event]) -> RuleResult:
        res = RuleResult("R4", "Endpoint below minimum app version", True)
        seen = set()
        for e in events:
            v = e.app_version
            if v and cmp_version(v, self.min_app_version) < 0:
                key = f"{e.user}@{v}"
                if key not in seen:
                    seen.add(key)
                    res.alerts.append(self._mk(
                        e, "R4", "MEDIUM",
                        f"app version {v} < required {self.min_app_version}; "
                        f"telemetry may be incomplete for this endpoint"))
        return res

    def _r5(self, tool_events: List[Event]) -> RuleResult:
        res = RuleResult("R5", "Sensitive path or secret touched", True)
        for e in tool_events:
            text = e.touched_text
            hit = next((p for p in self.sensitive_patterns if p in text), None)
            if hit:
                res.alerts.append(self._mk(
                    e, "R5", "MEDIUM",
                    f"tool '{e.tool_name}' touched a path matching '{hit}'"))
        return res

    def _r6(self, events: List[Event]) -> RuleResult:
        res = RuleResult("R6", "Telemetry silence (fleet not reporting)", True)
        if not self.roster:
            res.evaluated = False
            res.skipped_reason = "no roster provided (--roster); cannot judge who is silent"
            return res
        active = {e.user for e in events}
        for expected in self.roster:
            if expected not in active:
                res.alerts.append(Alert(
                    rule="R6", severity="MEDIUM", component=None, tool_name=None,
                    user=expected, session_id=None, prompt_id=None,
                    detail=f"'{expected}' on roster but produced no Cowork events "
                           f"(check OTLP config / egress allowlist)"))
        return res
