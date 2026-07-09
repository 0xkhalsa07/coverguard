"""SARIF 2.1.0 output so findings can be ingested by GitHub Code Scanning
and other SARIF-aware tools.
"""

from __future__ import annotations

import json
from typing import List

from . import __version__
from .models import RuleResult

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
          "LOW": "note", "UNKNOWN": "warning"}
_INFO_URI = "https://github.com/0xkhalsa07/coverguard"


def render_sarif(coverage, rule_results: List[RuleResult]) -> str:
    rules = []
    results = []
    seen = set()
    for r in rule_results:
        if r.rule not in seen:
            seen.add(r.rule)
            rules.append({
                "id": r.rule,
                "name": r.title,
                "shortDescription": {"text": r.title},
            })
        for a in r.alerts:
            results.append({
                "ruleId": a.rule,
                "level": _LEVEL.get(a.severity, "warning"),
                "message": {"text": a.detail},
                "properties": {
                    "severity": a.severity,
                    "user": a.user,
                    "component": a.component,
                    "tool": a.tool_name,
                    "sessionId": a.session_id,
                    "promptId": a.prompt_id,
                },
            })
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "coverguard",
                "version": __version__,
                "informationUri": _INFO_URI,
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)
