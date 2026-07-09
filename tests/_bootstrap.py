"""Shared test bootstrap: make the src/ package importable and expose helpers."""

import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.abspath(os.path.join(_HERE, "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

EXAMPLES = os.path.abspath(os.path.join(_HERE, "..", "examples"))

import coverguard as cg  # noqa: E402,F401
from coverguard import (  # noqa: E402,F401
    cli,
    coverage,
    errors,
    ingest,
    inventory,
    models,
    report,
    rules,
    security,
    versions,
    vulndb,
)
from coverguard.models import Component, Event, Finding  # noqa: E402,F401


def tool_event(component=None, tool_name=None, decision_source="user_temporary",
               tool_input="", version="1.1.4200", user="user_01X", mcp=True):
    params = {}
    if mcp and component:
        params = {"mcp_server_name": component, "mcp_tool_name": tool_name or "do"}
    return Event.from_obj({
        "event_name": "tool_result",
        "attributes": {
            "session.id": "s1", "user.account_uuid": user, "prompt.id": "p1",
            "tool_name": tool_name or component, "success": "true",
            "decision_type": "accept", "decision_source": decision_source,
            "tool_parameters": json.dumps(params) if params else "",
            "tool_input": tool_input,
        },
        "resource": {"service.name": "cowork", "service.version": version},
    })
