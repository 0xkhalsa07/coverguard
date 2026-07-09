"""coverguard: CVE-aware coverage for Claude Cowork tool calls.

A small, dependency-free tool that ingests the OpenTelemetry events Claude Cowork
emits, matches invoked tools and MCP connectors against a pinned inventory and a
CVE feed, runs a set of detection rules, and reports how much of the capability
is actually covered.
"""

__version__ = "1.1.0"
__all__ = ["__version__"]
