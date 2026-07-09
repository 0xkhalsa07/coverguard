"""Command-line interface.

Security plumbing lives here: integrity checks on inputs, PII redaction,
restrictive report writes, an audit log line, and graceful error handling that
never leaks a stack trace unless --debug is set.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from dataclasses import asdict, replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import __version__
from .config import load_config
from .coverage import compute_coverage
from .enrich import all_cve_ids, annotate, fetch_epss, load_kev_ids
from .errors import CoverguardError, InputFormatError
from .ingest import load_events, load_json_file
from .inventory import Inventory
from .models import RuleResult
from .report import render_html, render_text
from .report_sarif import render_sarif
from .rules import MIN_APP_VERSION, Detector
from .security import (
    DEFAULT_MAX_BYTES,
    new_salt,
    redact_user,
    safe_write,
    sha256_file,
    verify_integrity,
)
from .suppress import apply_suppressions, load_suppressions
from .vulndb import VulnDB, osv_online_scan, refresh_advisories

_log = logging.getLogger("coverguard")


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def cmd_scan(args) -> int:
    max_bytes = args.max_bytes or DEFAULT_MAX_BYTES
    cfg = load_config(args.config, max_bytes)
    sensitive_tools = set(cfg["sensitive_tools"]) if cfg.get("sensitive_tools") else None
    sensitive_patterns = cfg.get("sensitive_patterns")
    min_ver = cfg.get("min_app_version") or MIN_APP_VERSION
    bands = cfg.get("bands")

    if args.inventory_sha256:
        verify_integrity(args.inventory, args.inventory_sha256)

    events = load_events(args.events, max_bytes, args.max_events)
    inventory = Inventory.load(args.inventory, max_bytes)

    vuln_map, vuln_source = _build_vuln_map(args, inventory, max_bytes)
    _enrich(args, vuln_map)

    detector = Detector(inventory, vuln_map,
                        sensitive_tools=sensitive_tools,
                        sensitive_patterns=sensitive_patterns,
                        roster=_load_roster(args.roster, max_bytes),
                        min_app_version=min_ver)
    results = detector.run(events)
    results, suppressed = apply_suppressions(results, load_suppressions(args.suppressions, max_bytes))

    coverage = compute_coverage(events, inventory, vuln_map, results,
                                _load_roster(args.roster, max_bytes),
                                min_app_version=min_ver, bands=bands, suppressed=suppressed)
    coverage["provenance"] = {
        "tool_version": __version__,
        "events": _prov(args.events),
        "inventory": _prov(args.inventory),
        "vulns": vuln_source,
        "redacted": bool(args.redact),
    }

    total = sum(len(r.alerts) for r in results)
    _log.info("scan user=%s events=%s inventory=%s vulns=%s alerts=%d suppressed=%d redacted=%s",
              getpass.getuser(), coverage["provenance"]["events"],
              coverage["provenance"]["inventory"], vuln_source, total, suppressed, bool(args.redact))
    if args.audit_log:
        _append_audit(args.audit_log, coverage, total, suppressed)

    if args.redact:
        salt = args.redact_salt or new_salt()
        results = _redact_results(results, salt)

    print(render_text(coverage, results))

    if args.out_json:
        payload = {"coverage": coverage, "alerts": [asdict(a) for r in results for a in r.alerts]}
        safe_write(args.out_json, json.dumps(payload, indent=2))
        print(f"\n[coverguard] wrote JSON report -> {args.out_json} (mode 0600)")
    if args.out_html:
        safe_write(args.out_html, render_html(coverage, results))
        print(f"[coverguard] wrote HTML report -> {args.out_html} (mode 0600)")
    if args.out_sarif:
        safe_write(args.out_sarif, render_sarif(coverage, results))
        print(f"[coverguard] wrote SARIF report -> {args.out_sarif} (mode 0600)")

    critical = any(a.severity in ("CRITICAL", "HIGH") for r in results for a in r.alerts)
    if args.fail_on_alert and total and critical:
        return 1
    return 0


def _build_vuln_map(args, inventory, max_bytes):
    if args.online:
        return osv_online_scan(inventory.all()), "osv.dev (online)"
    vulns = args.vulns or []
    if not vulns:
        raise InputFormatError("offline mode requires --vulns SNAPSHOT.json (or pass --online)")
    if args.vulns_sha256 and len(vulns) == 1:
        verify_integrity(vulns[0], args.vulns_sha256)
    elif args.vulns_sha256:
        _log.warning("--vulns-sha256 ignored with multiple --vulns; use 'coverguard verify' per file")
    advisories: List[Dict[str, Any]] = []
    sources: List[str] = []
    for path in vulns:
        db = VulnDB.load(path, max_bytes)
        advisories.extend(db.advisories)
        sources.append(f"{os.path.basename(path)} ({db.source})")
    merged = VulnDB(advisories, None, "; ".join(sources))
    vuln_map = {c.name: found for c in inventory.all() if (found := merged.match(c))}
    return vuln_map, "; ".join(sources)


def _enrich(args, vuln_map) -> None:
    if not (args.online or args.kev):
        return
    kev_ids = load_kev_ids(args.kev, args.online)
    epss = fetch_epss(all_cve_ids(vuln_map)) if args.online else {}
    annotate(vuln_map, kev_ids, epss)


# --------------------------------------------------------------------------- #
# refresh-vulns
# --------------------------------------------------------------------------- #
def cmd_refresh_vulns(args) -> int:
    inventory = Inventory.load(args.inventory, args.max_bytes or DEFAULT_MAX_BYTES)
    advisories = refresh_advisories(inventory.all())
    snapshot = {"generated_at": datetime.now(timezone.utc).isoformat(),
                "source": "osv.dev", "advisories": advisories}
    safe_write(args.out, json.dumps(snapshot, indent=2), mode=0o644)
    digest = sha256_file(args.out)
    safe_write(args.out + ".sha256", digest + "\n", mode=0o644)
    print(f"[coverguard] wrote {len(advisories)} advisories -> {args.out}")
    print(f"[coverguard] sha256 {digest} -> {args.out}.sha256")
    return 0


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def cmd_verify(args) -> int:
    actual = verify_integrity(args.file, args.sha256)
    print(f"[coverguard] OK {args.file} sha256={actual}")
    return 0


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _prov(path: Optional[str]):
    if not path:
        return None
    return {"path": os.path.basename(path), "sha256": sha256_file(path)}


def _load_roster(path: Optional[str], max_bytes: int) -> Optional[List[str]]:
    if not path:
        return None
    data = load_json_file(path, max_bytes)
    if isinstance(data, dict):
        data = data.get("users") or data.get("roster")
    if not isinstance(data, list):
        raise InputFormatError(f"{path}: roster must be a list or {{'users': [...]}}")
    return [str(x) for x in data]


def _redact_results(results: List[RuleResult], salt: str) -> List[RuleResult]:
    return [replace(r, alerts=[replace(a, user=redact_user(a.user, salt)) for a in r.alerts])
            for r in results]


def _append_audit(path: str, coverage: Dict[str, Any], total: int, suppressed: int) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "user": getpass.getuser(),
        "tool_version": __version__,
        "events": coverage["provenance"]["events"],
        "inventory": coverage["provenance"]["inventory"],
        "vulns": coverage["provenance"]["vulns"],
        "redacted": coverage["provenance"]["redacted"],
        "alerts": total,
        "suppressed": suppressed,
    }
    line = json.dumps(record) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log-level", default="warning",
                        choices=["debug", "info", "warning", "error"],
                        help="stderr log verbosity (default: warning)")
    common.add_argument("--debug", action="store_true",
                        help="show full tracebacks on unexpected errors")

    p = argparse.ArgumentParser(prog="coverguard",
                                description="CVE-aware coverage for Cowork tool calls.")
    p.add_argument("--version", action="version", version=f"coverguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", parents=[common], help="scan events and report coverage + alerts")
    s.add_argument("--events", required=True, help="Cowork OTel events (JSONL or JSON array)")
    s.add_argument("--inventory", required=True, help="approved component inventory (JSON)")
    s.add_argument("--vulns", action="append",
                   help="offline OSV-shaped vuln snapshot (JSON); repeat for multiple sources")
    s.add_argument("--roster", help="expected users/endpoints (JSON) to enable R6")
    s.add_argument("--online", action="store_true", help="query OSV.dev live instead of --vulns")
    s.add_argument("--config", help="JSON config to tune rules and coverage bands")
    s.add_argument("--suppressions", help="JSON allowlist of accepted findings")
    s.add_argument("--kev", help="CISA KEV catalog JSON for offline known-exploited flags")
    s.add_argument("--out-json", help="write full JSON report here (mode 0600)")
    s.add_argument("--out-html", help="write HTML report here (mode 0600)")
    s.add_argument("--out-sarif", help="write SARIF 2.1.0 report here (mode 0600)")
    s.add_argument("--audit-log", help="append a JSON audit record to this file (mode 0600)")
    s.add_argument("--redact", action="store_true", help="pseudonymise user identifiers in output")
    s.add_argument("--redact-salt", help="fixed salt for redaction (default: random per run)")
    s.add_argument("--inventory-sha256", help="expected SHA-256 of the inventory file")
    s.add_argument("--vulns-sha256", help="expected SHA-256 of a single vuln snapshot")
    s.add_argument("--max-bytes", type=int, help=f"max input file size (default {DEFAULT_MAX_BYTES})")
    s.add_argument("--max-events", type=int, help="max number of events to load")
    s.add_argument("--fail-on-alert", action="store_true",
                   help="exit 1 if any HIGH/CRITICAL alert fires (for CI)")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("refresh-vulns", parents=[common],
                       help="build an offline snapshot (+ .sha256) from OSV.dev")
    r.add_argument("--inventory", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--max-bytes", type=int)
    r.set_defaults(func=cmd_refresh_vulns)

    v = sub.add_parser("verify", parents=[common], help="verify a file's SHA-256")
    v.add_argument("--file", required=True)
    v.add_argument("--sha256", required=True)
    v.set_defaults(func=cmd_verify)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(getattr(args, "log_level", "warning"))
    try:
        return args.func(args)
    except CoverguardError as exc:
        sys.stderr.write(f"coverguard: error: {exc}\n")
        return exc.exit_code
    except KeyboardInterrupt:
        return 130
    except Exception:  # noqa: BLE001 - top-level guard
        if getattr(args, "debug", False):
            raise
        _log.exception("unexpected error")
        sys.stderr.write("coverguard: internal error (rerun with --debug for details)\n")
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
