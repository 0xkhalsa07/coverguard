import contextlib
import io
import json
import os
import tempfile
import unittest

from _bootstrap import EXAMPLES
from coverguard.cli import main

EVENTS = os.path.join(EXAMPLES, "events.jsonl")
INV = os.path.join(EXAMPLES, "inventory.json")
VULNS = os.path.join(EXAMPLES, "vuln_snapshot.json")
ROSTER = os.path.join(EXAMPLES, "roster.json")
KEV = os.path.join(EXAMPLES, "kev.json")
CONFIG = os.path.join(EXAMPLES, "config.json")
SUPP = os.path.join(EXAMPLES, "suppressions.json")


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


def tmp(name):
    return os.path.join(tempfile.mkdtemp(), name)


class CliExtraTests(unittest.TestCase):
    def test_kev_offline_escalates_to_critical(self):
        out_json = tmp("r.json")
        code, _ = run(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
                       "--kev", KEV, "--out-json", out_json])
        self.assertEqual(code, 0)
        with open(out_json) as fh:
            data = json.load(fh)
        self.assertIn("acme-github-mcp", data["coverage"]["cve"]["kev_components"])
        r1 = [a for a in data["alerts"] if a["rule"] == "R1"][0]
        self.assertEqual(r1["severity"], "CRITICAL")
        self.assertIn("KEV", r1["detail"])

    def test_sarif_output(self):
        out_sarif = tmp("r.sarif")
        code, _ = run(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
                       "--out-sarif", out_sarif])
        self.assertEqual(code, 0)
        with open(out_sarif) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])

    def test_suppressions_remove_r3(self):
        out_json = tmp("r.json")
        code, _ = run(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
                       "--suppressions", SUPP, "--out-json", out_json])
        self.assertEqual(code, 0)
        with open(out_json) as fh:
            data = json.load(fh)
        self.assertGreaterEqual(data["coverage"]["suppressed"], 1)
        self.assertFalse([a for a in data["alerts"] if a["rule"] == "R3"])

    def test_config_runs(self):
        code, out = run(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
                         "--config", CONFIG])
        self.assertEqual(code, 0)
        self.assertIn("coverguard scan report", out)

    def test_multiple_vulns_merge(self):
        code, out = run(["scan", "--events", EVENTS, "--inventory", INV,
                         "--vulns", VULNS, "--vulns", VULNS])
        self.assertEqual(code, 0)
        self.assertIn("coverguard scan report", out)

    def test_audit_log_written(self):
        audit = tmp("audit.jsonl")
        run(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
             "--audit-log", audit])
        with open(audit) as fh:
            record = json.loads(fh.readline())
        self.assertIn("alerts", record)
        self.assertIn("ts", record)


if __name__ == "__main__":
    unittest.main()
