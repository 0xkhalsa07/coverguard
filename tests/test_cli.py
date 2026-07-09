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


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(argv)
    return code, out.getvalue()


class CliTests(unittest.TestCase):
    def test_scan_ok(self):
        code, out = run(["scan", "--events", EVENTS, "--inventory", INV,
                         "--vulns", VULNS, "--roster", ROSTER])
        self.assertEqual(code, 0)
        self.assertIn("coverguard scan report", out)

    def test_fail_on_alert_exit_code(self):
        code, _ = run(["scan", "--events", EVENTS, "--inventory", INV,
                       "--vulns", VULNS, "--fail-on-alert"])
        self.assertEqual(code, 1)  # HIGH alerts present (R1/R2)

    def test_redaction_removes_raw_ids(self):
        d = tempfile.mkdtemp()
        out_json = os.path.join(d, "r.json")
        code, _ = run(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
                       "--roster", ROSTER, "--redact", "--redact-salt", "abcd",
                       "--out-json", out_json])
        self.assertEqual(code, 0)
        with open(out_json) as fh:
            data = json.load(fh)
        raw = json.dumps(data["alerts"])
        self.assertNotIn("user_01ALICE", raw)
        for alert in data["alerts"]:
            self.assertTrue(alert["user"].startswith("u_"))

    def test_graceful_error_on_bad_input(self):
        d = tempfile.mkdtemp()
        bad = os.path.join(d, "bad.jsonl")
        with open(bad, "w") as fh:
            fh.write("this is not json\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["scan", "--events", bad, "--inventory", INV, "--vulns", VULNS])
        self.assertEqual(code, 65)  # InputFormatError exit code, no traceback
        self.assertIn("coverguard: error:", err.getvalue())

    def test_integrity_failure_is_clean(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["scan", "--events", EVENTS, "--inventory", INV, "--vulns", VULNS,
                         "--inventory-sha256", "0" * 64])
        self.assertEqual(code, 66)
        self.assertIn("integrity check failed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
