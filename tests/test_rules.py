import unittest

from _bootstrap import Component, Finding, tool_event
from coverguard.inventory import Inventory
from coverguard.rules import Detector


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.inv = Inventory([
            Component(name="acme-github-mcp", ecosystem="npm",
                      package="@acme/github-mcp", pinned_version="1.2.0"),
            Component(name="files-mcp", ecosystem="npm",
                      package="@acme/files-mcp", pinned_version="3.0.1"),
        ])
        self.vuln_map = {"acme-github-mcp": [Finding("CVE-2026-31337", "HIGH", "1.2.5", "x")]}

    def _det(self, roster=None):
        return Detector(self.inv, self.vuln_map, roster=roster)

    def _alerts(self, results, rule):
        return [a for r in results if r.rule == rule for a in r.alerts]

    def test_r1_known_vulnerable(self):
        res = self._det().run([tool_event(component="acme-github-mcp")])
        self.assertEqual(len(self._alerts(res, "R1")), 1)

    def test_r1_clean_component_no_alert(self):
        res = self._det().run([tool_event(component="files-mcp")])
        self.assertEqual(len(self._alerts(res, "R1")), 0)

    def test_r2_unknown_component(self):
        res = self._det().run([tool_event(component="sketchy-mcp")])
        self.assertEqual(len(self._alerts(res, "R2")), 1)

    def test_r2_approved_not_flagged(self):
        res = self._det().run([tool_event(component="files-mcp")])
        self.assertEqual(len(self._alerts(res, "R2")), 0)

    def test_r3_auto_approved_sensitive(self):
        res = self._det().run([tool_event(tool_name="Bash", decision_source="config", mcp=False)])
        self.assertEqual(len(self._alerts(res, "R3")), 1)

    def test_r3_human_not_flagged(self):
        res = self._det().run([tool_event(tool_name="Bash", decision_source="user_temporary", mcp=False)])
        self.assertEqual(len(self._alerts(res, "R3")), 0)

    def test_r4_old_version(self):
        res = self._det().run([tool_event(version="1.1.4000")])
        self.assertEqual(len(self._alerts(res, "R4")), 1)

    def test_r4_current_ok(self):
        res = self._det().run([tool_event(version="1.1.4200")])
        self.assertEqual(len(self._alerts(res, "R4")), 0)

    def test_r5_sensitive_path(self):
        res = self._det().run([tool_event(tool_name="Read", mcp=False,
                                          tool_input='{"file_path":"/Users/a/.ssh/id_rsa"}')])
        self.assertEqual(len(self._alerts(res, "R5")), 1)

    def test_r6_needs_roster(self):
        res = self._det(roster=None).run([tool_event(component="files-mcp", user="user_01ALICE")])
        r6 = [r for r in res if r.rule == "R6"][0]
        self.assertFalse(r6.evaluated)

    def test_r6_flags_silent(self):
        res = self._det(roster=["user_01ALICE", "user_01SILENT"]).run(
            [tool_event(component="files-mcp", user="user_01ALICE")])
        alerts = self._alerts(res, "R6")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].user, "user_01SILENT")


if __name__ == "__main__":
    unittest.main()
