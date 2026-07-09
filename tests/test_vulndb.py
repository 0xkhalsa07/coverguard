import os
import unittest

from _bootstrap import EXAMPLES, Component
from coverguard.vulndb import VulnDB


class VulnMatchTests(unittest.TestCase):
    def setUp(self):
        self.db = VulnDB.load(os.path.join(EXAMPLES, "vuln_snapshot.json"))

    def test_vulnerable_pinned_version(self):
        comp = Component(name="acme-github-mcp", ecosystem="npm",
                         package="@acme/github-mcp", pinned_version="1.2.0")
        findings = self.db.match(comp)
        self.assertEqual([f.id for f in findings], ["CVE-2026-31337"])
        self.assertEqual(findings[0].fixed_version, "1.2.5")

    def test_patched_version_clean(self):
        comp = Component(name="files-mcp", ecosystem="npm",
                         package="@acme/files-mcp", pinned_version="3.0.1")
        self.assertEqual(self.db.match(comp), [])

    def test_no_coordinates_no_match(self):
        self.assertEqual(self.db.match(Component(name="x")), [])


if __name__ == "__main__":
    unittest.main()
