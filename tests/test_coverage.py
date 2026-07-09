import json
import os
import unittest

from _bootstrap import EXAMPLES
from coverguard.coverage import compute_coverage
from coverguard.ingest import load_events
from coverguard.inventory import Inventory
from coverguard.rules import Detector
from coverguard.vulndb import VulnDB


class CoverageEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.events = load_events(os.path.join(EXAMPLES, "events.jsonl"))
        self.inv = Inventory.load(os.path.join(EXAMPLES, "inventory.json"))
        db = VulnDB.load(os.path.join(EXAMPLES, "vuln_snapshot.json"))
        self.vuln_map = {c.name: f for c in self.inv.all() if (f := db.match(c))}
        with open(os.path.join(EXAMPLES, "roster.json")) as fh:
            self.roster = json.load(fh)["users"]

    def test_matrix_and_alerts(self):
        det = Detector(self.inv, self.vuln_map, roster=self.roster)
        results = det.run(self.events)
        cov = compute_coverage(self.events, self.inv, self.vuln_map, results, self.roster)

        self.assertTrue(cov["pipeline_healthy"])
        self.assertEqual(cov["counts"]["distinct_mcp_components"], 3)
        self.assertEqual(cov["inventory"]["match_rate_pct"], 66.7)
        self.assertEqual(cov["inventory"]["unknown_observed"], ["sketchy-mcp"])
        self.assertEqual(cov["cve"]["vulnerable_components"], ["acme-github-mcp"])

        counts = {r.rule: len(r.alerts) for r in results}
        self.assertEqual(counts, {"R1": 1, "R2": 1, "R3": 1, "R4": 1, "R5": 1, "R6": 1})


if __name__ == "__main__":
    unittest.main()
