import json
import unittest

import _bootstrap  # noqa: F401
from coverguard.models import Alert, RuleResult
from coverguard.report_sarif import render_sarif


class SarifTests(unittest.TestCase):
    def test_valid_shape_and_level_mapping(self):
        results = [RuleResult("R1", "Known-vulnerable component invoked", True,
                              [Alert("R1", "CRITICAL", "c", "t", "u", "s", "p", "detail")])]
        doc = json.loads(render_sarif({}, results))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "coverguard")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "R1")
        self.assertEqual(run["results"][0]["ruleId"], "R1")
        self.assertEqual(run["results"][0]["level"], "error")

    def test_no_alerts_no_results(self):
        results = [RuleResult("R6", "silence", False, [])]
        doc = json.loads(render_sarif({}, results))
        self.assertEqual(doc["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
