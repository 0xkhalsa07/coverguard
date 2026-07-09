import unittest

import _bootstrap  # noqa: F401
from coverguard import suppress
from coverguard.models import Alert, RuleResult


def _alert(rule="R2", component="sketchy-mcp", tool="fetch_url"):
    return Alert(rule=rule, severity="HIGH", component=component, tool_name=tool,
                 user="u", session_id=None, prompt_id=None, detail="d")


class SuppressTests(unittest.TestCase):
    def test_match_by_rule_and_component(self):
        self.assertTrue(suppress.is_suppressed(_alert(), [{"rule": "R2", "component": "sketchy-mcp"}]))

    def test_no_criteria_never_matches(self):
        self.assertFalse(suppress.is_suppressed(_alert(), [{"reason": "note only"}]))

    def test_expired_does_not_match(self):
        self.assertFalse(suppress.is_suppressed(_alert(), [{"rule": "R2", "expires": "2000-01-01"}]))

    def test_apply_filters_and_counts(self):
        results = [RuleResult("R2", "t", True, [_alert(), _alert(component="other")])]
        out, n = suppress.apply_suppressions(results, [{"rule": "R2", "component": "sketchy-mcp"}])
        self.assertEqual(n, 1)
        self.assertEqual(len(out[0].alerts), 1)
        self.assertEqual(out[0].alerts[0].component, "other")


if __name__ == "__main__":
    unittest.main()
