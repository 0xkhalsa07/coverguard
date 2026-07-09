import unittest

from _bootstrap import tool_event
from coverguard.coverage import compute_coverage
from coverguard.inventory import Inventory
from coverguard.report import render_html, render_text
from coverguard.rules import Detector

XSS = "<script>alert(1)</script>"


class ReportSecurityTests(unittest.TestCase):
    def _render(self):
        events = [tool_event(component=XSS, user=XSS)]
        inv = Inventory([])
        det = Detector(inv, {}, roster=None)
        results = det.run(events)
        cov = compute_coverage(events, inv, {}, results, None)
        cov["provenance"] = {"tool_version": "test", "redacted": False}
        return render_html(cov, results), render_text(cov, results)

    def test_html_escapes_untrusted_values(self):
        html_out, _ = self._render()
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)

    def test_reports_render(self):
        html_out, text_out = self._render()
        self.assertIn("<html", html_out)
        self.assertIn("coverguard scan report", text_out)


if __name__ == "__main__":
    unittest.main()
