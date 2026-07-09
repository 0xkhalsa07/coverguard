import unittest

from _bootstrap import Component
from coverguard.models import normalize_ecosystem, parse_purl


class PurlTests(unittest.TestCase):
    def test_normalize_ecosystem(self):
        self.assertEqual(normalize_ecosystem("pypi"), "PyPI")
        self.assertEqual(normalize_ecosystem("PYTHON"), "PyPI")
        self.assertEqual(normalize_ecosystem("npm"), "npm")
        self.assertEqual(normalize_ecosystem("golang"), "Go")
        self.assertEqual(normalize_ecosystem("Weird"), "Weird")

    def test_parse_purl(self):
        eco, name, ver = parse_purl("pkg:npm/%40acme/github-mcp@1.2.0")
        self.assertEqual(eco, "npm")
        self.assertEqual(name, "@acme/github-mcp")
        self.assertEqual(ver, "1.2.0")

    def test_component_derives_from_purl(self):
        c = Component(name="requests", purl="pkg:pypi/requests@2.0.0")
        self.assertEqual(c.ecosystem, "PyPI")
        self.assertEqual(c.package, "requests")
        self.assertEqual(c.pinned_version, "2.0.0")
        self.assertTrue(c.has_coordinates)

    def test_explicit_fields_win_and_ecosystem_normalized(self):
        c = Component(name="x", ecosystem="pypi", package="x", pinned_version="1.0")
        self.assertEqual(c.ecosystem, "PyPI")


if __name__ == "__main__":
    unittest.main()
