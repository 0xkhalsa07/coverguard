import unittest

import _bootstrap  # noqa: F401  (adds src to sys.path)
from coverguard import enrich
from coverguard.models import Finding


class EnrichTests(unittest.TestCase):
    def test_kev_ids_from_catalog(self):
        ids = enrich._kev_ids({"vulnerabilities": [{"cveID": "CVE-2026-31337"}]})
        self.assertEqual(ids, {"CVE-2026-31337"})

    def test_all_cve_ids_filters_non_cve(self):
        vm = {"c": [Finding("CVE-1", "HIGH", None, ""), Finding("GHSA-x", "HIGH", None, "")]}
        self.assertEqual(enrich.all_cve_ids(vm), {"CVE-1"})

    def test_annotate_sets_kev_and_epss(self):
        vm = {"c": [Finding("CVE-2026-31337", "HIGH", "1.2.5", "x")]}
        enrich.annotate(vm, {"CVE-2026-31337"}, {"CVE-2026-31337": 0.97})
        f = vm["c"][0]
        self.assertTrue(f.kev)
        self.assertEqual(f.epss, 0.97)

    def test_fetch_epss_parses_mocked_response(self):
        original = enrich._get_json
        enrich._get_json = lambda url: {"data": [{"cve": "CVE-2026-31337", "epss": "0.42"}]}
        try:
            scores = enrich.fetch_epss(["CVE-2026-31337"])
        finally:
            enrich._get_json = original
        self.assertEqual(scores["CVE-2026-31337"], 0.42)

    def test_fetch_epss_network_failure_is_empty(self):
        original = enrich._get_json
        enrich._get_json = lambda url: None
        try:
            self.assertEqual(enrich.fetch_epss(["CVE-1"]), {})
        finally:
            enrich._get_json = original


if __name__ == "__main__":
    unittest.main()
