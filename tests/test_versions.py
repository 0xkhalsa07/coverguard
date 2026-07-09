import unittest

from _bootstrap import versions as v


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(v.parse_version("v1.2.3-rc1"), (1, 2, 3))
        self.assertEqual(v.parse_version(None), (0,))

    def test_cmp(self):
        self.assertEqual(v.cmp_version("1.2.0", "1.2.5"), -1)
        self.assertEqual(v.cmp_version("1.10.0", "1.9.9"), 1)
        self.assertEqual(v.cmp_version("2.0", "2.0.0"), 0)

    def test_in_range(self):
        self.assertTrue(v.version_in_range("1.2.0", "0", "1.2.5"))
        self.assertFalse(v.version_in_range("1.2.5", "0", "1.2.5"))
        self.assertFalse(v.version_in_range("3.0.1", "0", "2.9.0"))


if __name__ == "__main__":
    unittest.main()
