import unittest

from _bootstrap import versions as v


class SemverTests(unittest.TestCase):
    def test_prerelease_sorts_below_final(self):
        self.assertEqual(v.cmp_version("1.0.0-rc1", "1.0.0"), -1)
        self.assertEqual(v.cmp_version("1.0.0a1", "1.0.0"), -1)
        self.assertEqual(v.cmp_version("1.0.0-rc1", "1.0.0-rc2"), -1)
        self.assertEqual(v.cmp_version("1.0.0", "1.0.0"), 0)

    def test_epoch(self):
        self.assertEqual(v.cmp_version("1!1.0", "2.0"), 1)

    def test_build_and_local_metadata_ignored(self):
        self.assertEqual(v.cmp_version("1.2.3+build.5", "1.2.3"), 0)

    def test_post_and_dev(self):
        self.assertEqual(v.cmp_version("1.0.0.post1", "1.0.0"), 1)
        self.assertEqual(v.cmp_version("1.0.0.dev1", "1.0.0"), -1)

    def test_range_semantics(self):
        self.assertTrue(v.version_in_range("1.2.0", "0", "1.2.5"))
        self.assertFalse(v.version_in_range("1.2.5", "0", "1.2.5"))
        self.assertFalse(v.version_in_range("1.0.0", "0", "1.0.0-rc1"))


if __name__ == "__main__":
    unittest.main()
