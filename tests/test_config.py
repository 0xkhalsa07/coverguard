import json
import os
import tempfile
import unittest

from _bootstrap import EXAMPLES
from coverguard.config import load_config
from coverguard.errors import InputFormatError


class ConfigTests(unittest.TestCase):
    def test_load_example(self):
        cfg = load_config(os.path.join(EXAMPLES, "config.json"))
        self.assertIn("sensitive_tools", cfg)
        self.assertEqual(cfg["min_app_version"], "1.1.4173")

    def test_none_is_empty(self):
        self.assertEqual(load_config(None), {})

    def test_unknown_key_rejected(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "c.json")
        with open(path, "w") as fh:
            json.dump({"bogus": 1}, fh)
        with self.assertRaises(InputFormatError):
            load_config(path)


if __name__ == "__main__":
    unittest.main()
