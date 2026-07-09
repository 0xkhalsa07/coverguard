import os
import stat
import tempfile
import unittest

from coverguard import security
from coverguard.errors import InputTooLargeError, IntegrityError


class SecurityTests(unittest.TestCase):
    def test_redact_is_deterministic_and_prefixed(self):
        a = security.redact_user("user_01ALICE", "deadbeef")
        b = security.redact_user("user_01ALICE", "deadbeef")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("u_"))
        self.assertNotIn("ALICE", a)
        self.assertNotEqual(a, security.redact_user("user_01BOB", "deadbeef"))

    def test_safe_write_is_owner_only(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "report.json")
        security.safe_write(path, "sensitive")
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o600)

    def test_integrity_roundtrip(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "snap.json")
        security.safe_write(path, "hello")
        digest = security.sha256_file(path)
        self.assertEqual(security.verify_integrity(path, digest), digest)
        with self.assertRaises(IntegrityError):
            security.verify_integrity(path, "0" * 64)

    def test_size_guard(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "big.txt")
        security.safe_write(path, "x" * 1000)
        with self.assertRaises(InputTooLargeError):
            security.check_size(path, max_bytes=10)


if __name__ == "__main__":
    unittest.main()
