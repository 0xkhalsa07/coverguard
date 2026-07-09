import os
import random
import string
import tempfile
import unittest

import _bootstrap  # noqa: F401
from coverguard.errors import CoverguardError
from coverguard.ingest import load_events


class IngestFuzzTests(unittest.TestCase):
    """The parser ingests untrusted telemetry. It must never crash with an
    unexpected exception: it either parses, or raises a typed CoverguardError.
    """

    def test_random_garbage_never_crashes_uncaught(self):
        rnd = random.Random(20260709)
        d = tempfile.mkdtemp()
        for i in range(250):
            path = os.path.join(d, f"f{i}.jsonl")
            blob = "".join(rnd.choice(string.printable) for _ in range(rnd.randint(0, 400)))
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(blob)
            try:
                load_events(path)
            except CoverguardError:
                pass  # acceptable, this is the typed failure path


if __name__ == "__main__":
    unittest.main()
