"""Version parsing and comparison for common semver and PEP 440 forms.

Zero dependencies. It handles the cases that matter for CVE range matching:
dotted-numeric release segments, an optional PEP 440 epoch ("N!"), and
pre-release markers (alpha/beta/rc and semver "-rc.1"), which sort BELOW the
corresponding final release. Build and local metadata ("+...") is ignored.

This is deliberately pragmatic, not a full PEP 440 or semver implementation.
Exotic schemes (calendar versions, distro revisions, unusual suffixes) may need
a dedicated comparator; this limitation is documented in the README.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Tuple

_RELEASE = re.compile(r"(\d+(?:\.\d+)*)(.*)")
_PRE_RANK = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "pre": 2, "preview": 2, "rc": 2, "c": 2}


def _split_epoch(s: str) -> Tuple[int, str]:
    if "!" in s:
        head, rest = s.split("!", 1)
        return (int(head) if head.isdigit() else 0), rest
    return 0, s


def _pre_key(suffix: str) -> Tuple[int, ...]:
    """Category-first key so cross-category comparisons decide on element 0.

    -1 = dev (lowest), 0 or 1 = pre-release groups, 2 = final, 3 = post-release.
    """
    suffix = suffix.strip(".-_")
    if suffix == "":
        return (2,)  # final release
    pre = re.match(r"(alpha|beta|preview|pre|rc|a|b|c)\.?(\d*)", suffix)
    if pre:
        return (0, _PRE_RANK.get(pre.group(1), 1), int(pre.group(2) or 0))
    post = re.match(r"\.?post\.?(\d*)", suffix)
    if post:
        return (3, int(post.group(1) or 0))
    dev = re.match(r"\.?dev\.?(\d*)", suffix)
    if dev:
        return (-1, int(dev.group(1) or 0))
    # Unknown suffix: treat as a low-rank pre-release so it sorts below final.
    return (0, 1, 0)


def _parse(v: Any) -> Tuple[int, Tuple[int, ...], Tuple[int, ...]]:
    s = str(v).strip().lower()
    if s.startswith("v"):
        s = s[1:]
    s = s.split("+", 1)[0]  # drop build / local metadata
    epoch, s = _split_epoch(s)
    m = _RELEASE.match(s)
    if not m:
        return (epoch, (0,), (2,))
    release = tuple(int(x) for x in m.group(1).split("."))
    return (epoch, release, _pre_key(m.group(2)))


def parse_version(v: Any) -> Tuple[int, ...]:
    """Backwards-compatible helper: the numeric release tuple only."""
    return _parse(v)[1]


def cmp_version(a: Any, b: Any) -> int:
    ea, ra, pa = _parse(a)
    eb, rb, pb = _parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    n = max(len(ra), len(rb))
    ra = ra + (0,) * (n - len(ra))
    rb = rb + (0,) * (n - len(rb))
    if ra != rb:
        return -1 if ra < rb else 1
    if pa != pb:
        return -1 if pa < pb else 1
    return 0


def version_in_range(version: Any, introduced: Optional[str], fixed: Optional[str]) -> bool:
    """OSV range semantics: introduced <= version < fixed."""
    if introduced not in (None, "0") and cmp_version(version, introduced) < 0:
        return False
    if fixed is not None and cmp_version(version, fixed) >= 0:
        return False
    return True
