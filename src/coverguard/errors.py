"""Typed, user-facing errors.

Raising a CoverguardError produces a clean one-line message and a documented
exit code, never a stack trace (unless --debug is set). This keeps internal
paths and implementation detail out of normal error output.
"""

from __future__ import annotations


class CoverguardError(Exception):
    """Base class for expected, user-facing errors."""

    exit_code = 2


class InputFormatError(CoverguardError):
    """Input file is malformed or not the expected shape."""

    exit_code = 65  # EX_DATAERR


class InputTooLargeError(CoverguardError):
    """Input exceeds the configured size or count limit (DoS guard)."""

    exit_code = 65


class IntegrityError(CoverguardError):
    """A file failed its SHA-256 integrity check."""

    exit_code = 66
