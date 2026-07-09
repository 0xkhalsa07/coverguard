"""Security primitives: size guards, integrity checks, redaction, safe writes.

These are the controls that harden coverguard against the gaps identified in the
threat model: unbounded input (DoS), tampered inputs (integrity), sensitive data
at rest (restrictive file mode), and PII in output (redaction).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from .errors import InputTooLargeError, IntegrityError

# Default input ceiling. Bounds memory use when ingesting fleet-wide telemetry.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024  # 256 MiB
_CHUNK = 65536


def check_size(path: str, max_bytes: int = DEFAULT_MAX_BYTES) -> int:
    """Reject oversized inputs before reading them into memory."""
    size = os.path.getsize(path)
    if size > max_bytes:
        raise InputTooLargeError(
            f"{path} is {size} bytes, exceeds limit {max_bytes}; raise --max-bytes to override")
    return size


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_integrity(path: str, expected_hex: str) -> str:
    """Constant-time compare of a file's SHA-256 against an expected value."""
    actual = sha256_file(path)
    if not hmac.compare_digest(actual.lower(), expected_hex.strip().lower()):
        raise IntegrityError(
            f"integrity check failed for {path}: expected {expected_hex.strip()}, got {actual}")
    return actual


def new_salt() -> str:
    """Fresh per-run salt for pseudonymising identifiers."""
    return secrets.token_hex(16)


def redact_user(value, salt: str) -> str:
    """Pseudonymise a user identifier with a keyed hash (HMAC-SHA-256).

    Deterministic within a run so events stay correlatable, but not reversible
    without the salt. Prompt bodies are never emitted in the first place.
    """
    if not value:
        return value
    key = bytes.fromhex(salt) if _is_hex(salt) else salt.encode("utf-8")
    digest = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return "u_" + digest[:12]


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def safe_write(path: str, data: str, mode: int = 0o600) -> None:
    """Write text with restrictive permissions, independent of the umask.

    Reports can contain user identifiers and matched paths, so their default
    mode is owner-read/write only (0600).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    # If the file pre-existed with looser perms, O_CREAT will not tighten it.
    try:
        os.chmod(path, mode)
    except OSError:
        # Some filesystems (network mounts, FUSE) reject chmod; best effort.
        pass
