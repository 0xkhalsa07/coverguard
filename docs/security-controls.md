# Security controls

This maps each control area to its implementation and the test that proves it.
It is deliberately honest about what is not applicable to a local CLI.

## Control matrix

| Control | Status | Implementation | Test |
|---------|--------|----------------|------|
| Authentication | N/A by design | Local CLI; no accounts or server. Inherits the OS user. | n/a |
| Authorization / access control | Enforced at output | Reports written owner-only (0600) via `safe_write`; no privilege escalation paths. | `test_security.test_safe_write_is_owner_only` |
| Cryptography | In use | HTTPS with default cert validation for OSV; SHA-256 integrity gates on inputs; keyed-hash (HMAC-SHA-256) redaction. | `test_security.test_integrity_roundtrip`, `test_redact_*` |
| Input validation / sanitization | Enforced | `json`-only parsing (no eval); typed shape checks; HTML output fully escaped. | `test_events.*`, `test_report.test_html_escapes_untrusted_values` |
| Logging / audit | Present | Structured logging; audit line with OS user and input SHA-256; no secrets or prompt bodies logged. | manual + `test_cli` (no PII with `--redact`) |
| Exception handling | Graceful | Typed `CoverguardError` with documented exit codes; no traceback unless `--debug`. | `test_cli.test_graceful_error_on_bad_input`, `test_integrity_failure_is_clean` |
| Monitoring | External by design | Exit codes (`--fail-on-alert`) and logs consumed by CI/cron; the tool has no self-service surface to monitor. | `test_cli.test_fail_on_alert_exit_code` |
| Resource management / DoS | Bounded | `check_size` and `--max-events` guards; context-managed files and sockets; timeouts on network. | `test_security.test_size_guard` |
| Supply chain | Minimal | Zero third-party runtime dependencies (stdlib only). | `pyproject.toml` (empty `dependencies`) |
| SAST / lint | Clean | `bandit` (config in `.bandit.yaml`) and `ruff` run in CI. | CI `security` job |

## Gaps that were closed

These were identified in review of the earlier prototype and fixed here:

1. Reports were world-readable. Now written 0600 with an explicit `chmod`
   fallback for filesystems that ignore create-mode.
2. No integrity check on inputs. Added `--inventory-sha256` / `--vulns-sha256`
   and a `.sha256` sidecar from `refresh-vulns`.
3. Unbounded input. Added size and count guards.
4. Tracebacks on bad input leaked internal paths. Added typed errors and a clean
   top-level handler.
5. User identifiers always present in output. Added `--redact`.
6. No audit trail. Added a structured audit log line.

## Deliberate non-goals

- No app-layer authentication or authorization: this is a single-user CLI, and
  those controls belong to the OS and to the environment it runs in.
- No encryption of reports at rest: rely on the host's disk encryption and file
  permissions, and prefer `--redact`. If you productionise this as a service, add
  authn/authz, TLS termination, rate limiting, and at-rest encryption first.

## Regulatory mapping (indicative)

- GDPR: reports and events can contain personal data. Article 32 (security of
  processing) is supported by 0600 writes and redaction; Article 5 (minimisation,
  storage limitation) by not emitting prompt bodies and by `.gitignore` excluding
  reports. A DPIA may apply where monitoring is systematic.
- PCI DSS: where in-scope data is reachable, the tool supports Requirement 10
  (audit logging and monitoring) via its audit line and alerts, and complements
  Requirement 6 (manage known vulnerabilities) via R1.

Confirm applicability with your Legal and Security functions.
