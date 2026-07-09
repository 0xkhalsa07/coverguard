# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-07-09

### Added

- Accurate semver and PEP 440 version comparison, including pre-release ordering
  and epochs.
- Package URL (purl) support and ecosystem-name normalization in the inventory.
- EPSS scores and CISA KEV flags on findings; a KEV match escalates to CRITICAL.
- JSON rule configuration (`--config`) for sensitive tools, patterns, minimum app
  version, and coverage bands.
- Suppressions allowlist (`--suppressions`) for accepted findings, with expiry.
- SARIF 2.1.0 output (`--out-sarif`) and a JSON audit log (`--audit-log`).
- Multiple `--vulns` snapshots can be merged in one scan.
- Published JSON report schema, coverage gate, mypy, a signed-release workflow
  with SBOM, CODEOWNERS, architecture diagram, and README visuals.
- Distribution: pipx install instructions and a hardened non-root container
  image (base-image digest pinning via Dependabot, documented locked-down run
  flags), plus a CI job that builds and Trivy-scans the image.

### Fixed

- The event parser now raises a typed error instead of crashing on a malformed
  JSON array (found by the new fuzz test).

## [1.0.0] - 2026-07-09

### Added

- Ingestion of Claude Cowork OpenTelemetry events (JSONL or JSON array), grounded
  in the documented event schema.
- Pinned component inventory as the source of truth for names and versions.
- CVE matching against an offline OSV-shaped snapshot, with an optional live
  OSV.dev path (`--online`) and a `refresh-vulns` command to build snapshots.
- Six detection rules (R1 known-vulnerable, R2 unknown component, R3 sensitive
  auto-approval, R4 endpoint below minimum version, R5 sensitive path, R6
  telemetry silence).
- Capability coverage report mapped to the four governance gaps, in text, JSON,
  and HTML.
- Security controls: input size and count guards, SHA-256 integrity checks on
  inputs, `--redact` pseudonymisation of user identifiers, restrictive (0600)
  report writes, structured logging with an audit line, and graceful error
  handling that hides tracebacks unless `--debug` is set.
- Test suite (unit, security, CLI), bandit SAST config, ruff lint config, CI,
  CodeQL, and Dependabot.
