# Security Policy

## Supported versions

The latest released minor version receives security fixes. Pre-1.0 and older
minors are best effort.

| Version | Supported |
|---------|-----------|
| 1.0.x   | yes       |

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public issue
for a security report.

- Preferred: open a GitHub private security advisory (Security tab, "Report a
  vulnerability") so the fix can be coordinated.
- If you cannot use the advisory flow, open a public issue asking a maintainer
  to get in touch, without including any vulnerability details.

Please include a description, reproduction steps, affected version, and impact.
We aim to acknowledge within 3 business days and to agree a remediation timeline
within 10 business days. We support coordinated disclosure and will credit
reporters who wish to be named.

## Scope and posture

coverguard is a local, dependency-free analysis CLI. It:

- runs offline by default; the only outbound connection is to a constant OSV.dev
  URL when `--online` or `refresh-vulns` is used (never a URL taken from input),
- reads events, inventory, vuln snapshot, and roster files you provide,
- writes reports (text/JSON/HTML) that can contain user identifiers and matched
  paths.

Because its inputs and outputs can contain personal data, treat scan output as
sensitive: reports are written owner-only (0600), `--redact` pseudonymises user
identifiers, and inputs can be integrity-gated with SHA-256. See
[docs/security-controls.md](docs/security-controls.md) and
[docs/threat-model.md](docs/threat-model.md) for the full control mapping and the
STRIDE analysis.

## Known non-goals

- It is a detective control, not a preventive one.
- It does not authenticate users or encrypt reports at rest; those belong to the
  environment it runs in. Do not expose it as a network service without adding
  those controls.
