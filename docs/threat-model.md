# Threat model

This model uses STRIDE against an assume-breach, least-privilege baseline. It
covers coverguard itself, not the Cowork platform it analyses.

## Assets

- Input telemetry (events): may contain prompt text, user email, file paths, and
  tool parameters. Sensitive / personal data.
- Inventory and vuln snapshot: integrity-sensitive; a tampered snapshot silently
  defeats detection.
- Reports (text/JSON/HTML): derived, but carry user identifiers and matched paths.
- The detection outcome itself: a false "all clear" has security consequences.

## Trust boundaries

1. Untrusted input data crossing into the parser (events are attacker-influenced;
   a compromised connector or a malicious prompt can shape event content).
2. The local filesystem the tool reads inputs from and writes reports to.
3. The optional outbound connection to OSV.dev (`--online`, `refresh-vulns`).

Everything read through files or the network is data, never instructions.

## Data flow (trust view)

```
[untrusted events] ─(1)─► parser ─► rules ─► report ─(2)─► [report files]
[inventory/snapshot] ─(2)─► loader (integrity-checkable)
                                    └─(3)─► OSV.dev (constant URL only)
```

## STRIDE

### Spoofing
- Threat: a forged inventory or snapshot substituted for the real one.
- Mitigation: `--inventory-sha256` / `--vulns-sha256` verify SHA-256 with a
  constant-time compare before use; `refresh-vulns` emits a `.sha256` sidecar.
- Residual: trust is anchored on the expected hash the operator supplies; manage
  it like any pinned checksum.

### Tampering
- Threat: modified snapshot drops an advisory so R1 misses; modified events hide
  an invocation. Also on-path tampering of OSV responses.
- Mitigation: integrity gates on files; OSV fetched over HTTPS with default
  certificate validation; offline mode removes the network entirely.
- Residual: without integrity flags, file tampering is undetected. The docs push
  operators to pin hashes in CI.

### Repudiation
- Threat: no record of who ran a scan or against what.
- Mitigation: an audit log line records the OS user and the SHA-256 of each input
  at info level; `prompt.id` and `user.account_uuid` in alerts tie findings back
  to sources.
- Residual: the audit line is local; ship it to your log pipeline for durability.

### Information disclosure
- Threat: sensitive data leaking through reports, logs, tracebacks, or the HTML
  report (XSS if opened in a browser).
- Mitigation: HTML output is fully escaped (tested); reports are written 0600;
  `--redact` pseudonymises user identifiers with a keyed hash; prompt bodies are
  never emitted; R5 reports the matched pattern, not the full path; errors are
  clean one-liners with no traceback unless `--debug`.
- Residual: even redacted reports contain component names and matched patterns;
  treat them as sensitive and restrict access.

### Denial of service
- Threat: a huge or crafted events file exhausts memory or time.
- Mitigation: `check_size` rejects oversized inputs before reading; `--max-events`
  bounds record count; version and pattern matching are linear with no
  catastrophic backtracking; OSV calls have timeouts and degrade to empty.
- Residual: default ceiling is 256 MiB; tune `--max-bytes` for your fleet.

### Elevation of privilege
- Threat: the tool executing attacker-controlled input, or reaching an
  attacker-chosen network endpoint.
- Mitigation: no `eval`, `exec`, `pickle`, shell, or template execution; input is
  parsed as data via `json` only; the OSV URL is a module constant, never taken
  from input (no SSRF); no dynamic import of input-named modules.
- Residual: the tool runs with the invoking user's privileges; run it as a
  low-privilege principal with read-only access to inputs.

## Residual risk summary

coverguard is detective, not preventive. The inventory is load-bearing and must
be kept fresh. CVE feeds under-cover bespoke or internal MCP servers, which is why
R2 (unknown component) exists. Reports are sensitive artefacts. These are accepted
and documented, not silently ignored.
