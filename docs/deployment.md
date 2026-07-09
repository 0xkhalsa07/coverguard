# Deployment

coverguard runs anywhere Python 3.8+ exists, with no third-party dependencies.
Below are the common ways to operate it.

## Prerequisite: telemetry must be flowing

coverguard analyses exported Cowork OTel events. Before it is useful, an
administrator must configure Cowork's OTLP export (Admin settings > Cowork) and,
if egress is restricted, allowlist the collector domain. If nothing is exported,
coverguard will correctly report the telemetry gap rather than a false all-clear.

## One-off scan

```bash
coverguard scan \
  --events export.jsonl \
  --inventory inventory.json \
  --vulns vuln_snapshot.json \
  --roster roster.json \
  --redact \
  --out-json report.json --out-html report.html
```

## Scheduled job (cron)

Run on a cadence against a rolling export, failing on new high-severity findings:

```bash
coverguard scan --events "$EXPORT" --inventory "$INV" --vulns "$SNAP" \
  --inventory-sha256 "$INV_SHA" --vulns-sha256 "$SNAP_SHA" \
  --redact --fail-on-alert || notify-security "coverguard: HIGH finding"
```

Refresh the offline snapshot on its own schedule:

```bash
coverguard refresh-vulns --inventory inventory.json --out vuln_snapshot.json
# commit vuln_snapshot.json.sha256, pass it as --vulns-sha256 on scans
```

## CI gate

Add a step that runs `coverguard scan ... --fail-on-alert`. A nonzero exit blocks
the pipeline when a known-vulnerable or unknown component was invoked.

## Air-gapped

Use the default offline mode with a snapshot built elsewhere and transferred with
its `.sha256`. Never pass `--online` in an air-gapped context. Integrity-gate the
snapshot with `--vulns-sha256`.

## SIEM integration

`--out-json` emits coverage plus every alert. Ship it to your SIEM as the
detection feed, and correlate on `prompt.id` and `user.account_uuid` to
reconstruct action chains. coverguard complements the raw OTel stream: the stream
is the evidence, coverguard is the judgement over it.

## Handling sensitive output

Reports can contain user identifiers and matched paths. Recommended posture:

- Always pass `--redact` unless you have a specific need for raw identifiers.
- Keep reports on encrypted storage with restricted access (they are written
  0600 by default).
- Set a retention policy; do not archive reports indefinitely.
- Never commit real reports to a repository (`.gitignore` already excludes them).

These practices support GDPR Article 32 and Article 5; see
[security-controls.md](security-controls.md).
