# Go-live checklist (GitHub settings)

The repository files are ready to publish. These are the one-time settings to
turn on in the GitHub web UI after the first push. None of them are code; they
are toggles that keep you the sole gatekeeper and harden the project.

## Branch protection (Settings, Branches, add rule for `main`)

- Require a pull request before merging.
- Require approval (1 review). With CODEOWNERS in place, that review is routed
  to you automatically.
- Require status checks to pass: select the CI "test" matrix and the "quality"
  job.
- Do not allow force pushes or deletions of `main`.

## Security features (Settings, Code security)

- Enable secret scanning and push protection (free on public repos).
- Enable Dependabot alerts and security updates. The `dependabot.yml` in the
  repo already schedules update PRs.
- Private vulnerability reporting: enable it so researchers can use the process
  in SECURITY.md.

## Repository metadata (main repo page)

- Description: CVE-aware coverage for Claude Cowork tool calls.
- Topics: security, opentelemetry, cve, mcp, detection, siem.

## Optional

- Enable Discussions if you want a place for questions.
- Create a few issue labels (for example: bug, enhancement, good first issue).
- Tag a release `v1.0.0` to trigger the release workflow, which builds the
  wheel and sdist, generates an SBOM, and records build provenance.

## Contributions

Anyone can fork and open a pull request, but nothing merges into your `main`
without your review and approval. See the "How outside changes work" note in
the project discussion or CONTRIBUTING.md.
