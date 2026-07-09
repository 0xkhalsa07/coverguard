# Contributing to coverguard

Thanks for your interest in improving coverguard. This project values small,
well-tested, security-conscious changes.

## Development setup

```bash
git clone https://github.com/0xkhalsa07/coverguard
cd coverguard
make dev        # editable install with ruff + bandit
make check      # ruff + bandit + tests, all must pass
```

No third-party runtime dependencies are allowed in `src/`. Keeping the tool
stdlib-only is a deliberate supply-chain control. Dev/test tooling belongs in the
`dev` optional-dependencies group.

## Standards

- **Tests.** Every behavioural change needs a test. Security-relevant behaviour
  (escaping, redaction, integrity, limits, error handling) must be covered.
- **Lint and SAST.** `ruff` and `bandit` must pass. If you must suppress a
  finding, scope it as narrowly as possible and justify it in a comment.
- **Style.** Clear names, docstrings on modules and non-trivial functions, and no
  dead code. Line length 110.
- **Security first.** New inputs must be size-bounded and validated. New outputs
  must not widen what sensitive data is written or logged. New network calls must
  use constant, non-input-derived URLs.

## Pull requests

1. Branch from `main`.
2. Keep the change focused; one concern per PR.
3. Run `make check` and update `CHANGELOG.md`.
4. Sign off your commits (`git commit -s`) to certify the
   [Developer Certificate of Origin](https://developercertificate.org/).
5. Fill in the PR template, including the security checklist.

## Reporting security issues

Do not use public issues or PRs for vulnerabilities. Follow
[SECURITY.md](SECURITY.md).
