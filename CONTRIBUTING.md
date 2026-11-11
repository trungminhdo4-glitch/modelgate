# Contributing to ModelGate

Thanks for helping improve a defensive security tool. Please read
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first, and note that contributions
must stay inside the defensive scope defined in [ETHICS.md](ETHICS.md).

## Where to start

* **Bug reports and feature ideas** — GitHub Issues (use the templates).
* **Security vulnerabilities** — [SECURITY.md](SECURITY.md), never a public
  issue.
* **Questions about acceptable scope** — open a discussion issue *before*
  writing code.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. The sign-off certifies that you have the
right to contribute the work under the licences in [NOTICE](NOTICE):

```console
$ git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match your Git identity (`git config user.name` /
`git config user.email`). Commits without a matching sign-off fail the blocking
`dco` CI job - see `ci/check-dco.mjs`.

**Decision (identity vs. DCO check):** the repository-local Git identity is
`trung-dev <trung-dev@users.noreply.github.com>` and the DCO check stays
configured against the *author email of each commit* rather than against a
hard-coded address. Reason: the identity already equals the DCO sign-off email,
so no re-identification was needed, and a per-commit comparison keeps the gate
correct for contributor commits while validating maintainers with the same
logic - one rule, no special case, and no permission model to drift.

If you have commits that are already unsigned:

```console
$ git rebase HEAD~n --exec 'git commit --amend --no-edit --reset-author -s'
```

(Only rewrite your own unpushed commits, and never rewrite someone else's.)

## Local quality gates (all blocking in CI)

Run these before every pull request:

```console
$ gofmt -l .                      # must print nothing
$ go vet ./...
$ go test ./... -count=1           # unit + acceptance, includes fuzz seed corpus
$ node --test ci/test-gates.mjs    # CI gate logic (17 tests)
$ node ci/check-keywords.mjs       # scope + secret gate on this tree
$ gitleaks dir . --redact          # no secrets
```

Coverage of the core packages must stay at or above **80 %**:

```console
$ go test ./internal/cli ./internal/finding ./internal/hf ./internal/pin \
         ./internal/report ./internal/sbom ./internal/scan \
         -coverprofile coverage.out -covermode=atomic
$ go tool cover -func coverage.out | tail -n 1
```

The `internal/testserver` package is deliberately outside that list: it is a
GET-only fixture endpoint that exists purely as test infrastructure, not as
product code, so it carries no coverage requirement of its own. Its absence
from the seven core packages is intentional and is not a coverage gap.

Workspace-level check (when working in the agent workspace):

```console
$ node school/quality-loop/quality-loop.mjs run builtin:go --cwd <repo>
```

## Pull request rules

1. **One task per PR.** Unrelated changes go in a separate PR.
2. **Tests first.** A behaviour change needs a test that fails before your
   fix and passes after (TDD). Fuzz findings must be added to the regression
   corpus under `testdata/fuzz/` together with the fix.
3. **Stay defensive.** No exploit code, payloads, phishing material, C2
   tooling, or code-execution paths. `ci/check-keywords.mjs` blocks the build
   if this is violated, and reviewers will reject it anyway.
4. **Read-only by construction.** Any new network call must be GET-only; any
   new filesystem write must be behind an explicit opt-in flag and documented
   in the README.
5. **Rule contributions** must follow the catalogue format: ID `MG-<CAT>-<NNN>`
   (see `modelgate rules`), severity, title, remediation, reference, plus a
   test in `internal/scan` covering both a matching and a non-matching
   sample. Detection patterns live in `internal/scan/rules.go` and are
   licensed CC BY 4.0 (see [NOTICE](NOTICE)).
6. **Docs and changelog.** User-visible changes update `README.md` and add a
   bullet under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
7. **No secrets, no personal data.** Never commit credentials, tokens, or
   real user data — including in fixtures (use synthetic values only).

## Commit style

* Imperative subject, ≤ 72 characters, prefixed with the area when useful
  (`scan:`, `report:`, `cli:`, `ci:`, `docs:`).
* Body explains *why*, not *what* (the diff shows what).
* Always `-s` (DCO).

## Release process

Maintainers follow [RELEASING.md](RELEASING.md): SemVer, changelog, full gate
run, SBOM, and signed artifacts. Contributors do not need to worry about
signing — that happens in CI at release time.
