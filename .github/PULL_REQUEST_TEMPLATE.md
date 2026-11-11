## Summary

<!-- What does this change, and why? One or two sentences. -->

## Type of change

- [ ] Bug fix
- [ ] New detection rule / analysis capability
- [ ] Refactor (no behaviour change)
- [ ] Documentation / governance
- [ ] CI

## Checklist

- [ ] Tests cover the change; any behaviour change has a test that fails without this patch
- [ ] `gofmt -l .` is empty, `go vet ./...` passes, `go test ./... -count=1` passes
- [ ] Core-package coverage stays ≥ 80 % (`go test ... -coverprofile` + `go tool cover -func`)
- [ ] `node --test ci/test-gates.mjs` and `node ci/check-keywords.mjs` pass locally
- [ ] No secrets, credentials, or personal data in code, fixtures, or docs
- [ ] Change stays **defensive only**: no exploit code, payloads, phishing material, C2 tooling, or code execution
- [ ] Read-only by construction preserved: outbound requests are GET-only, filesystem writes only behind `--out` / `--sbom`
- [ ] `README.md` updated for user-visible changes; `[Unreleased]` entry added to `CHANGELOG.md`
- [ ] Rule contributions follow `MG-<CAT>-<NNN>` with remediation, reference, and match/non-match tests

## DCO

- [ ] All commits are signed off (`git commit -s`) and the `Signed-off-by`
      line matches my Git identity — I certify the right to contribute this
      work under the licences in `NOTICE` (Apache-2.0 code, CC BY 4.0 rules
      and docs).
