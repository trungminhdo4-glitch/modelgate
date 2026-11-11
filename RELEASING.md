# Releasing ModelGate

Releases are produced by maintainers only. Every step below is mechanical; if
any step fails, stop and do not tag.

## Versioning

* **Semantic Versioning.** `MAJOR.MINOR.PATCH`.
* The following are public contract and may only change with a MAJOR bump:
  exit codes (`0`/`1`/`2`), CLI flags and their defaults, rule IDs
  (`MG-<CAT>-<NNN>`), the JSON `schema_version` (`1.0`), and the SARIF/Sigma
  output shapes.
* New rules and new flags are MINOR. Fixes that change no contract are PATCH.
* Pre-releases use a suffix (`v0.2.0-rc.1`) and are never the default
  download.

## Support window

* **Support window (best effort).** Each MAJOR line is intended to receive
  security fixes for 6 months after the next MAJOR release, then declared
  end-of-life (EOL) in the README and CHANGELOG. This is a best-effort
  intention of a non-commercial project, not a binding commitment or SLA;
  a shorter window may be announced in the CHANGELOG when capacity requires
  it.
* EOL versions receive no backports, including for disclosed vulnerabilities.

## Repository bootstrap (fresh clone)

A fresh clone becomes green with one command:

```console
$ node ci/bootstrap.mjs            # go mod download + tool preflight + full gate run
$ node ci/bootstrap.mjs --offline  # re-run without module download (air-gapped)
```

The script executes a fixed step plan (`go mod download` unless `--offline`,
tool preflight, `gofmt -l`, `go vet`, `go test ./... -count=1`, gate unit
tests, keyword gate). A missing required tool (`go`, `node`, `gitleaks`,
`actionlint`, `yamllint`) fails closed with exit 2 and a pointer to the
machine tool registry (`school/tool-registry`); a failing step exits 1.
Step semantics are pinned by `ci/test-bootstrap.mjs`.

## Reproducible repository initialization

The repository layout was created with this command set; re-creating it
(mirror, fork recovery) follows the same order:

```console
$ git init -b main
$ git config user.name  "trung-dev"
$ git config user.email "trung-dev@users.noreply.github.com"  # == DCO email
$ # layout, in commit order:
$ #   cmd/<tool>/            entry point (wiring only)
$ #   internal/<7 pkgs>/     core packages + internal/testserver fixture
$ #   ci/                    test-gates, check-keywords, check-dco, sbom, bootstrap
$ #   .github/workflows/     ci, codeql, dependency-review, gitleaks, sbom, scorecard
$ #   testdata/              inert fixtures
$ #   governance docs        README, SECURITY, ETHICS, CONTRIBUTING (+ DCO),
$ #                          CODE_OF_CONDUCT, NOTICE, TRANSPARENCY, APPEAL,
$ #                          CHANGELOG, RELEASING, LICENSE, LICENSE-CC-BY-4.0.txt
$ git add -A && git commit -s -m "initial import"
$ node ci/bootstrap.mjs && git status --short   # must end green and clean
```

## Release checklist

1. **Green gates on the release commit**
   ```console
   $ gofmt -l . && go vet ./... && go test ./... -count=1
   $ node --test ci/test-gates.mjs && node ci/check-keywords.mjs
   $ gitleaks dir . --redact
   ```
   Coverage of the core packages ≥ 80 % (see CONTRIBUTING.md).
2. **Changelog** — move the `[Unreleased]` entries into a new versioned
   section with today's date; add the comparison links.
3. **README** — version references and support table still accurate.
4. **Tag** — annotated and signed:
   ```console
   $ git tag -s v0.1.0 -m "ModelGate v0.1.0"
   ```
5. **Build artifacts** — `GOOS`/`GOARCH` matrix builds of `cmd/modelgate`,
   checksummed:
   ```console
   $ sha256sum modelgate-* > checksums.txt
   ```
6. **SBOM** — generate the CycloneDX SBOM of the release and attach it:
   ```console
   $ node ci/sbom.mjs --out sbom.cdx.json --tool-version 0.1.0
   ```
7. **Sign** — sign the checksums and SBOM with cosign (keyless/OIDC):
   ```console
   $ cosign sign-blob --yes --bundle release.bundle checksums.txt
   $ cosign sign-blob --yes --bundle release.bundle sbom.cdx.json
   ```
8. **Publish** — GitHub Release with the artifacts, `checksums.txt`,
   `sbom.cdx.json`, `release.bundle`, and the CHANGELOG section as release
   notes.
9. **Post-release** — open the next `[Unreleased]` section; announce
   policy-relevant changes (see TRANSPARENCY.md §5).

## Hotfix releases

Security fixes skip the MINOR cycle: branch from the affected MAJOR line,
ship as PATCH, and reference the advisory in the CHANGELOG entry. The
advisory is published together with the release.

## Yanking

A broken release may be marked *yanked* on GitHub (never deleted): the tag
stays, the release notes are prefixed with the reason, and users are pointed
at the replacement version. Deleting tags or releases requires explicit owner
approval.
