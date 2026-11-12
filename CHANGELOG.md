# Changelog

All notable changes to ModelGate are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release tags are `vMAJOR.MINOR.PATCH`. See [RELEASING.md](RELEASING.md) for the
signing and support policy.

## [Unreleased]

### Added

* `ci/bootstrap.mjs` - reproducible fresh-clone bootstrap: tool preflight,
  module download, format/vet/test, gate tests and keyword gate in one
  pinned step plan; `--offline` skips the module download. Missing tools
  fail closed with exit 2 in every mode, covered by `ci/test-bootstrap.mjs`.

### Changed

* Support window (README, RELEASING) is now explicitly **best effort** - an
  intention of a non-commercial project, not a binding commitment or SLA.
* Repository initialization and bootstrap are documented as a command set
  in RELEASING.md; the DCO identity decision is documented in
  CONTRIBUTING.md, and why `internal/testserver` sits outside the coverage
  gate is documented in CONTRIBUTING.md and the README.
* yamllint runs against a committed profile (`.yamllint.yml`) instead of
  ad-hoc line wrapping.

### Fixed

* Gitleaks workflow: `go install` used `github.com/gitleaks/gitleaks/v8`,
  which does not match the declared module path
  (`github.com/zricethezav/gitleaks/v8`); the install also now publishes
  `$(go env GOPATH)/bin` for the following step.
* Scorecard workflow: `ossf/scorecard-action@v2` no longer exists as a tag;
  pinned to the released `v2.5.0`.
* Bootstrap executed `go mod download` before its own tool preflight, so a
  missing `go` exited 1 with a raw `ENOENT` instead of the documented
  exit 2.

## [0.1.0] - 2026-11-11

Initial release. ModelGate is a static, read-only supply-chain checker for
Hugging Face repositories.

### Added

* **Read-only scanner core** — GET-only Hugging Face client with strict
  validation of repository IDs, revisions, repository types and file paths;
  no code execution anywhere in the binary.
* **Static rule catalogue** — 13 Python rules across command execution,
  dynamic evaluation, obfuscation, networking, unsafe deserialization and
  dependency confusion, plus an auto_map chain rule (`MG-ENC-002`),
  listed by `modelgate rules`.
* **Config and trust analysis** — `trust_remote_code` flag, `auto_map`
  entry points (with traversal-safe path resolution), malformed-value
  findings, model-card mention counting, dataset loading-script detection.
* **Commit pinning** — `--pin <sha>` produces a delta report (changed files,
  new and resolved findings) against the current revision.
* **Report formats** — `text`, `json` (schema `1.0`), `sigma`, `sarif`
  (SARIF 2.1.0), written to stdout or to `--out`.
* **SBOM** — CycloneDX 1.6 JSON via `--sbom` (component type
  `machine-learning-model` for the analysed revision), verified against the
  official schema.
* **Exit codes** — `0` clean, `1` findings at or above `--fail-on`,
  `2` usage or runtime error; `WARNING:` line whenever a run fails the gate.
* **Defensive hardening** — hostile-tree handling (unknown entry types are
  analysed as files, traversal paths rejected at the parser), evidence
  masking (strings and comments blanked before matching), evidence length
  caps on rune boundaries, analysis file/size limits with explicit
  "not analyzed" findings.
* **Tests** — unit and acceptance tests for every package, ≥ 80 % coverage on
  the core packages, fuzz targets for every input parser
  (`FuzzParseConfig`, `FuzzResolveAutoMapPath`, `FuzzAnalyzePython`,
  `FuzzMaskPython`, `FuzzCountCardMentions`, `FuzzParseMeta`,
  `FuzzParseTree`, `FuzzSplitArgs`), a spy fixture proving model code is never
  executed, and a tree-hash test proving no file is written without
  `--out` / `--sbom`.
* **CI (blocking)** — build/vet/gofmt, full test suite with fuzz smoke runs,
  ≥ 80 % coverage gate, keyword and scope gate, DCO check, CodeQL, dependency
  review, gitleaks (pinned `v8.30.1`), CycloneDX SBOM generation, OpenSSF
  Scorecard.
* **Governance** — README with purpose, dual-use notice, unauthorized-use
  prohibition and AUP, disclaimer (§ 521 / § 276 Abs. 3 BGB), support-end and
  versioning policy; SECURITY, ETHICS, CONTRIBUTING (DCO), CODE_OF_CONDUCT,
  NOTICE, TRANSPARENCY, APPEAL, RELEASING; issue and pull request templates;
  Dependabot configuration.

[Unreleased]: https://github.com/trungminhdo4-glitch/modelgate/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/trungminhdo4-glitch/modelgate/releases/tag/v0.1.0
