# Changelog

All notable changes to ModelGate are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release tags are `vMAJOR.MINOR.PATCH`. See [RELEASING.md](RELEASING.md) for the
signing and support policy.

## [Unreleased]

### Added

* Metadata-only `MG-ARTIFACT-001` review notices for checkpoint filenames that
  may use pickle serialization, including standard PyTorch weight shards. No
  weight contents are downloaded or deserialized. Notices use low severity and
  flow through the existing reports and pin comparisons.

### Security

* `MG-DESER-001` covers the whole pickle family and other code-executing
  loaders, not just `pickle.load(s)`, `marshal.loads` and `shelve.open`:
  `marshal.load`, `dill`, `cloudpickle`, `joblib.load`, `jsonpickle.decode`,
  `pandas.read_pickle`, `numpy.load(..., allow_pickle=True)`,
  `pickle.Unpickler`, and `yaml.load`/`yaml.load_all` without a
  `SafeLoader`/`CSafeLoader`/`BaseLoader` (plus `yaml.unsafe_load`).
  Aliased imports (`import joblib as jl`) and imported functions
  (`from dill import load`, `from pickle import loads as f`, `import *`) are
  resolved too. `json.load`, `yaml.safe_load`, `numpy.load` without
  `allow_pickle=True` and method calls such as `self.load()` stay quiet.
* `MG-DESER-002` no longer fires on `torch.load(..., weights_only=True)`
  (false positive) and now also sees `from torch import load` and aliases.
* `auto_map` coverage now matches what `transformers` loads:
  * `tokenizer_config.json`, `preprocessor_config.json` and
    `processor_config.json` are read too (AutoTokenizer, AutoImageProcessor,
    AutoProcessor); before, their remote code was never analyzed.
  * List values such as `"AutoTokenizer": ["tok.Slow", "tok_fast.Fast"]`
    (a `null` side is skipped) resolve to each named module instead of
    `MG-CFG-002` "unexpected type".
  * `custom_pipelines[task].impl` in `config.json`, which
    `pipeline(..., trust_remote_code=True)` imports, is analyzed like an
    `auto_map` target; a task without `impl` raises `MG-CFG-002`.
  * A cross-repository reference `org/repo--module.Class` raises the new
    `MG-AUTO-002` (medium): the code comes from another repository and is not
    covered by the scan. Before it surfaced only as a missing local file.
* Python files pulled in by relative imports of an `auto_map` module
  (`from .helpers import x`, recursively) are now analyzed as well.
  `transformers` downloads and runs them with `trust_remote_code`, so a
  payload one import away from the `auto_map` target was previously missed.
  They count against the same analysis file limit (64 files).
* SARIF artifact locations are valid relative URIs (percent-encoded, `\` to
  `/`, `:` escaped) instead of raw file paths.
* Repository file paths are validated per segment: dotted names such as
  `weights..bin` no longer abort the scan, while `./x`, `a//b` and a leading
  `\` are rejected.

### Fixed

* `modelgate rules` rejects unexpected positional arguments instead of
  silently printing the entire catalogue.
* `modelgate rules` reports output write failures and exits with status 2 for text and JSON.

* DCO gate exempts GitHub App bot commits (`<id>+<name>[bot]@users.noreply.github.com`), so Dependabot PRs are no longer blocked by a sign-off they cannot add.

### Added

* Offline rule catalogue filters: `rules --id ID` and `--min-severity LEVEL`
  combine for text or JSON output, preserving rule details and catalogue order.
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

* `check` rejects shared `--out` and `--sbom` targets before scanning or writing either output.
* **DCO gate on pull requests** — `ci/check-dco.mjs` skips merge commits, so
  GitHub's unsigned synthetic merge commit no longer fails every PR.
* Gitleaks workflow: `go install` used `github.com/gitleaks/gitleaks/v8`,
  which does not match the declared module path
  (`github.com/zricethezav/gitleaks/v8`); the install also now publishes
  `$(go env GOPATH)/bin` for the following step.
* Scorecard workflow: `ossf/scorecard-action@v2` no longer exists as a tag;
  pinned to the released `v2.5.0`.
* Bootstrap executed `go mod download` before its own tool preflight, so a
  missing `go` exited 1 with a raw `ENOENT` instead of the documented
  exit 2.
* `recipeHint()` now fails closed (throws) when no tool registry path is
  known instead of returning a hint line containing a placeholder
  (`node undefined recipe ...`); `discoverRegistry()` is pinned by a
  deterministic temp-root test covering both directions.

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
