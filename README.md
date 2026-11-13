# ModelGate

ModelGate is a **static, read-only supply-chain checker for Hugging Face
repositories**. It downloads a repository's metadata, file tree, `config.json`
and the Python files referenced by `auto_map` using HTTP **GET requests only**,
matches them against a catalogue of static detection rules, and reports what it
finds — as human-readable text, JSON, Sigma or SARIF — plus an optional
CycloneDX 1.6 SBOM and a commit-pin delta report.

**ModelGate never executes model code, repository code, or any third-party
code.** There is no interpreter, no `os/exec`, no dynamic evaluation, and no
network listener: the binary only speaks outbound GET to the API endpoint you
point it at (default `https://huggingface.co`).

```console
$ modelgate check sentence-transformers/all-MiniLM-L6-v2
ModelGate 0.1.0 — static supply-chain check (read-only, non-executing)
...
No findings. The check found no known risky patterns.

Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info — worst=none, fail-on=high → exit 0
```

## Zweck

The tool exists to answer one question **before** a model or dataset is loaded
into an environment:

> *Does this repository contain code that runs automatically, and is that code
> doing anything a reviewer should see first?*

ModelGate is built for defensive use cases:

* **Pre-deployment review** of third-party models and datasets (ML engineers,
  platform teams, incident responders).
* **Continuous monitoring** of the repositories an organisation depends on
  (CI pipelines, pin-and-diff workflows).
* **Forensics and detection engineering** (Sigma/SARIF output feeds SIEM and
  code-scanning platforms).
* **Security research** into supply-chain attacks on the ML ecosystem,
  conducted lawfully and without harming third parties.

Scope of the analysis (v0.1):

| Surface | What is checked |
| --- | --- |
| `config.json` | `trust_remote_code`, `auto_map` entry points, malformed values |
| Repository tree | bounded pagination, traversal/absolute paths, size and file-count limits, unexpected entry types |
| Python sources | 13 static rules across command execution, dynamic evaluation, obfuscation, networking, unsafe deserialization, dependency confusion |
| Model card | documented `trust_remote_code` usage |
| Dataset repos | presence of executable loading scripts |
| Pinning | delta report between an approved commit SHA and the current revision |

What ModelGate deliberately does **not** do: execute code, import the model,
reach out to anything other than the configured API endpoint, mutate the remote
repository, or write to disk unless you explicitly pass `--out` / `--sbom`.

## Dual-Use

ModelGate is **defensive security software**. The detection rules describe how
malicious or careless repositories *look*; the scanner itself only reads and
reports. This is inherently dual-use knowledge — the same observations that let
a defender catch a backdoored model could, in other hands, help someone refine
what they hide.

That risk is managed, not denied:

* The repository ships **detections, never capabilities**: no exploit code, no
  payloads, no proof-of-concept exploits, no phishing or credential-harvesting
  material, no command-and-control tooling, no capture or exfiltration code.
* Fixtures used by the test suite are **inert**: they are static files that are
  read, never executed (a tripwire fixture proves this — see
  `testdata/spy/remote_code_spy.py` and the `SPY_EXECUTED.marker` test).
* Everything is published under a defensive-use licence and ethics policy
  ([ETHICS.md](ETHICS.md)) that prohibits weaponisation.
* A blocking keyword gate (`ci/check-keywords.mjs`) fails the build if offense
  markers or secret-shaped material enter the tree.

If you are unsure whether your intended use is covered, ask **before** you
build on top of this project (see [SECURITY.md](SECURITY.md)).

## Unauthorized Use — Verbot und Acceptable Use Policy (AUP)

**Using ModelGate against systems, accounts, or data you are not authorised to
examine is prohibited.** Unauthorised use includes, without limitation:

1. Scanning or probing third-party infrastructure, accounts, or private
   repositories without documented permission.
2. Using ModelGate — or what you learn from it — to develop, test, improve, or
   validate malware, backdoors, exploits, phishing content, or command-and-
   control infrastructure.
3. Using findings to target individuals, to extort, to harass, or to
   facilitate any other unlawful act.
4. Removing, altering, or hiding the licence, ethics, or attribution notices to
   present the work as your own offensive tool.
5. Circumventing the read-only construction (for example by adding code
   execution) and redistributing the result under this project's name.

Acceptable use is the inverse: defensive review of repositories you are
entitled to assess, detection engineering, academic research, and hardening of
your own supply chain. The full policy, including enforcement and reporting,
lives in [ETHICS.md](ETHICS.md); the abuse and appeal process is documented in
[TRANSPARENCY.md](TRANSPARENCY.md) and [APPEAL.md](APPEAL.md).

Violations reported through the channel in [SECURITY.md](SECURITY.md) are
handled within the 48-hour abuse process described there.

## Disclaimer (§ 521 / § 276 Abs. 3 BGB)

ModelGate wird **"wie besehen" (as-is)** bereitgestellt, ohne Gewähr auf
Vollständigkeit, Richtigkeit oder Eignung für einen bestimmten Zweck. Die
Regeln sind heuristische Erkennungsmuster: ein sauberer Lauf ist **kein**
Nachweis, dass ein Modell harmlos ist, und ein Fund ist **kein** Nachweis für
einen Angriff — beide erfordern fachliche Nachprüfung.

Soweit die unentgeltliche Bereitstellung dieser Software als Schenkung zu
werten ist, haftet der Anbieter gemäß **§ 521 BGB** nur bei Vorsatz und grober
Fahrlässigkeit. Eine Haftung für **Vorsatz bleibt gemäß § 276 Abs. 3 BGB
ausdrücklich vorbehalten** und kann nicht ausgeschlossen werden; ebenso
unberührt bleiben die zwingenden Haftungsvorschriften des Produkthaftungs-
rechts. Für leichte Fahrlässigkeit wird die Haftung — soweit gesetzlich
zulässig — ausgeschlossen.

Der Anbieter übernimmt keine Verantwortung für Schäden, die aus der Nutzung
oder Nicht-Nutzung dieses Werkzeugs entstehen, und keine Verpflichtung zur
Aktualität der Regeln. Es wird **kein Rechtsrat** erteilt; die genannten
Vorschriften ersetzen keine anwaltliche Beratung im Einzelfall.

Drittanbieter-Inhalte (Modell-, Dataset- und Kartenbeschreibungen, die von
Hugging Face geliefert werden) unterliegen den Lizenzen ihrer jeweiligen
Verfasser und werden von ModelGate nur gelesen, nicht verändert.

## Support-Ende und Versionierung

* **Semantic Versioning:** `MAJOR.MINOR.PATCH`. The report schema
  (`schema_version`), rule IDs, exit codes and CLI flags are part of the public
  contract; breaking any of them requires a MAJOR bump.
* **Support window (best effort):** each MAJOR line is *intended* to receive
  security fixes for about **6 months** after the next MAJOR release; after
  that it is declared end-of-life (EOL) and receives no further updates,
  including for newly disclosed vulnerabilities. This is a best-effort
  intention of a non-commercial, volunteer-run project - not a binding
  promise, warranty or SLA. If capacity changes, the window may be shorter;
  the CHANGELOG and [RELEASING.md](RELEASING.md) carry the authoritative
  statement at any time.
* **No SLA:** releases happen as capacity allows; there is no guaranteed
  response or delivery time for features.
* **Release signing:** release artifacts and the SBOM are produced by CI;
  checksums are published with each release (see [RELEASING.md](RELEASING.md)).
* The current version is printed by `modelgate version` and recorded in
  [CHANGELOG.md](CHANGELOG.md).

## Installation

```console
$ go install github.com/trungminhdo4-glitch/modelgate/cmd/modelgate@latest
$ modelgate version
modelgate 0.1.0
```

Requires Go 1.27 or newer to build. No runtime dependencies, no configuration
files, no telemetry.

## Usage

```console
modelgate check <repo-id> [flags]   read-only security check of one repository
modelgate rules [--format json]     list the static pattern rules
modelgate version                   print the version
```

Important flags for `check`:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--type` | `model` | repository type: `model` or `dataset` |
| `--revision` | default branch | branch, tag or commit SHA to check |
| `--pin` | — | expected commit SHA; emits a delta report when upstream differs |
| `--format` | `text` | `text`, `json`, `sigma` or `sarif` |
| `--fail-on` | `high` | minimum severity that fails the check |
| `--out` / `--sbom` | — | **the only** filesystem writes; opt-in by flag |
| `--api-url` | `https://huggingface.co` | Hugging Face compatible API base URL (GET only) |
| `--timeout` | `30s` | shared deadline for repository analysis, including pinned revision checks (positive duration such as `500ms` or `2m`) |

Exit codes: **0** — no findings at or above `--fail-on`;
**1** — findings at or above `--fail-on` (a `WARNING:` line is printed);
**2** — usage or runtime error.

CI integration examples:

```yaml
- run: modelgate check my-org/my-model --pin "${APPROVED_SHA}" --format sarif --out results.sarif
```

```console
$ modelgate check my-org/my-model --format json | jq '.summary'
```

## Repository layout

```
cmd/modelgate/        main entry point (wiring only)
internal/cli/         flag parsing, dispatch, exit codes
internal/scan/        rule catalogue, static Python analysis, config/trust logic
internal/hf/          read-only GET-only Hugging Face client and parsers
internal/pin/         commit-pin diffing
internal/report/      text, JSON, Sigma and SARIF renderers
internal/sbom/        CycloneDX 1.6 SBOM builder
internal/testserver/  GET-only fixture endpoint used by the tests
                      (test infrastructure, deliberately outside the
                      coverage gate - see CONTRIBUTING.md)
ci/                   blocking CI gates (keywords, DCO, SBOM) + their tests
testdata/             inert fixtures, including the spy tripwire
.github/workflows/    CI, CodeQL, dependency-review, gitleaks, SBOM, Scorecard
```

## Governance

| Document | Purpose |
| --- | --- |
| [SECURITY.md](SECURITY.md) | vulnerability reporting, 48-hour abuse process |
| [ETHICS.md](ETHICS.md) | defensive-only doctrine and dual-use rules |
| [CONTRIBUTING.md](CONTRIBUTING.md) | contribution and DCO sign-off rules |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | community standards |
| [TRANSPARENCY.md](TRANSPARENCY.md) | what we collect (nothing) and how decisions are published |
| [APPEAL.md](APPEAL.md) | how to appeal an abuse decision |
| [NOTICE](NOTICE) | attribution and the Apache-2.0 / CC-BY-4.0 licence split |
| [CHANGELOG.md](CHANGELOG.md) | release history (SemVer) |
| [RELEASING.md](RELEASING.md) | release and signing procedure |

## Licence

* **Code** — [Apache License 2.0](LICENSE).
* **Detection rules, fixtures, documentation and IOC-like content** —
  [CC BY 4.0](LICENSE-CC-BY-4.0.txt), attribution required.

See [NOTICE](NOTICE) for the exact split.

---

<!-- Badges last, after purpose, dual-use, AUP, disclaimer and support policy. -->

[![CI](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/ci.yml/badge.svg)](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/ci.yml)
[![CodeQL](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/codeql.yml/badge.svg)](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/codeql.yml)
[![Gitleaks](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/gitleaks.yml/badge.svg)](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/gitleaks.yml)
[![SBOM](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/sbom.yml/badge.svg)](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/sbom.yml)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25%20core-brightgreen)](https://github.com/trungminhdo4-glitch/modelgate/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: Code](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![License: Rules](https://img.shields.io/badge/license-CC%20BY%204.0-lightgrey.svg)](LICENSE-CC-BY-4.0.txt)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/trungminhdo4-glitch/modelgate/badge)](https://securityscorecards.dev/viewer/?uri=github.com/trungminhdo4-glitch/modelgate)
[![DCO](https://img.shields.io/badge/DCO-required-green.svg)](CONTRIBUTING.md)
