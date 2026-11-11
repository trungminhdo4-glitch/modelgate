# Transparency

ModelGate is a defensive security tool. Trust in it depends on being able to
verify what it does, what it collects, and how decisions about it are made.
This document states all three plainly.

## 1. What the software collects: nothing

* **No telemetry, no analytics, no crash reporting, no update checks.** The
  binary does not phone home. There is no code path that sends usage data
  anywhere.
* **No accounts, no cookies, no local state.** ModelGate reads no
  configuration files and writes none. The only filesystem writes are the
  explicit `--out` (report) and `--sbom` (SBOM) destinations you name on the
  command line.
* **The only network traffic** is outbound HTTP **GET** to the `--api-url`
  endpoint (default `https://huggingface.co`): repository metadata, file tree,
  `config.json`, the model card, and the Python files needed for static
  analysis. Request paths contain the repository ID and revision you asked
  for — nothing else.
* **No code is executed.** Fetched content is parsed and matched against
  static rules; it is never imported, evaluated, or spawned.

## 2. What appears in reports

Reports contain: repository ID and type, revision SHA, file paths, rule IDs,
severity, and short evidence excerpts from the analysed files. They contain
**no personal data and no credentials** by design — evidence is truncated and
masked (string and comment contents are blanked before matching).

## 3. How the project itself is run

| Topic | Practice |
| --- | --- |
| Source of truth | This repository; every policy change lands as a reviewed pull request. |
| Decision log | Issues, pull requests, and release notes are public. Substantive decisions get a written rationale in the issue or PR. |
| CI | All workflows are public and blocking: CI (build/test/fuzz/coverage/gates/DCO), CodeQL, dependency review, gitleaks, SBOM, Scorecard. |
| Supply chain | Dependabot for Go modules and GitHub Actions; pinned action major versions; a CycloneDX 1.6 SBOM is generated on every push. |
| Abuse reports | 48-hour acknowledgement window (see [SECURITY.md](SECURITY.md)). |
| Moderation | Conduct decisions follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and are communicated with reasons. |
| Data held about people | Only what a report or appeal requires to be processed (contact handle, message text). Kept no longer than the process needs; never sold, never shared beyond the maintainers handling the case. |

## 4. The 48-hour abuse process

1. **Day 0** — report received through the channel in [SECURITY.md](SECURITY.md)
   (GitHub Security Advisories). Automatic acknowledgement.
2. **Within 48 hours** — a human confirms receipt and states whether the
   report is in scope, needs more detail, or is rejected with reasons.
3. **Within 7 days** — triage outcome: accepted (fix or policy action
   scheduled, timeline agreed), needs information, or out of scope.
4. **Action** — accepted reports are handled under [ETHICS.md](ETHICS.md);
   affected parties are told what will change and when.
5. **Appeal** — any party affected by a decision may appeal under
   [APPEAL.md](APPEAL.md). Appeals do not restart the 48-hour clock but are
   acknowledged within 48 hours as well.
6. **Record** — outcomes are recorded in aggregate (category, outcome, date)
   in the project's public record; personal data stays inside the process.

## 5. Changes to this document

Material changes to policies (ethics, security, transparency, appeal) require
a pull request with rationale, are listed in [CHANGELOG.md](CHANGELOG.md), and
are announced in the release notes of the first release that contains them.
