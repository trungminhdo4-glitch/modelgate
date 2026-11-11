# Security Policy

## Reporting a vulnerability

Report vulnerabilities **privately** through
[GitHub Security Advisories](https://github.com/trung-dev/modelgate/security/advisories/new)
for this repository. Do **not** open a public issue for security-relevant
reports.

Please include:

* the ModelGate version (`modelgate version`) and how you installed it,
* a minimal reproduction (command line, repository ID, and the observed
  output),
* the impact you believe it has (for example: a finding is missed, code is
  executed, a file is written without `--out`/`--sbom`).

**What counts as a vulnerability here**

* any path that makes ModelGate execute, import, or evaluate code,
* any write to disk or network request other than the documented opt-in
  `--out` / `--sbom` files and outbound GET to `--api-url`,
* secret leakage through reports, logs, or SBOM output,
* a detection bypass that makes a known-risky pattern report as clean without
  any warning,
* denial of service through unbounded resource use on hostile input.

**What does not count**

* a repository that simply contains no risky patterns (a clean run is a
  heuristic, not a guarantee — see the README disclaimer),
* heuristic false positives that are documented behaviour of a rule,
* findings about third-party model repositories themselves (report those to
  the repository owner or to Hugging Face).

## Response commitments

* **Acknowledgement within 48 hours** of the report (abuse and security
  reports alike).
* **Triage and status update within 7 days**, including whether the report is
  accepted, needs more information, or is out of scope.
* Fixes for accepted critical and high severity issues are prioritised ahead
  of new features; the timeline is agreed with the reporter.
* Credit is given in the advisory and CHANGELOG unless the reporter prefers
  to remain anonymous.

## Abuse process (48 hours)

Reports about *use* of this project (for example someone deploying ModelGate
against infrastructure they do not own, or redistributing it as an offensive
tool) follow the same 48-hour acknowledgement window and are handled under
[ETHICS.md](ETHICS.md). Decisions are recorded and can be challenged through
the appeal path in [APPEAL.md](APPEAL.md); the process itself is described in
[TRANSPARENCY.md](TRANSPARENCY.md).

## Supported versions

Only the latest MAJOR line receives security fixes. See the
[Support-Ende und Versionierung](README.md#support-ende-und-versionierung)
section of the README for the exact policy.

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ (initial line) |
| older  | ❌ end of life |
