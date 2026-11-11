# Ethics Policy

ModelGate exists to **defend** machine-learning supply chains. This document is
binding for everyone who contributes to, distributes, or operates this project.

## 1. Defensive purpose only

The project is limited to detection, hardening, forensics, and defensive
research:

* **Allowed:** static analysis of repositories you are entitled to assess,
  detection-rule development, SIEM/SARIF integration, incident response,
  academic and defensive security research, and hardening your own supply
  chain.
* **Forbidden:** developing or improving exploits, payloads, shellcode,
  backdoors, malware, phishing or credential-harvesting material,
  command-and-control tooling, credential theft, or surveillance capabilities.

The repository must never contain exploit code, proof-of-concept exploits,
payloads, phishing templates, C2 infrastructure, or capture/exfiltration code —
in source, fixtures, documentation, or generated artifacts. This is enforced by
`ci/check-keywords.mjs`, which blocks the build when offense markers appear.

## 2. Read-only by construction

ModelGate must stay read-only unless the user explicitly opts in:

* outbound requests are **GET only**, to the configured API endpoint;
* filesystem writes happen **only** through `--out` and `--sbom`;
* no code execution: no interpreter, no `os/exec`, no dynamic evaluation of
  fetched content, no plugin loading;
* fixtures are inert data, proven by the spy-fixture test.

Weakening any of these properties requires an explicit design discussion in an
issue before code is written, and cannot be merged behind a default-on flag.

## 3. Authorisation and scope

Do not use this project to examine systems, accounts, or private data without
documented permission. Lawful testing requires prior, written authorisation
from the owner of the target. The maintainers do not provide authorisation for
third-party systems and will not assist with unauthorised scanning.

## 4. Honest reporting

* A clean run means "no known risky patterns found", never "safe". Reports,
  README text, and CI output must keep that distinction visible.
* Findings are evidence for human review, not verdicts. Do not publish
  accusations about named repositories or authors based on heuristic output
  alone.
* Do not fabricate test results, coverage numbers, or vulnerability claims.
  Unverified items must be marked as such.

## 5. Responsible disclosure

Vulnerability and abuse reports go through [SECURITY.md](SECURITY.md). We
acknowledge within 48 hours, triage within 7 days, and give affected reporters
a chance to be heard before decisions are final (see [APPEAL.md](APPEAL.md)).

## 6. No weaponised derivatives

Redistributing ModelGate with its read-only construction removed, or presenting
it as an offensive tool, violates this policy and the attribution conditions in
[NOTICE](NOTICE). Dual-use knowledge published here stays dual-use: it is
shared so defenders can see the same signals attackers leave behind.

## 7. Conflicts of interest and enforcement

Maintainers disclose conflicts before acting on a report about their own
repositories. Decisions under this policy are recorded (without personal data
beyond what the process requires) in line with
[TRANSPARENCY.md](TRANSPARENCY.md). Anyone affected by a decision may appeal it
under [APPEAL.md](APPEAL.md).

Questions about the boundary of an acceptable contribution: open a discussion
issue **before** submitting the code.
