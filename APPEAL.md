# Appeals

Every decision taken under [ETHICS.md](ETHICS.md) or the abuse process in
[SECURITY.md](SECURITY.md) — for example closing a report, rejecting a
contribution, restricting an account, or finding that no violation occurred —
can be challenged through this process. The goal is a second, independent look
with fresh eyes, not a re-run of the same argument.

## Who may appeal

* the person or organisation whose report was rejected or closed,
* a contributor whose contribution was rejected or reverted on ethics grounds,
* anyone directly affected by an enforcement decision.

Observers who are not affected may add context in the original issue but
cannot open an appeal themselves.

## Time limits

* **File within 14 days** of receiving the decision. Later appeals are
  accepted only where the appellant shows good cause for the delay (for
  example illness or absence).
* **Acknowledgement within 48 hours** of filing, consistent with the
  project's abuse-response commitment.
* **Decision within 14 days** of a complete filing, in writing.

## Grounds

An appeal must state at least one of:

1. **New evidence** — facts or documents that were not available during the
   original review and that could change the outcome.
2. **Procedural error** — the process in [TRANSPARENCY.md](TRANSPARENCY.md)
   was not followed (missed window, no reasons given, conflict of interest not
   disclosed).
3. **Disproportionality** — the decision is disproportionate to the conduct
   under the published policy.

Disagreeing with the policy itself is not a ground for appeal; propose a
policy change through a pull request instead.

## How to file

Open a **private** report through
[GitHub Security Advisories](https://github.com/trung-dev/modelgate/security/advisories/new)
with:

* the reference of the original decision (issue, advisory, or PR number),
* the ground(s) from the list above,
* any new evidence,
* the outcome you are seeking.

Use the title prefix `APPEAL:`.

## How it is reviewed

1. **Independence.** The appeal is reviewed by a maintainer who did not take
   the original decision. In a single-maintainer project, the repository owner
   performs the review; if the owner took the original decision, the appellant
   may ask an uninvolved third party (for example a respected member of the
   security community) to act as reviewer, and the project will cooperate with
   that reviewer.
2. **Record.** The reviewer re-reads the original evidence plus the appeal,
   and may ask both sides for clarification once.
3. **Outcome.** One of: *upheld* (original decision stands), *modified*
   (adjusted sanction or corrected record), or *overturned* (decision reversed
   and any record corrected).
4. **Communication.** The appellant receives the outcome in writing with
   reasons within the 14-day window. The final decision is binding for the
   project.

## Non-retaliation

Filing an appeal in good faith never results in additional restrictions,
delays, or hostility. Retaliation against an appellant is itself a violation
of [ETHICS.md](ETHICS.md).

## Record keeping

Appeal records are kept only as long as needed to demonstrate a fair process,
contain the minimum personal data required, and are never published. Aggregate
counts (number of appeals, outcomes) appear in the project's transparency
record.
