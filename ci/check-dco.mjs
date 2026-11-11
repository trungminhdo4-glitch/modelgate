#!/usr/bin/env node
// check-dco.mjs — Developer Certificate of Origin gate (node builtins only).
//
// Every commit message in the pushed range must carry a
// "Signed-off-by: Name <email>" line whose email matches the author
// (or the committer). Used as a blocking CI job; also usable locally.
//
// Exit codes: 0 = all commits signed off, 1 = violation, 2 = usage error.

import { execFileSync } from "node:child_process";
import process from "node:process";

export function checkCommit(subject, body, authorEmail) {
  const text = `${subject}\n${body}`;
  const lines = text.split(/\r?\n/);
  const signoffs = lines
    .filter((l) => /^Signed-off-by:\s*/.test(l))
    .map((l) => l.replace(/^Signed-off-by:\s*/, "").trim());
  if (signoffs.length === 0) {
    return { ok: false, reason: "missing Signed-off-by line" };
  }
  const normalized = authorEmail.trim().toLowerCase();
  const match = signoffs.find((s) => {
    const at = s.lastIndexOf("<");
    return at > 0 && s.slice(at + 1, -1).trim().toLowerCase() === normalized;
  });
  if (!match) {
    return {
      ok: false,
      reason: `Signed-off-by does not match author email ${authorEmail}: ${signoffs.join(" | ")}`,
    };
  }
  return { ok: true };
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8" });
}

function main(argv) {
  const base = argv[0];
  if (!base || argv.includes("--help")) {
    process.stderr.write(
      "usage: node ci/check-dco.mjs <base-ref>     checks <base-ref>..HEAD\n" +
        "       node ci/check-dco.mjs --root         checks every commit reachable from HEAD\n" +
        "exit 0 = signed off, 1 = violation, 2 = usage error\n",
    );
    return argv.includes("--help") ? 0 : 2;
  }
  let log;
  try {
    const range = base === "--root" ? "HEAD" : `${base}..HEAD`;
    log = git(["log", "--format=%H%x00%ae%x00%s%x00%b%x1e", range]);
  } catch (err) {
    process.stderr.write(`check-dco: git log failed: ${err.message}\n`);
    return 2;
  }
  const commits = log.split("\x1e").filter((c) => c.trim() !== "");
  if (commits.length === 0) {
    process.stdout.write("check-dco: no commits in range\n");
    return 0;
  }
  let bad = 0;
  for (const entry of commits) {
    const [hash, email, subject, body] = entry.replace(/^\n+/, "").split("\x00");
    const res = checkCommit(subject ?? "", body ?? "", email ?? "");
    if (!res.ok) {
      bad++;
      process.stdout.write(`check-dco: ${hash?.slice(0, 8)} ${res.reason}\n`);
    }
  }
  if (bad > 0) {
    process.stdout.write(`check-dco: ${bad}/${commits.length} commit(s) not signed off\n`);
    return 1;
  }
  process.stdout.write(`check-dco: ${commits.length} commit(s) signed off\n`);
  return 0;
}

const invoked = process.argv[1] ?? "";
if (invoked.endsWith("check-dco.mjs")) {
  process.exit(main(process.argv.slice(2)));
}
