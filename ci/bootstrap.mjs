#!/usr/bin/env node
// bootstrap.mjs - reproducible fresh-clone bootstrap (node builtins only).
//
// Deterministic, ordered step plan:
//   go-mod-download -> tool-preflight -> gofmt -> go-vet -> go-test ->
//   gate-tests -> keyword-gate
//
// Fail-closed: a missing required tool exits 2 with a pointer to the
// machine tool registry; a failing step exits 1. No step is skipped
// silently and no step contains placeholders.
//
// Exit codes: 0 = bootstrap green, 1 = step failed, 2 = missing tool/usage.

import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

/** Every external binary the full gate run depends on (plus Go itself). */
export const REQUIRED_TOOLS = ["go", "node", "gitleaks", "actionlint", "yamllint"];

/** Probe arguments per tool that print a version and exit 0. */
const PROBE_ARGS = {
  go: ["version"],
  node: ["--version"],
  gitleaks: ["version"],
  actionlint: ["-version"],
  yamllint: ["--version"],
};

const REGISTRY = path.join("Dev", "school", "tool-registry", "registry.mjs");

export function recipeHint(tool) {
  const root = process.env.USERPROFILE || process.env.HOME || os.homedir();
  return `node ${path.join(root, REGISTRY)} recipe ${tool}`;
}

export function describeMissing(missing) {
  return [
    `missing required tools: ${missing.join(", ")}`,
    "install them via the machine tool registry (school/tool-registry):",
    ...missing.map((t) => `  ${recipeHint(t)}`),
  ].join("\n");
}

/**
 * The bootstrap step plan. `offline` drops exactly the module download;
 * everything else always runs.
 */
export function planSteps({ offline }) {
  const steps = [
    { id: "go-mod-download", kind: "exec", cmd: "go", argv: ["mod", "download"] },
    {
      id: "tool-preflight",
      kind: "preflight",
      cmd: "preflight",
      argv: [...REQUIRED_TOOLS],
    },
    { id: "gofmt", kind: "exec", cmd: "gofmt", argv: ["-l", "."], expectEmptyStdout: true },
    { id: "go-vet", kind: "exec", cmd: "go", argv: ["vet", "./..."] },
    { id: "go-test", kind: "exec", cmd: "go", argv: ["test", "./...", "-count=1"] },
    {
      id: "gate-tests",
      kind: "exec",
      cmd: process.execPath,
      argv: ["--test", "ci/test-gates.mjs", "ci/test-bootstrap.mjs"],
    },
    { id: "keyword-gate", kind: "exec", cmd: process.execPath, argv: ["ci/check-keywords.mjs"] },
  ];
  return offline ? steps.filter((s) => s.id !== "go-mod-download") : steps;
}

/** Probe one tool; returns true only if it exists and its probe exits 0. */
export function probeTool(tool, exec = spawnSync) {
  const res = exec(tool, PROBE_ARGS[tool] || ["--version"], { encoding: "utf8" });
  if (res.error) return false;
  return res.status === 0;
}

export function preflight(tools, probe = probeTool) {
  return tools.filter((t) => !probe(t));
}

function runStep(step) {
  const res = spawnSync(step.cmd, step.argv, { encoding: "utf8" });
  if (res.error) {
    process.stderr.write(`bootstrap: ${step.id}: ${res.error.message}\n`);
    return false;
  }
  const out = (res.stdout || "").trim();
  if (res.status !== 0) {
    process.stderr.write(`bootstrap: ${step.id} failed (exit ${res.status})\n`);
    if (out) process.stderr.write(out + "\n");
    if (res.stderr) process.stderr.write(res.stderr + "\n");
    return false;
  }
  if (step.expectEmptyStdout && out !== "") {
    process.stderr.write(`bootstrap: ${step.id} reported differences:\n${out}\n`);
    return false;
  }
  process.stdout.write(`bootstrap: ${step.id} ok\n`);
  return true;
}

function main(argv) {
  if (argv.includes("--help")) {
    process.stdout.write(
      "usage: node ci/bootstrap.mjs [--offline]\n" +
        "  --offline   skip 'go mod download' (air-gapped re-runs)\n" +
        "exit 0 = green, 1 = step failed, 2 = missing tool/usage\n",
    );
    return 0;
  }
  const unknown = argv.filter((a) => a !== "--offline");
  if (unknown.length > 0) {
    process.stderr.write(`bootstrap: unknown argument: ${unknown[0]}\n`);
    return 2;
  }
  const offline = argv.includes("--offline");
  for (const step of planSteps({ offline })) {
    if (step.kind === "preflight") {
      const missing = preflight(step.argv);
      if (missing.length > 0) {
        process.stderr.write(describeMissing(missing) + "\n");
        return 2;
      }
      process.stdout.write("bootstrap: tool-preflight ok\n");
      continue;
    }
    if (!runStep(step)) return 1;
  }
  process.stdout.write("bootstrap: green\n");
  return 0;
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked !== "" && fileURLToPath(import.meta.url) === invoked) {
  process.exit(main(process.argv.slice(2)));
}
