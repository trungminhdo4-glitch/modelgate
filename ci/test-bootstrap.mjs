// test-bootstrap.mjs - tests for the reproducible bootstrap plan (node:test).
//
// TDD contract: bootstrap must be a deterministic, ordered step plan:
// module download (unless offline) -> tool preflight -> format -> vet ->
// tests -> gate tests -> keyword gate. Missing required tools fail closed
// with exit 2 and a pointer to the tool-registry recipe - never silently.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";
import test from "node:test";

import {
  REQUIRED_TOOLS,
  describeMissing,
  planSteps,
  recipeHint,
} from "./bootstrap.mjs";

test("planSteps (online) is ordered and complete", () => {
  const ids = planSteps({ offline: false }).map((s) => s.id);
  assert.deepEqual(ids, [
    "go-mod-download",
    "tool-preflight",
    "gofmt",
    "go-vet",
    "go-test",
    "gate-tests",
    "keyword-gate",
  ]);
});

test("planSteps (offline) skips only the module download", () => {
  const online = planSteps({ offline: false }).map((s) => s.id);
  const offline = planSteps({ offline: true }).map((s) => s.id);
  assert.deepEqual(offline, online.filter((id) => id !== "go-mod-download"));
});

test("every step carries a concrete argv (no placeholders)", () => {
  for (const step of planSteps({ offline: false })) {
    assert.ok(step.cmd.length > 0, `${step.id}: empty cmd`);
    for (const arg of step.argv) {
      assert.equal(typeof arg, "string");
      assert.ok(arg.length > 0, `${step.id}: empty argv entry`);
      assert.ok(!/TODO|FIXME|<[^>]+>/.test(arg), `${step.id}: placeholder in ${arg}`);
    }
  }
});

test("required tool set covers every external gate dependency", () => {
  assert.deepEqual(
    [...REQUIRED_TOOLS].sort(),
    ["actionlint", "gitleaks", "go", "node", "yamllint"],
  );
});

test("missing tools fail closed with registry recipe hint", () => {
  const missing = ["gitleaks", "actionlint"];
  const msg = describeMissing(missing);
  assert.match(msg, /gitleaks/);
  assert.match(msg, /actionlint/);
  assert.match(msg, /tool-registry/);
  assert.match(msg, /registry\.mjs recipe/);
});

test("recipeHint names the machine-readable registry", () => {
  assert.match(recipeHint("gitleaks"), /tool-registry/);
  assert.match(recipeHint("gitleaks"), /gitleaks/);
});

test("cli entry point answers --help with usage and exit 0", () => {
  const res = spawnSync(process.execPath, ["ci/bootstrap.mjs", "--help"], {
    encoding: "utf8",
    cwd: path.resolve(import.meta.dirname, ".."),
  });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /usage: node ci\/bootstrap\.mjs/);
  assert.match(res.stdout, /exit 0 = green, 1 = step failed, 2 = missing tool\/usage/);
});

test("cli rejects unknown arguments with exit 2", () => {
  const res = spawnSync(process.execPath, ["ci/bootstrap.mjs", "--nope"], {
    encoding: "utf8",
    cwd: path.resolve(import.meta.dirname, ".."),
  });
  assert.equal(res.status, 2, res.stderr);
  assert.match(res.stderr, /unknown argument: --nope/);
});
