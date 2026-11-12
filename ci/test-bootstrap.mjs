// test-bootstrap.mjs - tests for the reproducible bootstrap plan (node:test).
//
// TDD contract: bootstrap must be a deterministic, ordered step plan:
// tool preflight -> module download (unless offline) -> format -> vet ->
// tests -> gate tests -> keyword gate. Missing required tools fail closed
// with exit 2 and a concrete install hint - never silently, and with the
// same exit code in every mode.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  REQUIRED_TOOLS,
  describeMissing,
  discoverRegistry,
  main,
  planSteps,
  recipeHint,
} from "./bootstrap.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

test("planSteps (online) is ordered and complete", () => {
  const ids = planSteps({ offline: false }).map((s) => s.id);
  assert.deepEqual(ids, [
    "tool-preflight",
    "go-mod-download",
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
  const msg = describeMissing(missing, {
    registryPath: join("w", "Dev", "school", "tool-registry", "registry.mjs"),
  });
  assert.match(msg, /gitleaks/);
  assert.match(msg, /actionlint/);
  assert.match(msg, /tool-registry/);
  assert.match(msg, /registry\.mjs recipe/);
});

test("without a machine registry the hint falls back to RELEASING.md", () => {
  const msg = describeMissing(["go"], { registryPath: null });
  assert.match(msg, /missing required tools: go/);
  assert.match(msg, /install/);
  assert.match(msg, /RELEASING\.md/);
  assert.doesNotMatch(msg, /registry\.mjs recipe/);
});

test("recipeHint names the machine-readable registry", () => {
  const hint = recipeHint(
    "gitleaks",
    join("w", "Dev", "school", "tool-registry", "registry.mjs"),
  );
  assert.match(hint, /tool-registry/);
  assert.match(hint, /gitleaks/);
});

test("recipeHint fails closed instead of rendering a placeholder path", () => {
  assert.throws(() => recipeHint("gitleaks", null), /registry|tool/);
});

test("recipeHint without an explicit path follows discoverRegistry", () => {
  const discovered = discoverRegistry();
  if (discovered === null) {
    assert.throws(() => recipeHint("gitleaks"), /registry|tool/);
    return;
  }
  const hint = recipeHint("gitleaks");
  assert.ok(hint.includes(discovered), hint);
  assert.doesNotMatch(hint, /undefined|\bnull\b/, hint);
});

test("discoverRegistry probes the given root for the registry file", () => {
  const root = mkdtempSync(join(tmpdir(), "mg-registry-"));
  try {
    assert.equal(discoverRegistry(root), null);
    const dir = join(root, "Dev", "school", "tool-registry");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "registry.mjs"), "");
    assert.equal(discoverRegistry(root), join(dir, "registry.mjs"));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("cli entry point answers --help with usage and exit 0", () => {
  const res = spawnSync(process.execPath, ["ci/bootstrap.mjs", "--help"], {
    encoding: "utf8",
    cwd: repoRoot,
  });
  assert.equal(res.status, 0, res.stderr);
  assert.match(res.stdout, /usage: node ci\/bootstrap\.mjs/);
  assert.match(res.stdout, /exit 0 = green, 1 = step failed, 2 = missing tool\/usage/);
});

test("cli rejects unknown arguments with exit 2", () => {
  const res = spawnSync(process.execPath, ["ci/bootstrap.mjs", "--nope"], {
    encoding: "utf8",
    cwd: repoRoot,
  });
  assert.equal(res.status, 2, res.stderr);
  assert.match(res.stderr, /unknown argument: --nope/);
});

test("missing go exits 2 with an install hint before any step runs", () => {
  const res = spawnSync(process.execPath, ["ci/bootstrap.mjs"], {
    encoding: "utf8",
    cwd: repoRoot,
    env: { ...process.env, PATH: dirname(process.execPath) },
  });
  assert.equal(res.status, 2, res.stderr);
  assert.match(res.stderr, /missing required tools: go/);
  assert.match(res.stderr, /install/);
});

test("main switches to the repository root before parsing arguments", () => {
  const before = process.cwd();
  const outside = mkdtempSync(join(tmpdir(), "mg-bootstrap-"));
  try {
    process.chdir(outside);
    assert.equal(main(["--nope"]), 2);
    assert.equal(process.cwd(), repoRoot);
  } finally {
    process.chdir(before);
    rmSync(outside, { recursive: true, force: true });
  }
});
