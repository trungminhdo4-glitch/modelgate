#!/usr/bin/env node
// check-keywords.mjs — ModelGate scope and safety gate (node builtins only).
//
// Blocks commit content that would turn this defensive scanner into an
// offensive tool, plus secret-shaped data. Runs offline against the working
// tree or a git index listing.
//
// Exit codes: 0 = clean, 1 = findings, 2 = usage/internal error.
//
// Two tiers:
//   1. Scope rules: read-only-by-construction invariants (no exec, no
//      network clients besides the GET-only HF client, no eval-style
//      dynamic code loading) for *production* code.
//   2. Content rules: unmistakable offense markers (reverse shells,
//      webshells, exploit PoC payloads, credential stealers, phishing
//      kit templates) anywhere in the tree, except where a documented
//      allowlist entry exists (detection rules, test fixtures).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import process from "node:process";

const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  ".vscode",
  ".idea",
  "coverage",
  "dist",
  "bin",
]);

// Files whose content is *by design* hostile or rule-shaped: the rule
// catalog (detection patterns) and test fixtures. Content rules do not
// apply there — they are inert data, reviewed like any other change, and
// never executed (proven by the spy-fixture test). Secret scanning still
// applies everywhere.
const RULE_CONTEXT = /(^|[\\/])(rules\.go|testdata[\\/]|fixtures?[\\/])/;

// The gate defines these patterns as literals, so scanning it would always
// flag itself. Kept to exactly these two paths; every other file in the
// repository is scanned (asserted by ci/test-gates.mjs).
const SELF_EXCLUDE = new Set(["ci/check-keywords.mjs", "ci/test-gates.mjs"]);

// Production Go code must never execute or spawn anything.
const SCOPE_RULES = [
  {
    id: "SCOPE-EXEC-001",
    why: "production Go must not import os/exec (read-only by construction)",
    fileRe: /\.go$/,
    skipRe: /_test\.go$/,
    pattern: /"os\/exec"|exec\.Command\(/,
  },
  {
    id: "SCOPE-EVAL-001",
    why: "production Go must not use unsafe/reflect-based dynamic code loading",
    fileRe: /\.go$/,
    skipRe: /_test\.go$/,
    pattern: /"unsafe"|reflect\.MakeFunc|plugin\.Open\(/,
  },
  {
    id: "SCOPE-SECRETS-001",
    why: "no secret-shaped material may enter the repository",
    fileRe: /\.(go|mjs|js|md|yml|yaml|json|txt|py)$/,
    skipRe: /(^|[\\/])LICENSE(-CC-BY-4\.0)?\.txt$/,
    pattern:
      /-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|hf_[A-Za-z0-9]{36,}|xox[baprs]-[A-Za-z0-9-]{10,}/,
  },
];

// Unmistakable offense markers: never acceptable in this repository,
// not even in docs. Kept deliberately narrow (code-shaped, not words),
// because the README/ETHICS text legitimately *discusses* attacks.
const CONTENT_RULES = [
  {
    id: "OFFENSE-REVSHELL-001",
    why: "reverse shell one-liner",
    pattern: /bash -i >& ?\/dev\/tcp\/|ncat .*-e \/bin\/(ba)?sh|\/bin\/bash -i >&/,
  },
  {
    id: "OFFENSE-WEBSHELL-001",
    why: "PHP webshell snippet",
    pattern: /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)|system\s*\(\s*\$_(POST|GET|REQUEST)|passthru\s*\(\s*\$_(POST|GET)/,
  },
  {
    id: "OFFENSE-POC-001",
    why: "exploit PoC payload marker (Log4Shell JNDI injection string)",
    pattern: /\$\{jndi:(ldap|ldaps|rmi|dns|iiop):\/\//,
  },
  {
    id: "OFFENSE-STAGER-001",
    why: "credential-dumping / loader tooling invocation",
    pattern: /mimikatz|sekurlsa::logonpasswords|procdump(64)?\.exe.{0,40}lsass|msfvenom\s+-p\s/,
  },
  {
    id: "OFFENSE-C2-001",
    why: "command-and-control beacon configuration key",
    pattern: /beacon_interval\s*[:=]|"c2_server"\s*:|cobaltstrike[_-]beacon/,
  },
  {
    id: "OFFENSE-PHISH-001",
    why: "phishing kit template marker (credential harvest form action)",
    pattern: /<form[^>]+action=["'][^"']*(login|verify|signin|account)[-_.]?(confirm|update|secure)?[^"']*["'][^>]*>\s*<input[^>]+name=["'](pass|pwd|credential)/i,
  },
  {
    id: "OFFENSE-STEALER-001",
    why: "info-stealer / webinject marker",
    pattern: /webinject|redline[_-]stealer|raccoon[_-]stealer|steal(er)?[_-]log/,
  },
];

const TEXT_EXT = new Set([
  ".go", ".mjs", ".js", ".ts", ".py", ".md", ".txt", ".yml", ".yaml",
  ".json", ".toml", ".mod", ".sum", ".html", ".css", ".sh", ".ps1",
  ".gitignore", ".gitattributes", "",
]);

function walk(root, out = []) {
  for (const name of readdirSync(root)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(root, name);
    const st = statSync(full);
    if (st.isDirectory()) {
      walk(full, out);
    } else {
      out.push(full);
    }
  }
  return out;
}

function isTextFile(path) {
  const lower = path.toLowerCase();
  const dot = lower.lastIndexOf(".");
  const ext = dot >= 0 ? lower.slice(dot) : "";
  return TEXT_EXT.has(ext) || TEXT_EXT.has(lower.slice(lower.lastIndexOf(sep) + 1));
}

export function scanFile(relPath, content) {
  const findings = [];
  const inRuleContext = RULE_CONTEXT.test(relPath);
  for (const rule of SCOPE_RULES) {
    if (!rule.fileRe.test(relPath)) continue;
    if (rule.skipRe && rule.skipRe.test(relPath)) continue;
    if (inRuleContext && rule.id !== "SCOPE-SECRETS-001") continue;
    const m = content.match(rule.pattern);
    if (m) {
      findings.push({ rule: rule.id, path: relPath, why: rule.why, sample: m[0].slice(0, 60) });
    }
  }
  for (const rule of CONTENT_RULES) {
    if (inRuleContext) continue;
    const m = content.match(rule.pattern);
    if (m) {
      findings.push({ rule: rule.id, path: relPath, why: rule.why, sample: m[0].slice(0, 60) });
    }
  }
  return findings;
}

export function scanTree(root) {
  const findings = [];
  for (const file of walk(root)) {
    const rel = relative(root, file);
    if (rel.split(sep).includes(".git")) continue;
    const relPosix = rel.split(sep).join("/");
    if (SELF_EXCLUDE.has(relPosix)) continue;
    if (!isTextFile(file)) continue;
    let content;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    // Strip NUL-heavy binaries that slipped through the extension filter.
    if (content.includes("\u0000")) continue;
    findings.push(...scanFile(relPosix, content));
  }
  return findings;
}

function main(argv) {
  const root = argv.includes("--root")
    ? argv[argv.indexOf("--root") + 1]
    : process.cwd();
  if (!root || argv.includes("--help")) {
    process.stderr.write(
      "usage: node ci/check-keywords.mjs [--root <dir>]\n" +
        "exit 0 = clean, 1 = findings, 2 = usage error\n",
    );
    return argv.includes("--help") ? 0 : 2;
  }
  let findings;
  try {
    findings = scanTree(root);
  } catch (err) {
    process.stderr.write(`check-keywords: ${err.message}\n`);
    return 2;
  }
  if (findings.length > 0) {
    for (const f of findings) {
      process.stdout.write(`${f.rule} ${f.path}: ${f.why} [${f.sample}]\n`);
    }
    process.stdout.write(`check-keywords: ${findings.length} finding(s)\n`);
    return 1;
  }
  process.stdout.write("check-keywords: clean\n");
  return 0;
}

if ((process.argv[1] ?? "").endsWith("check-keywords.mjs")) {
  process.exit(main(process.argv.slice(2)));
}
