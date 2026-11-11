#!/usr/bin/env node
// sbom.mjs — CycloneDX 1.6 SBOM for this Go module (node builtins only).
//
// Reads `go list -m -json all` (offline for a dependency-free module) and
// emits a CycloneDX 1.6 JSON document with one component per module plus
// the ModelGate tool itself. Fails closed if `go` is unavailable or the
// output is not valid JSON.
//
// Exit codes: 0 = sbom written, 1 = invalid input, 2 = usage/tool error.

import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import process from "node:process";

export function buildBom(modules, opts) {
  const components = modules.map((m) => {
    const c = {
      type: "library",
      "bom-ref": `pkg:golang/${m.Path}@${m.Version || "v0.0.0"}`,
      name: m.Path,
      version: m.Version || "v0.0.0",
      purl: `pkg:golang/${m.Path}@${m.Version || "v0.0.0"}`,
      scope: m.Main ? "required" : "optional",
    };
    if (m.Main) c.type = "application";
    if (m.Replace) {
      c.name = m.Replace.Path || m.Path;
      c.version = m.Replace.Version || m.Version || "v0.0.0";
      c.purl = `pkg:golang/${c.name}@${c.version}`;
      c["bom-ref"] = c.purl;
    }
    return c;
  });
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    serialNumber: `urn:uuid:${opts.serial}`,
    metadata: {
      timestamp: opts.timestamp,
      tools: [
        {
          vendor: "trung-dev",
          name: "modelgate-sbom",
          version: opts.toolVersion,
        },
      ],
      component: components.find((c) => c.type === "application") ?? {
        type: "application",
        name: "modelgate",
        version: opts.toolVersion,
      },
    },
    components,
  };
}

export function validateBom(bom) {
  const problems = [];
  if (bom.bomFormat !== "CycloneDX") problems.push("bomFormat must be CycloneDX");
  if (bom.specVersion !== "1.6") problems.push("specVersion must be 1.6");
  if (!Array.isArray(bom.components) || bom.components.length === 0) {
    problems.push("components must be a non-empty array");
  }
  for (const c of bom.components ?? []) {
    if (!c.name || !c.version || !c.purl) problems.push(`component missing name/version/purl: ${JSON.stringify(c)}`);
    if (!["library", "application", "framework", "container", "operating-system", "device", "firmware", "file"].includes(c.type)) {
      problems.push(`invalid component type: ${c.type}`);
    }
  }
  return problems;
}

function deterministicSerial(input) {
  const hash = createHash("sha256").update(input).digest("hex");
  const h = hash.slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function main(argv) {
  const outIdx = argv.indexOf("--out");
  const outPath = outIdx >= 0 ? argv[outIdx + 1] : "sbom.cdx.json";
  const tsIdx = argv.indexOf("--timestamp");
  const timestamp = tsIdx >= 0 ? argv[tsIdx + 1] : new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const verIdx = argv.indexOf("--tool-version");
  const toolVersion = verIdx >= 0 ? argv[verIdx + 1] : "dev";
  if (!outPath || argv.includes("--help")) {
    process.stderr.write(
      "usage: node ci/sbom.mjs [--out sbom.cdx.json] [--timestamp ISO] [--tool-version V]\n" +
        "exit 0 = written, 1 = invalid, 2 = tool error\n",
    );
    return argv.includes("--help") ? 0 : 2;
  }

  let raw;
  try {
    raw = execFileSync("go", ["list", "-m", "-json", "all"], {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (err) {
    process.stderr.write(`sbom: go list failed: ${err.message}\n`);
    return 2;
  }

  const modules = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (raw[i] === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          modules.push(JSON.parse(raw.slice(start, i + 1)));
        } catch (err) {
          process.stderr.write(`sbom: cannot parse module JSON: ${err.message}\n`);
          return 1;
        }
        start = -1;
      }
    }
  }
  if (modules.length === 0) {
    process.stderr.write("sbom: no modules returned by go list\n");
    return 1;
  }

  const serial = deterministicSerial(JSON.stringify(modules) + timestamp + toolVersion);
  const bom = buildBom(modules, { serial, timestamp, toolVersion });
  const problems = validateBom(bom);
  if (problems.length > 0) {
    for (const p of problems) process.stderr.write(`sbom: ${p}\n`);
    return 1;
  }
  writeFileSync(outPath, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
  process.stdout.write(`sbom: wrote ${outPath} (${bom.components.length} component(s))\n`);
  return 0;
}

if ((process.argv[1] ?? "").endsWith("sbom.mjs")) {
  process.exit(main(process.argv.slice(2)));
}
