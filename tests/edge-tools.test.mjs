import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import plugin from "../dist/index.js";
import { FINDING_ID_PATTERN } from "../dist/src/utils/secopsai-runner.js";

async function makeFakeCore() {
  const root = await mkdtemp(join(tmpdir(), "secopsai-plugin-"));
  const bin = join(root, ".venv", "bin");
  const argsFile = join(root, "args.txt");
  await mkdir(bin, { recursive: true });
  await writeFile(
    join(bin, "secopsai"),
    `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsFile}"\ncase "$*" in\n  *"graph assets"*) printf '%s\\n' '{"assets":[{"ip_address":"192.168.1.10","status":"active","vendor":"Acme","hostname":"desk"}]}' ;;\n  *"triage list"*) printf '%s\\n' '{"findings":[{"finding_id":"EDGE-ABC123","severity":"high","status":"open","title":"Risky service"}]}' ;;\n  *) printf '%s\\n' '{"nodes":[],"edges":[]}' ;;\nesac\n`,
  );
  await chmod(join(bin, "secopsai"), 0o755);
  return { root, argsFile };
}

function registerTools(config) {
  const tools = new Map();
  plugin.register({
    config,
    registerTool(definition) {
      tools.set(definition.name, definition);
    },
  });
  return tools;
}

test("finding identifiers include Edge findings", () => {
  const pattern = new RegExp(FINDING_ID_PATTERN);
  assert.equal(pattern.test("EDGE-ABC123"), true);
  assert.equal(pattern.test("edge-abc123"), false);
});

test("Edge tools invoke the canonical Core CLI contract", async (t) => {
  const fake = await makeFakeCore();
  t.after(() => rm(fake.root, { recursive: true, force: true }));
  const dbPath = join(fake.root, "soc.db");
  const tools = registerTools({ secopsaiPath: fake.root, socDbPath: dbPath });

  assert.deepEqual(
    ["secopsai_edge_assets", "secopsai_edge_changes", "secopsai_edge_findings"].filter((name) => tools.has(name)),
    ["secopsai_edge_assets", "secopsai_edge_changes", "secopsai_edge_findings"],
  );

  const assets = await tools.get("secopsai_edge_assets").execute("call-1", { limit: 7 });
  assert.match(assets.content[0].text, /192\.168\.1\.10/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["graph", "assets", "--limit", "7", "--db-path", dbPath, "--json"],
  );

  await tools.get("secopsai_edge_changes").execute("call-2", { limit: 9 });
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["graph", "changes", "--limit", "9", "--db-path", dbPath, "--json"],
  );

  const findings = await tools.get("secopsai_edge_findings").execute("call-3", { status: "open", limit: 11 });
  assert.match(findings.content[0].text, /EDGE-ABC123/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["triage", "list", "--source", "secopsai_edge", "--db-path", dbPath, "--status", "open", "--limit", "11", "--json"],
  );
});
