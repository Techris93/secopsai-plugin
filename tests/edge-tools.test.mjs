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
    `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsFile}"\ncase "$*" in\n  *"session create"*) printf '%s\\n' '{"session":{"session_id":"SES-abcdef123456"}}' ;;\n  *"session request-approval"*) printf '%s\\n' '{"approval":{"approval_id":"APR-abcdef123456","state":"pending"}}' ;;\n  *"session resolve-approval"*) printf '%s\\n' '{"approval":{"approval_id":"APR-abcdef123456","state":"approved"},"applied":{"kind":"edge_scan","result":{"status":"queued"}}}' ;;\n  *"graph assets"*) printf '%s\\n' '{"assets":[{"ip_address":"192.168.1.10","status":"active","vendor":"Acme","hostname":"desk"}]}' ;;\n  *"edge status"*) printf '%s\\n' '{"sync_state":[{"source_instance":"secopsai_edge:api:org","schema_version":"secopsai.edge.bundle.v1","last_synced_at":"2026-07-13T19:00:00Z"}]}' ;;\n  *"triage list"*) printf '%s\\n' '{"findings":[{"finding_id":"EDGE-ABC123","severity":"high","status":"open","title":"Risky service"}]}' ;;\n  *) printf '%s\\n' '{"nodes":[],"edges":[]}' ;;\nesac\n`,
  );
  await chmod(join(bin, "secopsai"), 0o755);
  return { root, argsFile };
}

async function makeFakeEdge() {
  const root = await mkdtemp(join(tmpdir(), "secopsai-edge-plugin-"));
  const scripts = join(root, "scripts");
  const argsFile = join(root, "args.txt");
  await mkdir(scripts, { recursive: true });
  await writeFile(
    join(scripts, "edge"),
    `#!/bin/sh\nprintf '%s\\n' "$@" > "${argsFile}"\ncase "$*" in\n  *"worker status"*) printf '%s\\n' 'Worker service: running (ai.secopsai.edge)' ;;\n  *"preview 192.168.1.0/24"*) printf '%s\\n' '{"target_cidr":"192.168.1.0/24","commands":["nmap"]}' ;;\n  *) printf '%s\\n' 'unexpected command' ;;\nesac\n`,
  );
  await chmod(join(scripts, "edge"), 0o755);
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
  const fakeEdge = await makeFakeEdge();
  t.after(async () => {
    await rm(fake.root, { recursive: true, force: true });
    await rm(fakeEdge.root, { recursive: true, force: true });
  });
  const dbPath = join(fake.root, "soc.db");
  const tools = registerTools({ secopsaiPath: fake.root, edgePath: fakeEdge.root, socDbPath: dbPath });

  assert.deepEqual(
    ["secopsai_edge_assets", "secopsai_edge_worker_status", "secopsai_edge_scan_preview", "secopsai_edge_request_scan", "secopsai_edge_request_report", "secopsai_edge_request_worker_action", "secopsai_edge_changes", "secopsai_edge_sync_status", "secopsai_edge_findings"].filter((name) => tools.has(name)),
    ["secopsai_edge_assets", "secopsai_edge_worker_status", "secopsai_edge_scan_preview", "secopsai_edge_request_scan", "secopsai_edge_request_report", "secopsai_edge_request_worker_action", "secopsai_edge_changes", "secopsai_edge_sync_status", "secopsai_edge_findings"],
  );

  const assets = await tools.get("secopsai_edge_assets").execute("call-1", { limit: 7 });
  assert.match(assets.content[0].text, /192\.168\.1\.10/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["graph", "assets", "--limit", "7", "--db-path", dbPath, "--json"],
  );

  const workerStatus = await tools.get("secopsai_edge_worker_status").execute("call-2", {});
  assert.match(workerStatus.content[0].text, /Worker service: running/);
  assert.deepEqual(
    (await readFile(fakeEdge.argsFile, "utf8")).trim().split("\n"),
    ["worker", "status"],
  );

  const preview = await tools.get("secopsai_edge_scan_preview").execute("call-3", { targetCidr: "192.168.1.0/24" });
  assert.match(preview.content[0].text, /192\.168\.1\.0\/24/);
  assert.deepEqual(
    (await readFile(fakeEdge.argsFile, "utf8")).trim().split("\n"),
    ["preview", "192.168.1.0/24"],
  );

  const scanRequest = await tools.get("secopsai_edge_request_scan").execute("call-3b", {
    targetCidr: "192.168.1.7/24",
    includeWifi: true,
  });
  assert.match(scanRequest.content[0].text, /SES-abcdef123456/);
  assert.match(scanRequest.content[0].text, /APR-abcdef123456/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    [
      "session",
      "request-approval",
      "SES-abcdef123456",
      "--type",
      "custom",
      "--summary",
      "Queue authorized Edge scan for 192.168.1.7/24",
      "--payload",
      '{"kind":"edge_scan","target_cidr":"192.168.1.7/24","include_wifi":true}',
      "--json",
    ],
  );

  const reportRequest = await tools.get("secopsai_edge_request_report").execute("call-3c", {});
  assert.match(reportRequest.content[0].text, /APR-abcdef123456/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    [
      "session",
      "request-approval",
      "SES-abcdef123456",
      "--type",
      "custom",
      "--summary",
      "Generate the current Edge report",
      "--payload",
      '{"kind":"edge_report"}',
      "--json",
    ],
  );

  const workerRequest = await tools.get("secopsai_edge_request_worker_action").execute("call-3d", {
    action: "start",
    sessionId: "SES-abcdef123456",
  });
  assert.match(workerRequest.content[0].text, /APR-abcdef123456/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    [
      "session",
      "request-approval",
      "SES-abcdef123456",
      "--type",
      "custom",
      "--summary",
      "Apply Edge worker action: start",
      "--payload",
      '{"kind":"edge_worker","action":"start"}',
      "--json",
    ],
  );

  await tools.get("secopsai_edge_changes").execute("call-4", { limit: 9 });
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["graph", "changes", "--limit", "9", "--db-path", dbPath, "--json"],
  );

  const syncStatus = await tools.get("secopsai_edge_sync_status").execute("call-5", { limit: 13 });
  assert.match(syncStatus.content[0].text, /secopsai_edge:api:org/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["edge", "status", "--limit", "13", "--db-path", dbPath, "--json"],
  );

  const findings = await tools.get("secopsai_edge_findings").execute("call-6", { status: "open", limit: 11 });
  assert.match(findings.content[0].text, /EDGE-ABC123/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["triage", "list", "--source", "secopsai_edge", "--db-path", dbPath, "--status", "open", "--limit", "11", "--json"],
  );

  const resolved = await tools.get("secopsai_session_resolve_approval").execute("call-6b", {
    sessionId: "SES-abcdef123456",
    approvalId: "APR-abcdef123456",
    decision: "approved",
    apply: true,
  });
  assert.match(resolved.content[0].text, /edge_scan/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    [
      "session",
      "resolve-approval",
      "SES-abcdef123456",
      "APR-abcdef123456",
      "--approve",
      "--db-path",
      dbPath,
      "--edge-root",
      fakeEdge.root,
      "--apply",
      "--json",
    ],
  );

  const packageResearch = await tools.get("secopsai_research_package").execute("call-7", {
    ecosystem: "nuget",
    packageName: "Braintree.Payments.SDK",
    version: "4.2.1",
    searchRoot: fake.root,
  });
  assert.match(packageResearch.content[0].text, /nodes/);
  assert.deepEqual(
    (await readFile(fake.argsFile, "utf8")).trim().split("\n"),
    ["research", "package", "--ecosystem", "nuget", "--package", "Braintree.Payments.SDK", "--search-root", fake.root, "--version", "4.2.1", "--json"],
  );
});
