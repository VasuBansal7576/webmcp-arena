import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { runMonitor } from "../src/monitor.js";

const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

test("runMonitor persists hashes, skips unchanged pages, and selects affected missions", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-monitor-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  let pricingVersion = 1;
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    const send = (status, body) => {
      response.writeHead(status, { "content-type": "text/html" });
      response.end(body);
    };
    if (path === "/") return send(200, home());
    if (path === "/pricing") return send(200, pricing(pricingVersion));
    if (path === "/docs/quickstart") return send(200, quickstart());
    if (path === "/robots.txt") return send(200, "User-agent: *\nAllow: /\n");
    if (path === "/sitemap.xml") return send(200, "<urlset><url><loc>/</loc></url></urlset>");
    if (path === "/llms.txt") return send(200, "# Agent Contract OS\n");
    return send(404, "missing");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const common = {
    statePath: join(dir, "state.json"),
    contractDir: join(dir, ".agent"),
    browserExecutablePath: chromePath,
    missions: true,
  };

  const first = await runMonitor({ urls: [`${baseUrl}/`], ...common });
  assert.equal(first.changed.length, 1);
  assert.equal(first.unchanged.length, 0);
  assert.equal(first.missionReport.tested, 3);
  assert.deepEqual(first.selectedMissionIds, ["understand_company", "find_pricing", "find_api_quickstart"]);

  const second = await runMonitor({ urls: [`${baseUrl}/`], ...common });
  assert.equal(second.changed.length, 0);
  assert.equal(second.unchanged.length, 1);
  assert.equal(second.missionReport, null);

  await runMonitor({ urls: [`${baseUrl}/pricing`], ...common });
  pricingVersion = 2;
  const third = await runMonitor({ urls: [`${baseUrl}/pricing`], ...common });
  assert.equal(third.changed.length, 1);
  assert.deepEqual(third.selectedMissionIds, ["find_pricing"]);
  assert.equal(third.missionReport.tested, 1);
  assert.equal(third.missionReport.results[0].mission, "find_pricing");
});

test("runMonitor treats MCP tool description hash changes as changes", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-monitor-mcp-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const server = createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.end(home());
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));

  const mcpPath = join(dir, "mcp.json");
  const options = {
    urls: [`http://127.0.0.1:${server.address().port}/`],
    statePath: join(dir, "state.json"),
    scanOptions: { mcp: mcpPath },
  };

  await writeFile(mcpPath, JSON.stringify({ protocolVersion: "2025-06-18", tools: [{ name: "search", description: "Find docs" }] }));
  assert.equal((await runMonitor(options)).changed.length, 1);
  assert.equal((await runMonitor(options)).unchanged.length, 1);

  await writeFile(mcpPath, JSON.stringify({ protocolVersion: "2025-06-18", tools: [{ name: "search", description: "Find docs and pricing" }] }));
  const changed = await runMonitor(options);
  assert.equal(changed.changed.length, 1);
  assert.notEqual(changed.changed[0].previous_mcp_tool_description_hash, changed.changed[0].mcp_tool_description_hash);
});

function home() {
  return `<!doctype html><html><body>
    <h1>Agent Contract OS</h1>
    <p>Agent Contract OS publishes machine-readable contracts for autonomous web agents and validates them in CI.</p>
    <a href="/pricing">Pricing</a>
    <a href="/docs/quickstart">API quickstart</a>
  </body></html>`;
}

function pricing(version) {
  return `<!doctype html><html><body>
    <h1>Pricing v${version}</h1>
    <p>Startup $${version === 1 ? 49 : 79} per repo</p>
  </body></html>`;
}

function quickstart() {
  return `<!doctype html><html><body>
    <h1>API Quickstart</h1>
    <p>GET /v1/contracts</p>
  </body></html>`;
}
