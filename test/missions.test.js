import { createServer } from "node:http";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { runSyntheticMissions } from "../src/missions.js";

const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

test("runSyntheticMissions executes phase-one missions in a real browser and reuses cache", async (t) => {
  const cacheDir = await mkdtemp(join(tmpdir(), "agent-contract-missions-"));
  const evidenceDir = join(cacheDir, "evidence");
  t.after(() => rm(cacheDir, { recursive: true, force: true }));

  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    const send = (status, body) => {
      response.writeHead(status, { "content-type": "text/html" });
      response.end(body);
    };
    if (path === "/") return send(200, home());
    if (path === "/pricing") return send(200, pricing());
    if (path === "/docs/quickstart") return send(200, quickstart());
    return send(404, "missing");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  const baseUrl = `http://127.0.0.1:${server.address().port}/`;
  const first = await runSyntheticMissions(baseUrl, {
    browserExecutablePath: chromePath,
    cacheDir,
    evidenceDir,
    contentHash: "stable-test-page",
  });

  assert.equal(first.tested, 3);
  assert.equal(first.failed, 0);
  const pricingResult = first.results.find((item) => item.mission === "find_pricing");
  assert.equal(first.results.find((item) => item.mission === "understand_company").token_strategy, "a11y_tree");
  assert.equal(pricingResult.token_strategy, "prune4web");
  assert.deepEqual(pricingResult.selector_program, [
    "h1,h2,h3,p,li,section,article,tr,td,th,a,button,[role='button'],[role='link']",
    "text~=(free|pricing|price|plan|startup|enterprise|solo|$)",
  ]);
  assert.ok(pricingResult.evidence.some((item) => item.type === "prune4web" && item.tokens < 50));
  assert.equal(pricingResult.status, "passed");
  assert.match(pricingResult.summary, /Startup \$49/i);
  assert.match(first.results.find((item) => item.mission === "find_api_quickstart").summary, /GET \/v1\/contracts/i);
  assert.equal(first.results.some((item) => item.cached), false);
  assert.equal(first.results.every((item) => item.screenshot_path?.endsWith(".png")), true);
  await Promise.all(first.results.map((item) => access(item.screenshot_path)));

  await new Promise((resolve) => server.close(() => resolve()));
  const second = await runSyntheticMissions(baseUrl, {
    browserExecutablePath: chromePath,
    cacheDir,
    evidenceDir,
    contentHash: "stable-test-page",
  });

  assert.equal(second.failed, 0);
  assert.equal(second.results.every((item) => item.cached), true);
});

test("runSyntheticMissions executes opt-in standard missions", async (t) => {
  const cacheDir = await mkdtemp(join(tmpdir(), "agent-contract-standard-missions-"));
  t.after(() => rm(cacheDir, { recursive: true, force: true }));

  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    const send = (status, body, type = "text/html") => {
      response.writeHead(status, { "content-type": type });
      response.end(body);
    };
    if (path === "/") return send(200, home());
    if (path === "/docs/quickstart") return send(200, quickstart());
    if (path === "/legal/refund") return send(200, refund());
    if (path === "/.well-known/mcp.json") return send(200, JSON.stringify({ tools: [{ name: "create_contract" }, { name: "list_contracts" }] }), "application/json");
    return send(404, "missing");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  const result = await runSyntheticMissions(`http://127.0.0.1:${server.address().port}/`, {
    browserExecutablePath: chromePath,
    cacheDir,
    contentHash: "standard-test-page",
    missionIds: ["create_first_api_request", "find_refund_policy", "use_mcp_tool_if_available"],
  });

  assert.equal(result.tested, 3);
  assert.equal(result.failed, 0);
  assert.match(result.results.find((item) => item.mission === "create_first_api_request").summary, /GET \/v1\/contracts/i);
  assert.match(result.results.find((item) => item.mission === "find_refund_policy").summary, /refund/i);
  assert.match(result.results.find((item) => item.mission === "use_mcp_tool_if_available").summary, /create_contract/);
});

test("runSyntheticMissions rejects unknown mission ids", async (t) => {
  const cacheDir = await mkdtemp(join(tmpdir(), "agent-contract-unknown-mission-"));
  t.after(() => rm(cacheDir, { recursive: true, force: true }));

  await assert.rejects(
    runSyntheticMissions("https://example.test", {
      cacheDir,
      missionIds: ["find_pricing", "does_not_exist"],
    }),
    /Unknown mission id\(s\): does_not_exist/,
  );
});

function home() {
  return `<!doctype html>
<html><body>
  <h1>Agent Contract OS</h1>
  <p>Agent Contract OS helps engineering teams publish machine-readable contracts and CI gates for autonomous web agents.</p>
  <a href="/pricing">Pricing</a>
  <a href="/docs/quickstart">API quickstart</a>
  <a href="/legal/refund">Refund policy</a>
</body></html>`;
}

function pricing() {
  return `<!doctype html>
<html><body>
  <h1>Pricing</h1>
  <section>Solo Free</section>
  <section>Startup $49 per repo</section>
  <section>Enterprise $30000 per year</section>
</body></html>`;
}

function quickstart() {
  return `<!doctype html>
<html><body>
  <h1>API Quickstart</h1>
  <p>Make your first request with GET /v1/contracts using a Bearer token.</p>
  <code>curl -H "Authorization: Bearer $TOKEN" https://api.example.test/v1/contracts</code>
</body></html>`;
}

function refund() {
  return `<!doctype html>
<html><body>
  <h1>Refund policy</h1>
  <p>Customers can cancel any monthly plan and request a refund within 14 days of purchase.</p>
</body></html>`;
}
