import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { scanUrl } from "../src/scanner.js";
import { writeFixPack } from "../src/fixpack.js";
import { analyzeLogs } from "../src/logs.js";

test("writeFixPack exports reviewable files for missing llms, jsonld, and weak OpenAPI", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-fixpack-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    const send = (status, body, type = "text/plain") => {
      response.writeHead(status, { "content-type": type });
      response.end(body);
    };
    if (path === "/") return send(200, home(), "text/html");
    if (path === "/openapi.json") return send(200, JSON.stringify(openapi()), "application/json");
    if (path === "/robots.txt") return send(200, "User-agent: *\nAllow: /\n");
    if (path === "/sitemap.xml") return send(200, "<urlset><url><loc>/</loc></url></urlset>", "application/xml");
    if (path === "/llms.txt") return send(404, "missing");
    return send(404, "missing");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const mcpPath = join(dir, "mcp.json");
  await writeFile(mcpPath, JSON.stringify({ protocolVersion: "2025-06-18", tools: [{ name: "delete_workspace", description: "Delete workspace data" }] }));
  const scan = await scanUrl(`${baseUrl}/`, { openapi: `${baseUrl}/openapi.json`, mcp: mcpPath });
  const logReport = analyzeLogs('203.0.113.1 - - [21/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1200 "-" "GPTBot/1.0"\n');
  const manifest = await writeFixPack(join(dir, "fix-pack"), { scan, logReport });

  assert.deepEqual(manifest.files.sort(), [
    "agent-auth-template.json",
    "agent.json",
    "README.md",
    "llms.txt",
    "openapi-patches.json",
    "problem-details-example.json",
    "schema-org.jsonld",
    "mcp-security-checklist.md",
  ].sort());

  const llms = await readFile(join(dir, "fix-pack", "llms.txt"), "utf8");
  const readme = await readFile(join(dir, "fix-pack", "README.md"), "utf8");
  const mcpChecklist = await readFile(join(dir, "fix-pack", "mcp-security-checklist.md"), "utf8");
  const agentAuth = JSON.parse(await readFile(join(dir, "fix-pack", "agent-auth-template.json"), "utf8"));
  const agentCard = JSON.parse(await readFile(join(dir, "fix-pack", "agent.json"), "utf8"));
  const jsonld = JSON.parse(await readFile(join(dir, "fix-pack", "schema-org.jsonld"), "utf8"));
  const patches = JSON.parse(await readFile(join(dir, "fix-pack", "openapi-patches.json"), "utf8"));
  const problem = JSON.parse(await readFile(join(dir, "fix-pack", "problem-details-example.json"), "utf8"));

  assert.match(llms, /Agent Contract OS creates contracts/i);
  assert.match(readme, /Cost at scale/);
  assert.match(readme, /Estimated monthly Sonnet input cost/);
  assert.match(mcpChecklist, /NSA U\/OO\/6030316-26/);
  assert.match(mcpChecklist, /delete_workspace/);
  assert.ok(agentAuth.agent_auth.supported_schemes.includes("ap2_vc"));
  assert.equal(agentCard.capabilities[0].id, "answer_product_questions");
  assert.equal(jsonld["@type"], "SoftwareApplication");
  assert.ok(patches.patches.some((patch) => patch.op === "add_examples"));
  assert.ok(patches.patches.some((patch) => patch.op === "add_error_responses"));
  assert.ok(patches.patches.some((patch) => patch.op === "add_security_schemes"));
  assert.equal(problem.type, "https://example.com/problems/agent-contract-error");
});

function home() {
  return `<!doctype html><html><body>
    <h1>Agent Contract OS</h1>
    <p>Agent Contract OS creates contracts for autonomous agents so websites can publish docs, API expectations, and policy boundaries.</p>
  </body></html>`;
}

function openapi() {
  return {
    openapi: "3.1.0",
    info: { title: "Weak API", version: "1.0.0" },
    paths: {
      "/contracts": {
        get: {
          responses: {
            200: { description: "OK" },
          },
        },
      },
    },
  };
}
