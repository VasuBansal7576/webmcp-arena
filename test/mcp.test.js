import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { analyzeMcpManifest } from "../src/mcp.js";
import { scanUrl } from "../src/scanner.js";

test("analyzeMcpManifest flags dangerous write/payment/exec tools", async () => {
  const manifest = {
    name: "billing-mcp",
    tools: [
      { name: "list_invoices", description: "Read invoices" },
      { name: "delete_customer", description: "Deletes a customer account" },
      { name: "charge_card", description: "Charges a payment method" },
      { name: "run_shell", description: "Execute a shell command" },
    ],
  };
  const result = analyzeMcpManifest(manifest, "fixture");
  assert.equal(result.discovered, true);
  assert.equal(result.tool_count, 4);
  assert.deepEqual(result.dangerous_tools.map((tool) => tool.name).sort(), ["charge_card", "delete_customer", "run_shell"].sort());
});

test("scanUrl includes MCP checks and lowers readiness for dangerous tools", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-mcp-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const server = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    if (path === "/") {
      response.writeHead(200, { "content-type": "text/html" });
      response.end("<html><body><h1>Agent Contract</h1><p>Readable content for agents and developers.</p></body></html>");
      return;
    }
    response.writeHead(404, { "content-type": "text/plain" });
    response.end("missing");
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const mcpPath = join(dir, "mcp.json");
  await writeFile(mcpPath, JSON.stringify({
    name: "dangerous-mcp",
    tools: [{ name: "delete_workspace", description: "Delete workspace data" }],
  }));

  const result = await scanUrl(`http://127.0.0.1:${server.address().port}/`, {
    mcp: mcpPath,
    linkLimit: 0,
  });

  assert.equal(result.mcp.discovered, true);
  assert.equal(result.checks.find((check) => check.id === "mcp_discovery").pass, true);
  assert.equal(result.checks.find((check) => check.id === "mcp_dangerous_tools").pass, false);
  assert.ok(result.readiness.score < 100);
});
