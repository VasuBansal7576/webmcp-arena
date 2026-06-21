import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { explainFixesWithLlm, writeLlmFixExplanation } from "../src/llmfix.js";

test("explainFixesWithLlm requires explicit provider configuration", async () => {
  await assert.rejects(
    () => explainFixesWithLlm({ findings: [] }, { apiKey: "", model: "" }),
    /requires --llm-api-key|OPENAI_API_KEY/,
  );
});

test("writeLlmFixExplanation calls a Responses-compatible endpoint and writes evidence", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-llmfix-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  let requestBody;
  let authHeader;
  const server = createServer((request, response) => {
    if (request.method !== "POST" || request.url !== "/responses") {
      response.writeHead(404);
      response.end("missing");
      return;
    }
    authHeader = request.headers.authorization;
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      requestBody = JSON.parse(body);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        id: "resp_test",
        output_text: "Prioritize llms.txt first because agents need a stable text surface before richer metadata.",
      }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));

  const result = await writeLlmFixExplanation(join(dir, "fix-explanation.md"), {
    findings: [
      { id: "llms_txt", severity: "high", message: "llms.txt missing" },
      { id: "json_ld", severity: "medium", message: "No JSON-LD/schema.org block found" },
    ],
    fixPackFiles: ["llms.txt", "schema-org.jsonld"],
  }, {
    endpoint: `http://127.0.0.1:${server.address().port}`,
    apiKey: "test-key",
    model: "gpt-test",
  });

  assert.equal(authHeader, "Bearer test-key");
  assert.equal(requestBody.model, "gpt-test");
  assert.equal(requestBody.store, false);
  assert.match(JSON.stringify(requestBody.input), /llms\.txt missing/);
  assert.equal(result.response_id, "resp_test");
  assert.match(await readFile(join(dir, "fix-explanation.md"), "utf8"), /Prioritize llms\.txt first/);
});
