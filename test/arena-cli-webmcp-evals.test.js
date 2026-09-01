import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runArenaCli } from "../src/arena-cli.js";

test("arena eval bridges a current webmcp-evals report to a verified behavioral proof", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-webmcp-evals-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const paths = await writeInputs(directory);

  const result = await runArenaCli([
    "eval",
    "--evals", paths.evals,
    "--results", paths.results,
    "--tools", paths.tools,
    "--observations", paths.observations,
    "--proof", paths.proof,
    "--format", "json",
  ], {
    async verifyProof(candidate) {
      assert.deepEqual(candidate, { proof: "signed" });
      return { valid: true, verdict: "pass", payloadHash: "P".repeat(43) };
    },
  });

  assert.equal(result.exitCode, 0, result.stdout || result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.kind, "arena.webmcp_eval_audit");
  assert.equal(report.verdict, "pass");
  assert.equal(report.layers.selection.status, "pass");
  assert.equal(report.layers.guidance.status, "pass");
  assert.equal(report.layers.behavior.status, "pass");
  assert.equal(report.source.format, "googlechromelabs.webmcp-evals");
});

test("arena eval stays inconclusive without a proof and exposes the command in help", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-webmcp-evals-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const paths = await writeInputs(directory);
  const result = await runArenaCli([
    "eval",
    "--evals", paths.evals,
    "--results", paths.results,
    "--tools", paths.tools,
    "--observations", paths.observations,
  ]);
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 2);
  assert.equal(report.verdict, "inconclusive");
  assert.equal(report.layers.behavior.status, "inconclusive");
  assert.match((await runArenaCli(["--help"])).stdout, /arena eval/);
});

test("arena eval refuses unreadable or malformed imported JSON at the CLI boundary", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-webmcp-evals-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const malformed = join(directory, "malformed.json");
  await writeFile(malformed, "not-json");
  const result = await runArenaCli(["eval", "--evals", malformed, "--results", malformed]);
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 2);
  assert.match(report.error, /evals file is not readable JSON/i);
});

async function writeInputs(directory) {
  const evals = join(directory, "evals.json");
  const results = join(directory, "results.json");
  const tools = join(directory, "tools.json");
  const observations = join(directory, "observations.json");
  const proof = join(directory, "proof.json");
  const suite = [{
    name: "Search",
    messages: [{ role: "user", type: "message", content: "Find a jacket." }],
    expectedCall: [{ functionName: "search", arguments: { query: "jacket" } }],
  }];
  const upstream = {
    config: { url: "https://shop.example", evalsFile: "evals.json" },
    results: {
      testCount: 1,
      passCount: 1,
      failCount: 0,
      errorCount: 0,
      results: [{
        test: { name: "Search", messages: suite[0].messages, expectedCall: suite[0].expectedCall },
        response: { functionName: "search", args: { query: "jacket" }, result: { items: [] } },
        outcome: "pass",
        runIndex: 1,
        stepIndex: 1,
      }],
    },
  };
  const toolDefinitions = [{
    name: "search",
    description: "Search the product catalog.",
    inputSchema: {
      type: "object",
      properties: { query: { type: "string", description: "Product search text." } },
    },
    annotations: { readOnlyHint: true, untrustedContentHint: false },
    exposedTo: ["https://shop.example"],
  }];
  const runtime = {
    tokenLimit: { configured: true, maxInputTokens: 4096 },
    cancellation: { tested: true, requested: true, outcome: "cancelled", sideEffectsAfterCancel: false },
    executions: [{
      toolName: "search",
      outcome: "completed",
      consequential: false,
      confirmationRequired: false,
      confirmationObserved: false,
      influencedByUntrustedContent: false,
      effects: [],
      output: { items: [] },
      outputTrusted: true,
    }],
  };
  await Promise.all([
    writeFile(evals, JSON.stringify(suite)),
    writeFile(results, JSON.stringify(upstream)),
    writeFile(tools, JSON.stringify(toolDefinitions)),
    writeFile(observations, JSON.stringify(runtime)),
    writeFile(proof, JSON.stringify({ proof: "signed" })),
  ]);
  assert.equal(JSON.parse(await readFile(evals, "utf8")).length, 1);
  return { evals, results, tools, observations, proof };
}
