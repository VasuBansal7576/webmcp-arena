import assert from "node:assert/strict";
import test from "node:test";

import { createWebMcpEvalBridge } from "../src/webmcp-evals.js";

const safeTools = [{
  name: "searchProducts",
  description: "Find products that match a query.",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string", description: "Product search text." },
    },
    required: ["query"],
  },
  annotations: { readOnlyHint: true, untrustedContentHint: false },
  exposedTo: ["https://shop.example"],
}];

const safeObservations = {
  tokenLimit: { configured: true, maxInputTokens: 4096 },
  cancellation: {
    tested: true,
    requested: true,
    outcome: "cancelled",
    sideEffectsAfterCancel: false,
  },
  executions: [{
    toolName: "searchProducts",
    outcome: "completed",
    consequential: false,
    confirmationRequired: false,
    confirmationObserved: false,
    influencedByUntrustedContent: false,
    effects: [],
    output: { items: ["jacket"] },
    outputTrusted: true,
  }],
};

test("Arena independently recomputes current webmcp-evals trajectories and ignores imported pass counts", async () => {
  const suite = [{
    name: "Find a jacket",
    messages: [{ role: "user", type: "message", content: "Find a leather jacket." }],
    expectedCall: [{
      functionName: "searchProducts",
      arguments: { query: { $contains: "jacket" } },
      result: { items: [{ $type: "string" }] },
    }],
  }];
  const upstreamReport = reportFor({
    name: "Find a jacket",
    response: {
      functionName: "searchProducts",
      args: { query: "leather jacket", page: 1 },
      result: { items: ["p3"], total: 1 },
    },
    importedOutcome: "fail",
    importedPassCount: 0,
  });
  const bridge = createWebMcpEvalBridge({
    verifyProof: async () => ({ valid: true, verdict: "pass", payloadHash: "P".repeat(43) }),
  });

  const audit = await bridge.audit({
    suite,
    upstreamReport,
    tools: safeTools,
    observations: safeObservations,
    behavioralProof: { signed: true },
  });

  assert.equal(audit.verdict, "pass");
  assert.equal(audit.layers.selection.status, "pass");
  assert.equal(audit.layers.selection.passCount, 1);
  assert.equal(audit.layers.selection.cases[0].runs[0].steps[0].status, "pass");
  assert.equal(audit.layers.behavior.status, "pass");
  assert.equal(audit.source.trust, "untrusted_import_recomputed");
});

test("Arena supports nested ordered, unordered, optional, and unconstrained current eval nodes", async () => {
  const suite = [{
    name: "Build and checkout",
    messages: [{ role: "user", type: "message", content: "Build my cart." }],
    expectedCall: [{
      ordered: [
        { functionName: "search", arguments: { query: { $pattern: "(?i)jacket" } } },
        { unordered: [
          { functionName: "filter", arguments: { max: { $lte: 200 } } },
          { functionName: "summarize", optional: true },
          { functionName: "select", arguments: null },
        ] },
        { functionName: "checkout", arguments: {} },
      ],
    }],
  }];
  const responses = [
    { functionName: "search", args: { query: "Leather Jacket" } },
    { functionName: "select", args: { productId: "p3" } },
    { functionName: "filter", args: { max: 150 } },
    { functionName: "checkout", args: { modelAdded: true } },
  ];
  const bridge = createWebMcpEvalBridge({
    verifyProof: async () => ({ valid: true, verdict: "pass", payloadHash: "P".repeat(43) }),
  });
  const audit = await bridge.audit({
    suite,
    upstreamReport: multiStepReport("Build and checkout", responses),
    tools: safeTools,
    observations: safeObservations,
    behavioralProof: {},
  });

  assert.equal(audit.layers.selection.status, "pass");
  assert.equal(audit.layers.selection.cases[0].runs[0].actualCount, 4);
});

test("Arena fails a wrong imported call even when the upstream report claims every step passed", async () => {
  const suite = [{
    name: "Find a jacket",
    messages: [{ role: "user", type: "message", content: "Find a jacket." }],
    expectedCall: [{ functionName: "searchProducts", arguments: { query: "jacket" } }],
  }];
  const upstreamReport = reportFor({
    name: "Find a jacket",
    response: { functionName: "checkout", args: {} },
    importedOutcome: "pass",
    importedPassCount: 999,
  });
  const bridge = createWebMcpEvalBridge({
    verifyProof: async () => ({ valid: true, verdict: "pass", payloadHash: "P".repeat(43) }),
  });

  const audit = await bridge.audit({
    suite,
    upstreamReport,
    tools: safeTools,
    observations: safeObservations,
    behavioralProof: {},
  });

  assert.equal(audit.verdict, "fail");
  assert.equal(audit.layers.selection.status, "fail");
  assert.ok(audit.findings.some((finding) => finding.code === "tool_selection_mismatch"));
});

test("Arena rejects ambiguous suite identities and malformed constraint nodes at the import boundary", async () => {
  const bridge = createWebMcpEvalBridge({ verifyProof: async () => ({ valid: true, verdict: "pass" }) });
  const duplicate = {
    name: "Duplicate",
    messages: [{ role: "user", type: "message", content: "One" }],
    expectedCall: [],
  };
  await assert.rejects(
    bridge.audit({ suite: [duplicate, duplicate], upstreamReport: { results: { results: [] } } }),
    /unique case identity/i,
  );
  await assert.rejects(
    bridge.audit({
      suite: [{
        name: "Bad constraint",
        messages: [{ role: "user", type: "message", content: "One" }],
        expectedCall: [{ functionName: "search", arguments: { query: { $unknown: true } } }],
      }],
      upstreamReport: { results: { results: [] } },
    }),
    /unsupported constraint/i,
  );
});

test("Arena marks the behavior layer inconclusive without a verified Arena proof", async () => {
  const suite = [{
    name: "No call",
    messages: [{ role: "user", type: "message", content: "Say hello." }],
    expectedCall: null,
  }];
  const bridge = createWebMcpEvalBridge({ verifyProof: async () => ({ valid: true, verdict: "pass" }) });
  const audit = await bridge.audit({
    suite,
    upstreamReport: reportFor({ name: "No call", response: null }),
    tools: safeTools,
    observations: safeObservations,
  });

  assert.equal(audit.verdict, "inconclusive");
  assert.equal(audit.layers.behavior.status, "inconclusive");
  assert.ok(audit.inconclusive_reasons.includes("behavioral_proof_missing"));
});

function reportFor({ name, response, importedOutcome = "pass", importedPassCount = 1 }) {
  return {
    config: { url: "https://shop.example", evalsFile: "evals.json" },
    results: {
      testCount: 1,
      passCount: importedPassCount,
      failCount: 0,
      errorCount: 0,
      results: [{
        test: {
          name,
          messages: [{ role: "user", type: "message", content: name }],
          expectedCall: null,
        },
        response,
        outcome: importedOutcome,
        runIndex: 1,
        stepIndex: 1,
      }],
    },
  };
}

function multiStepReport(name, responses) {
  const rows = responses.map((response, index) => ({
    test: {
      name,
      messages: [{ role: "user", type: "message", content: name }],
      expectedCall: null,
    },
    response,
    outcome: "pass",
    runIndex: 1,
    stepIndex: index + 1,
  }));
  return {
    config: { url: "https://shop.example", evalsFile: "evals.json" },
    results: {
      testCount: 1,
      passCount: rows.length,
      failCount: 0,
      errorCount: 0,
      results: rows,
    },
  };
}
