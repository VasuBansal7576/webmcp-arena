import assert from "node:assert/strict";
import test from "node:test";

import {
  createWebMcpInvocationReceipt,
  finalizeWebMcpInvocationReceipt,
  verifyWebMcpInvocationReceipt,
} from "../src/webmcp-invocation.js";

const review = Object.freeze({
  toolName: "preview_checkout",
  toolDefinitionHash: "D".repeat(43),
  argumentsHash: "A".repeat(43),
});
const approval = Object.freeze({ sessionCommitment: "S".repeat(43) });
const auditId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

test("a callback receipt binds the reviewed invocation, page origin, and one-time lease", async () => {
  const prepared = await createWebMcpInvocationReceipt({
    auditId,
    review,
    approval,
    pageOrigin: "https://arena.example",
    invocationLease: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    invokedAt: "2026-08-31T12:00:00.000Z",
  });
  const settled = await finalizeWebMcpInvocationReceipt(prepared, {
    result: { state: "previewed", total: 149 },
    backendTraceRoot: "T".repeat(43),
    settledAt: "2026-08-31T12:00:00.650Z",
  });

  assert.deepEqual(await verifyWebMcpInvocationReceipt(settled, {
    auditId,
    review,
    approval,
    result: { state: "previewed", total: 149 },
    backendTraceRoot: "T".repeat(43),
  }), { valid: true });
  assert.equal(settled.channel, "registered_webmcp_callback");
  assert.notEqual(settled.invocationLeaseCommitment, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
  assert.equal(Object.values(settled).includes("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), false);
});

test("callback receipt verification fails closed for altered channel, intent, result, trace, and chronology", async (t) => {
  const prepared = await createWebMcpInvocationReceipt({
    auditId,
    review,
    approval,
    pageOrigin: "https://arena.example",
    invocationLease: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    invokedAt: "2026-08-31T12:00:00.000Z",
  });
  const result = { state: "previewed", total: 149 };
  const backendTraceRoot = "T".repeat(43);
  const settled = await finalizeWebMcpInvocationReceipt(prepared, {
    result,
    backendTraceRoot,
    settledAt: "2026-08-31T12:00:00.650Z",
  });
  const cases = [
    ["channel", (value) => { value.channel = "direct_http"; }],
    ["page origin", (value) => { value.pageOrigin = "https://evil.example"; }],
    ["tool", (value) => { value.toolName = "place_order"; }],
    ["tool definition", (value) => { value.toolDefinitionHash = "X".repeat(43); }],
    ["arguments", (value) => { value.argumentsHash = "X".repeat(43); }],
    ["lease", (value) => { value.invocationLeaseCommitment = "X".repeat(43); }],
    ["request", (value) => { value.requestHash = "X".repeat(43); }],
    ["result", (value) => { value.resultHash = "X".repeat(43); }],
    ["trace", (value) => { value.backendTraceRoot = "X".repeat(43); }],
    ["chronology", (value) => { value.settledAt = "2026-08-31T11:59:59.000Z"; }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const changed = structuredClone(settled);
      mutate(changed);
      const verification = await verifyWebMcpInvocationReceipt(changed, {
        auditId,
        review,
        approval,
        result,
        backendTraceRoot,
      });
      assert.equal(verification.valid, false);
      assert.equal(typeof verification.reason, "string");
    });
  }
});

test("receipt creation rejects non-origin URLs and malformed reviewed commitments", async () => {
  await assert.rejects(
    createWebMcpInvocationReceipt({
      auditId,
      review,
      approval,
      pageOrigin: "https://arena.example/path",
      invocationLease: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      invokedAt: "2026-08-31T12:00:00.000Z",
    }),
    /page origin/,
  );
  await assert.rejects(
    createWebMcpInvocationReceipt({
      auditId,
      review: { ...review, argumentsHash: "short" },
      approval,
      pageOrigin: "https://arena.example",
      invocationLease: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      invokedAt: "2026-08-31T12:00:00.000Z",
    }),
    /reviewed invocation/,
  );
});
