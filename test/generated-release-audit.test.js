import assert from "node:assert/strict";
import test from "node:test";

import {
  CHECKOUT_WEBMCP_TOOL,
  createCheckoutAuditAdapter,
} from "../src/checkout-audit-adapter.js";
import { CHECKOUT_CART_ID } from "../src/checkout-fixture.js";
import { createGeneratedReleaseAuditor, hashGeneratedRelease } from "../src/generated-release-audit.js";
import { hashWebMcpToolDefinition } from "../src/webmcp-tool-definition.js";

const TARGET = "arena-owned://checkout/?version=vulnerable";
const AGENT = "chatgpt-browser-agent";

test("a generated release audit catches a delayed effect hidden behind a read-only tool", async () => {
  let approve;
  const auditor = createGeneratedReleaseAuditor({
    adapter: createCheckoutAuditAdapter({
      chargeDelayMs: 75,
      settlementPollIntervalMs: 10,
      settlementTimeoutMs: 1_500,
    }),
    capability: () => "release_audit_capability_000000000000000000000001",
    onApprovalRequired(input) {
      approve = input.approve;
    },
  });
  const prepared = await auditor.prepare({
    release: generatedRelease(),
    target: TARGET,
    principalRef: "fixture:principal_demo_buyer",
    agent: {
      id: AGENT,
      toolName: "preview_checkout",
      arguments: { cartId: CHECKOUT_CART_ID },
    },
  });

  assert.equal(prepared.state, "awaiting_approval");
  assert.equal(prepared.review.release.id, "example.checkout-generator");
  assert.equal(prepared.review.release.version, "2026.08.31");
  assert.equal(prepared.review.release.artifact.algorithm, "sha256");
  assert.match(prepared.review.release.hash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(prepared.review.intent.targetHash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(prepared.review.intent.agentHash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(prepared.review.intent.principalLabel, "Demo buyer account");
  assert.match(prepared.review.intent.principalHash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(prepared.review.intent.toolDefinitionHash, hashWebMcpToolDefinition(CHECKOUT_WEBMCP_TOOL));
  assert.match(prepared.review.intent.toolHash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(prepared.review.intent.argumentsHash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(typeof approve, "function");

  const authorization = approve({ humanId: "human_vasu" });
  assert.equal(authorization.commitments.targetHash, prepared.review.intent.targetHash);
  assert.equal(authorization.commitments.principalHash, prepared.review.intent.principalHash);
  const result = await auditor.run({
    auditId: prepared.auditId,
    capability: authorization.capability,
    agent: {
      id: AGENT,
      toolName: "preview_checkout",
      arguments: { cartId: CHECKOUT_CART_ID },
    },
  });

  assert.equal(result.state, "completed");
  assert.equal(result.verdict, "fail");
  assert.equal(result.release.hash, prepared.review.release.hash);
  assert.equal(result.selectedToolBundle.targetHash, prepared.review.intent.targetHash);
  assert.equal(result.selectedToolBundle.principalHash, prepared.review.intent.principalHash);
  assert.equal(result.authorization.status, "consumed");
  assert.equal(result.findings.some(({ code }) => code === "unexpected_consequential_effect"), true);
  assert.equal(result.selectedToolBundle.events.some(({ route, payload }) =>
    route === "agent" && payload.kind === "money" && payload.amount === 149), true);
  assert.equal(result.selectedToolBundle.events.some(({ route, payload }) =>
    route === "agent" && payload.kind === "effect_settlement" && payload.complete === true), true);
});

test("a generated release authorization rejects the wrong agent, argument substitution, and replay", async () => {
  let approve;
  const auditor = createGeneratedReleaseAuditor({
    adapter: createCheckoutAuditAdapter(),
    capability: () => "release_audit_capability_000000000000000000000002",
    onApprovalRequired(input) {
      approve = input.approve;
    },
  });
  const prepared = await auditor.prepare({
    release: generatedRelease(),
    target: TARGET,
    principalRef: "fixture:principal_demo_buyer",
    agent: exactIntent(),
  });
  const authorization = approve({ humanId: "human_vasu" });

  const wrongAgent = await auditor.run({
    auditId: prepared.auditId,
    capability: authorization.capability,
    agent: { ...exactIntent(), id: "different-agent" },
  });
  assert.equal(wrongAgent.reason, "agent_identity_mismatch");
  assert.equal(wrongAgent.auditId, prepared.auditId);
  assert.equal(wrongAgent.finding.expectedCommitment, prepared.review.intent.agentHash);
  assert.match(wrongAgent.finding.actualCommitment, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(wrongAgent.finding.actualCommitment, wrongAgent.finding.expectedCommitment);

  const changedArguments = await auditor.run({
    auditId: prepared.auditId,
    capability: authorization.capability,
    agent: {
      ...exactIntent(),
      arguments: { cartId: "cart_substituted_after_approval" },
    },
  });
  assert.equal(changedArguments.reason, "argument_substitution");
  assert.equal(changedArguments.finding.expectedCommitment, prepared.review.intent.argumentsHash);
  assert.match(changedArguments.finding.actualCommitment, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(changedArguments.finding.actualCommitment, changedArguments.finding.expectedCommitment);

  const completed = await auditor.run({
    auditId: prepared.auditId,
    capability: authorization.capability,
    agent: exactIntent(),
  });
  assert.equal(completed.state, "completed");

  const replay = await auditor.run({
    auditId: prepared.auditId,
    capability: authorization.capability,
    agent: exactIntent(),
  });
  assert.equal(replay.state, "denied");
  assert.equal(replay.reason, "authorization_replayed");
  assert.equal(replay.auditId, prepared.auditId);
});

test("preparation rejects a generated release whose tool changed after the target adapter review", async () => {
  let approvalRequests = 0;
  const auditor = createGeneratedReleaseAuditor({
    adapter: createCheckoutAuditAdapter(),
    onApprovalRequired() {
      approvalRequests += 1;
    },
  });
  const changedTool = {
    ...CHECKOUT_WEBMCP_TOOL,
    description: "Preview the checkout and schedule a charge.",
  };

  await assert.rejects(
    () => auditor.prepare({
      release: { ...generatedRelease(), tools: [changedTool] },
      target: TARGET,
      principalRef: "fixture:principal_demo_buyer",
      agent: exactIntent(),
    }),
    (error) => {
      assert.equal(error.code, "tool_definition_mismatch");
      assert.equal(error.expectedCommitment, hashWebMcpToolDefinition(CHECKOUT_WEBMCP_TOOL));
      assert.equal(error.actualCommitment, hashWebMcpToolDefinition(changedTool));
      return true;
    },
  );
  assert.equal(approvalRequests, 0);
});

test("one selected-tool audit cannot certify an otherwise unaudited multi-tool release", async () => {
  let approve;
  const auditor = createGeneratedReleaseAuditor({
    adapter: createCheckoutAuditAdapter(),
    capability: () => "release_audit_capability_000000000000000000000003",
    onApprovalRequired(input) {
      approve = input.approve;
    },
  });
  const unauditedTool = {
    name: "place_order",
    title: "Place order",
    description: "Place and charge an order.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: false, untrustedContentHint: false },
  };
  const prepared = await auditor.prepare({
    release: { ...generatedRelease(), tools: [CHECKOUT_WEBMCP_TOOL, unauditedTool] },
    target: "arena-owned://checkout/?version=fixed",
    principalRef: "fixture:principal_demo_buyer",
    agent: exactIntent(),
  });
  const authorization = approve({ humanId: "human_vasu" });
  const result = await auditor.run({
    auditId: prepared.auditId,
    capability: authorization.capability,
    agent: exactIntent(),
  });

  assert.equal(result.selectedToolVerdict, "pass");
  assert.equal(result.verdict, "inconclusive");
  assert.equal(result.bundle, undefined);
  assert.equal(result.selectedToolBundle.verdict, "pass");
  assert.deepEqual(result.coverage, {
    auditedTools: ["preview_checkout"],
    totalTools: 2,
    complete: false,
  });
  assert.equal(result.findings.some(({ code }) => code === "release_coverage_incomplete"), true);

  let approveUnsafe;
  const unsafeAuditor = createGeneratedReleaseAuditor({
    adapter: createCheckoutAuditAdapter(),
    capability: () => "release_audit_capability_000000000000000000000004",
    onApprovalRequired(input) {
      approveUnsafe = input.approve;
    },
  });
  const unsafePrepared = await unsafeAuditor.prepare({
    release: { ...generatedRelease(), tools: [CHECKOUT_WEBMCP_TOOL, unauditedTool] },
    target: TARGET,
    principalRef: "fixture:principal_demo_buyer",
    agent: exactIntent(),
  });
  const unsafeAuthorization = approveUnsafe({ humanId: "human_vasu" });
  const unsafeResult = await unsafeAuditor.run({
    auditId: unsafePrepared.auditId,
    capability: unsafeAuthorization.capability,
    agent: exactIntent(),
  });
  assert.equal(unsafeResult.selectedToolVerdict, "fail");
  assert.equal(unsafeResult.verdict, "fail");
});

test("the owned adapter, not the caller, resolves the human-readable principal scope", async () => {
  const auditor = createGeneratedReleaseAuditor({
    adapter: createCheckoutAuditAdapter(),
    onApprovalRequired() {},
  });
  const input = {
    release: generatedRelease(),
    target: TARGET,
    principalRef: "fixture:principal_demo_buyer",
    agent: exactIntent(),
  };

  const prepared = await auditor.prepare(input);
  assert.equal(prepared.review.intent.principalLabel, "Demo buyer account");
  await assert.rejects(
    () => auditor.prepare({ ...input, principalLabel: "Victim account" }),
    /unsupported generated release audit field: principalLabel/,
  );
  await assert.rejects(
    () => auditor.prepare({ ...input, principalRef: "fixture:principal_other_buyer" }),
    /authorized demo buyer account/,
  );
});

test("the release hash binds a required immutable implementation artifact", async () => {
  const release = generatedRelease();
  const changedArtifact = {
    ...release,
    artifact: { ...release.artifact, digest: "B".repeat(43) },
  };

  assert.notEqual(hashGeneratedRelease(release), hashGeneratedRelease(changedArtifact));
  assert.throws(
    () => hashGeneratedRelease({ ...release, artifact: undefined }),
    /generated release artifact/,
  );
});

test("generated releases enforce the current WebMCP name and annotation grammar", () => {
  const release = generatedRelease();
  assert.throws(
    () => hashGeneratedRelease({
      ...release,
      tools: [{ ...CHECKOUT_WEBMCP_TOOL, name: "invalid:tool" }],
    }),
    /tool name is invalid/,
  );
  assert.throws(
    () => hashGeneratedRelease({
      ...release,
      tools: [{ ...CHECKOUT_WEBMCP_TOOL, name: "a".repeat(129) }],
    }),
    /tool name is invalid/,
  );
  assert.throws(
    () => hashGeneratedRelease({
      ...release,
      tools: [{
        ...CHECKOUT_WEBMCP_TOOL,
        annotations: { readOnlyHint: true, destructiveHint: false },
      }],
    }),
    /unsupported generated WebMCP tool annotations field: destructiveHint/,
  );
  assert.throws(
    () => hashGeneratedRelease({
      ...release,
      tools: [{ ...CHECKOUT_WEBMCP_TOOL, annotations: { readOnlyHint: "yes" } }],
    }),
    /readOnlyHint must be a boolean/,
  );
  assert.doesNotThrow(() => hashGeneratedRelease({
    ...release,
    tools: [{
      ...CHECKOUT_WEBMCP_TOOL,
      name: "valid.tool-name_1",
      annotations: { readOnlyHint: true, untrustedContentHint: false },
    }],
  }));
});

function generatedRelease() {
  return {
    id: "example.checkout-generator",
    version: "2026.08.31",
    generator: "example-generator",
    artifact: {
      algorithm: "sha256",
      digest: "A".repeat(43),
      subject: "example.checkout.implementation:v1",
    },
    tools: [CHECKOUT_WEBMCP_TOOL],
  };
}

function exactIntent() {
  return {
    id: AGENT,
    toolName: "preview_checkout",
    arguments: { cartId: CHECKOUT_CART_ID },
  };
}
