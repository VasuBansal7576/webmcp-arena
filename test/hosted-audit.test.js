import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, completeHostedAudit, createHostedAudit, publicHostedAudit } from "../src/hosted-audit.js";

const vulnerableId = "11111111-1111-4111-8111-111111111111";
const fixedId = "22222222-2222-4222-8222-222222222222";
const now = Date.parse("2026-08-30T10:00:00.000Z");
const privateApproval = Object.freeze({
  capabilityHash: "A".repeat(43),
  sessionHash: "B".repeat(43),
  nonceId: "nonce_hosted_test_01",
});

test("hosted audits accept only owned Checkout versions and bind the exact review material", async () => {
  await assert.rejects(() => createHostedAudit({ id: vulnerableId, version: "caller_recipe", privateApproval }), /version must be vulnerable or fixed/);
  const vulnerable = await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now });
  const fixed = await createHostedAudit({ id: fixedId, version: "fixed", privateApproval, now });

  assert.equal(vulnerable.state, "awaiting_approval");
  assert.equal(vulnerable.review.claimScope, "owned_fixture:checkout");
  assert.deepEqual(vulnerable.review.arguments, { cartId: "cart_checkout_demo_001" });
  assert.match(vulnerable.review.toolHash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(vulnerable.review.argumentsHash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(vulnerable.review.contractHash, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(vulnerable.review.targetHash, fixed.review.targetHash);
  assert.equal(publicHostedAudit(vulnerable).privateApproval, undefined);
  assert.deepEqual(vulnerable.result, null);
});

test("hosted vulnerable audit executes the owned route and observes its delayed charge", async () => {
  const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
  const result = await completeHostedAudit(record, { now: now + 2_000 });
  const money = result.display.agentEvents.find((event) => event.kind === "money");
  const settlement = result.display.agentEvents.find((event) => event.kind === "effect_settlement");

  assert.equal(result.verdict, "fail");
  assert.equal(money.amount, 149);
  assert.equal(money.currency, "USD");
  assert.equal(settlement.observedThrough, 1);
  assert.equal(result.display.settlement.complete, true);
  assert.equal(result.bundle.coverage.authoritativeComplete, true);
  assert.equal(result.verification.semanticValid, true);
  assert.equal(result.verification.hashValid, true);
  assert.equal(result.findings.some((finding) => finding.code === "unexpected_consequential_effect"), true);
  assert.equal(result.evidence.approval.reviewedContractHash, record.review.contractHash);
});

test("hosted fixed audit executes matching routes and preserves both audit layers", async () => {
  const record = approve(await createHostedAudit({ id: fixedId, version: "fixed", privateApproval, now }));
  const result = await completeHostedAudit(record, { now: now + 2_000 });

  assert.equal(result.verdict, "pass");
  assert.equal(result.bundle.routeParity.status, "pass");
  assert.equal(result.bundle.baselineSafety.status, "pass");
  assert.deepEqual(result.findings, []);
  assert.equal(
    canonicalJson(result.display.humanEvents.map(stripSequence)),
    canonicalJson(result.display.agentEvents.map(stripSequence)),
  );
});

test("execution fails closed without an approval receipt bound to target, tool, arguments, and contract", async () => {
  const record = await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now });
  await assert.rejects(() => completeHostedAudit(record), /approval receipt is required/);
  approve(record);
  record.approval.reviewedArgumentsHash = "C".repeat(43);
  await assert.rejects(() => completeHostedAudit(record), /approval is not bound/);
});

function approve(record) {
  record.approval = {
    status: "approved",
    method: "one_time_interface_session_capability",
    nonceId: privateApproval.nonceId,
    approvedAt: new Date(now + 1_000).toISOString(),
    reviewedTargetHash: record.review.targetHash,
    reviewedToolHash: record.review.toolHash,
    reviewedArgumentsHash: record.review.argumentsHash,
    reviewedContractHash: record.review.contractHash,
  };
  return record;
}

function stripSequence(event) {
  const { sequence: _sequence, ...rest } = event;
  return rest;
}
