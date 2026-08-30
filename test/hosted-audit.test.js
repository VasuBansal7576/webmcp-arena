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
  assert.equal(result.evidence.approval.expiresAt, record.expiresAt);
  assert.equal(result.evidence.approval.nonceId, privateApproval.nonceId);
  assert.equal(result.evidence.approval.sessionCommitment, privateApproval.sessionHash);
  assert.equal(result.evidence.approval.reviewerClaim, "same_origin_interface_session_controller");
  assert.equal(result.evidence.approval.assuranceClaim, "session_capability_verified_human_presence_not_attested");
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

test("execution rejects a stored target review even when the receipt is changed to match it", async () => {
  const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
  record.review.targetHash = "D".repeat(43);
  record.approval.reviewedTargetHash = record.review.targetHash;

  await assert.rejects(
    () => completeHostedAudit(record, { now: now + 2_000 }),
    /executable checkout target no longer matches the reviewed target/,
  );
});

test("execution rejects tampering with every signed approval commitment", async (t) => {
  const cases = [
    ["nonce", { nonceId: "different_nonce_value" }],
    ["session commitment", { sessionCommitment: "C".repeat(43) }],
    ["expiry", { expiresAt: new Date(now + 9 * 60_000).toISOString() }],
    ["reviewer claim", { reviewerClaim: "biological_human" }],
    ["assurance claim", { assuranceClaim: "human_presence_verified" }],
    ["approval after expiry", { approvedAt: new Date(now + 10 * 60_000 + 1).toISOString() }],
  ];

  for (const [name, mutation] of cases) {
    await t.test(name, async () => {
      const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
      Object.assign(record.approval, mutation);
      await assert.rejects(
        () => completeHostedAudit(record, { now: now + 2_000 }),
        /approval receipt/,
      );
    });
  }

  await t.test("unattested human-presence claim", async () => {
    const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
    record.approval.humanPresence = "verified";
    await assert.rejects(
      () => completeHostedAudit(record, { now: now + 2_000 }),
      /approval receipt/,
    );
  });
});

function approve(record) {
  record.approval = {
    status: "approved",
    method: "one_time_interface_session_capability",
    nonceId: privateApproval.nonceId,
    approvedAt: new Date(now + 1_000).toISOString(),
    expiresAt: record.expiresAt,
    sessionCommitment: privateApproval.sessionHash,
    reviewerClaim: "same_origin_interface_session_controller",
    assuranceClaim: "session_capability_verified_human_presence_not_attested",
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
