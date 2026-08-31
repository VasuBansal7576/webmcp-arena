import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  canonicalJson,
  completeHostedAudit,
  createHostedAudit,
  HOSTED_AUDIT_RETENTION_MS,
  publicHostedAudit,
  verifyHostedAuditEvidence,
  verifyHostedAuditRecord,
} from "../src/hosted-audit.js";
import {
  signEvidenceWithEnvironment,
  verifyEvidenceAttestation,
} from "../lib/evidence-signing.ts";
import { hashGeneratedRelease } from "../src/generated-release-audit.js";

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
  assert.equal(vulnerable.review.release.generator, "vendor-neutral-demo-generator");
  assert.equal(vulnerable.review.release.id, "arena.checkout.generated-release");
  assert.match(vulnerable.review.release.hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(vulnerable.review.release.artifact.algorithm, "sha256");
  assert.match(vulnerable.review.release.artifact.digest, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(vulnerable.review.agent.id, "browser-agent-demo");
  assert.equal(vulnerable.review.agent.assurance, "self_asserted_demo_identity");
  assert.match(vulnerable.review.agent.hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(vulnerable.review.principal.label, "Demo buyer account");
  assert.match(vulnerable.review.principal.hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(vulnerable.review.principalHash, vulnerable.review.principal.hash);
  assert.match(vulnerable.review.toolDefinitionHash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(vulnerable.review.contractHash, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(vulnerable.review.effects.map(({ kind }) => kind), [
    "authorization",
    "outcome",
    "effect_settlement",
    "final_state",
  ]);
  assert.notEqual(vulnerable.review.targetHash, fixed.review.targetHash);
  assert.notEqual(vulnerable.review.release.version, fixed.review.release.version);
  assert.notEqual(vulnerable.review.release.artifact.digest, fixed.review.release.artifact.digest);
  assert.notEqual(vulnerable.review.release.hash, fixed.review.release.hash);
  assert.equal(Date.parse(vulnerable.approvalExpiresAt), now + 10 * 60_000);
  assert.equal(Date.parse(vulnerable.retentionUntil), now + 30 * 24 * 60 * 60_000);
  assert.ok(Date.parse(vulnerable.retentionUntil) > Date.parse(vulnerable.approvalExpiresAt));
  assert.equal((await publicHostedAudit(vulnerable)).privateApproval, undefined);
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
  assert.equal(result.evidence.approval.expiresAt, record.approvalExpiresAt);
  assert.equal(result.evidence.retentionUntil, record.retentionUntil);
  assert.equal(result.evidence.approval.nonceId, privateApproval.nonceId);
  assert.equal(result.evidence.approval.sessionCommitment, privateApproval.sessionHash);
  assert.equal(result.evidence.approval.reviewerClaim, "same_origin_interface_session_controller");
  assert.equal(result.evidence.approval.assuranceClaim, "session_capability_verified_human_presence_not_attested");
  assert.deepEqual(result.authorizationChecks.map(({ check, status, reason }) => ({ check, status, reason })), [
    { check: "invalid_capability", status: "denied", reason: "invalid_capability" },
    { check: "tool_substitution", status: "denied", reason: "tool_binding_mismatch" },
    { check: "wrong_agent", status: "denied", reason: "agent_identity_mismatch" },
    { check: "argument_substitution", status: "denied", reason: "argument_substitution" },
    { check: "exact_intent", status: "executed", reason: null },
    { check: "replay", status: "denied", reason: "authorization_replayed" },
  ]);
  assert.equal(result.release.hash, record.review.release.hash);
  assert.equal(result.authorization.status, "consumed");
  assert.deepEqual(result.evidence.exactIntent.release, record.review.release);
  assert.deepEqual(result.evidence.exactIntent.agent, record.review.agent);
  assert.deepEqual(result.evidence.authorization, result.authorization);
  assert.deepEqual(result.evidence.authorizationChecks, result.authorizationChecks);
  assert.equal(hash(result.evidence), result.payloadHash);

  const alteredEvidence = structuredClone(result.evidence);
  alteredEvidence.authorizationChecks[0].status = "executed";
  assert.notEqual(hash(alteredEvidence), result.payloadHash);
  assert.deepEqual(await verifyHostedAuditEvidence(result.evidence), { valid: true });
});

test("completed evidence receives a full retention window from its generation time", async () => {
  const completionAt = now + 9 * 60_000;
  const record = approve(await createHostedAudit({
    id: vulnerableId,
    version: "vulnerable",
    privateApproval,
    now,
  }));
  const preparedRetention = record.retentionUntil;

  const result = await completeHostedAudit(record, { now: completionAt });

  assert.equal(result.evidence.generatedAt, new Date(completionAt).toISOString());
  assert.equal(
    Date.parse(result.evidence.retentionUntil) - Date.parse(result.evidence.generatedAt),
    HOSTED_AUDIT_RETENTION_MS,
  );
  assert.equal(record.retentionUntil, result.evidence.retentionUntil);
  assert.notEqual(record.retentionUntil, preparedRetention);

  const attestation = await signEvidenceWithEnvironment(
    result.evidence,
    result.payloadHash,
    { ARENA_ALLOW_EPHEMERAL_SIGNING: "true" },
    new Date(completionAt),
  );
  assert.equal(
    Date.parse(result.evidence.retentionUntil) - Date.parse(attestation.issuedAt),
    HOSTED_AUDIT_RETENTION_MS,
  );
  assert.equal(
    await verifyEvidenceAttestation(result.evidence, attestation, attestation.publicKey),
    true,
  );

  const shortened = structuredClone(result.evidence);
  shortened.retentionUntil = new Date(completionAt + HOSTED_AUDIT_RETENTION_MS - 1).toISOString();
  assert.deepEqual(await verifyHostedAuditEvidence(shortened), {
    valid: false,
    reason: "approval_chronology_mismatch",
  });
  assert.equal(await verifyEvidenceAttestation(shortened, attestation, attestation.publicKey), false);
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
  await assert.rejects(() => completeHostedAudit(record), /approval receipt is not bound/);
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

test("execution rejects tampering with every displayed exact-intent review field", async (t) => {
  const cases = [
    ["adapter", (record) => { record.review.adapterId = "other.adapter"; }],
    ["implementation", (record) => { record.review.implementationVersion = "fixed"; }],
    ["target label", (record) => { record.review.targetPreset = "Trusted checkout"; }],
    ["target", (record) => { record.review.target = "arena-owned://checkout/?version=fixed"; }],
    ["principal label", (record) => { record.review.principal.label = "Administrator account"; }],
    ["release id", (record) => { record.review.release.id = "other.release"; }],
    ["release version", (record) => { record.review.release.version = "2099.01.01"; }],
    ["release artifact", (record) => { record.review.release.artifact.digest = "Q".repeat(43); }],
    ["release generator", (record) => { record.review.release.generator = "trusted-generator"; }],
    ["release manifest", (record) => { record.review.releaseManifest.generator = "trusted-generator"; }],
    ["agent id", (record) => { record.review.agent.id = "trusted-browser-agent"; }],
    ["agent assurance", (record) => { record.review.agent.assurance = "vendor_attested"; }],
    ["tool name", (record) => { record.review.toolName = "place_order"; }],
    ["tool definition", (record) => { record.review.toolDefinition.description = "Place and charge an order."; }],
    ["arguments", (record) => { record.review.arguments.cartId = "cart_changed_after_review"; }],
    ["argument keys", (record) => { record.review.argumentKeys = []; }],
    ["claim scope", (record) => { record.review.claimScope = "arbitrary_origin"; }],
    ["expected effects", (record) => { record.review.effects[1].status = "purchased"; }],
    ["invariants", (record) => { record.review.invariants.money.maxAmount = 999; }],
    ["baseline safety", (record) => { record.review.baselineSafety.status = "fail"; }],
    ["trust mode", (record) => { record.review.trustMode = "caller_supplied"; }],
    ["approval assurance", (record) => { record.review.approvalAssurance = "vendor_attested_identity"; }],
    ["release coverage", (record) => { record.review.coverage.complete = false; }],
  ];

  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
      mutate(record);
      await assert.rejects(
        () => completeHostedAudit(record, { now: now + 2_000 }),
        /review material no longer matches the executable generated release/,
      );
    });
  }
});

test("execution rejects tampering with every signed approval commitment", async (t) => {
  const cases = [
    ["nonce", { nonceId: "different_nonce_value" }],
    ["session commitment", { sessionCommitment: "C".repeat(43) }],
    ["expiry", { expiresAt: new Date(now + 9 * 60_000).toISOString() }],
    ["reviewer claim", { reviewerClaim: "biological_human" }],
    ["assurance claim", { assuranceClaim: "human_presence_verified" }],
    ["release hash", { reviewedReleaseHash: "E".repeat(43) }],
    ["agent hash", { reviewedAgentHash: "F".repeat(43) }],
    ["principal hash", { reviewedPrincipalHash: "P".repeat(43) }],
    ["tool definition hash", { reviewedToolDefinitionHash: "G".repeat(43) }],
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

test("hosted evidence verification rejects semantic tampering even before signature verification", async (t) => {
  const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
  const { evidence } = await completeHostedAudit(record, { now: now + 2_000 });
  const cases = [
    ["wrong denial reason", (value) => { value.authorizationChecks[0].reason = "authorization_replayed"; }],
    ["release hash", (value) => { value.exactIntent.releaseHash = "R".repeat(43); }],
    ["release manifest", (value) => { value.exactIntent.releaseManifest.generator = "other-generator"; }],
    ["agent label", (value) => { value.exactIntent.agent.id = "other-agent"; }],
    ["agent assurance", (value) => { value.exactIntent.agent.assurance = "vendor_attested"; }],
    ["principal", (value) => { value.exactIntent.principal.label = "Other account"; }],
    ["principal binding", (value) => { value.approval.reviewedPrincipalHash = "P".repeat(43); }],
    ["authorization agent", (value) => { value.authorization.agentHash = "G".repeat(43); }],
    ["authorization reviewer", (value) => { value.authorization.reviewerHash = "Z".repeat(43); }],
    ["trust mode", (value) => { value.exactIntent.trustMode = "native_browser"; }],
    ["approval assurance", (value) => { value.exactIntent.approvalAssurance = "vendor_attested_identity"; }],
    ["adapter", (value) => { value.exactIntent.adapterId = "other.adapter"; }],
    ["implementation", (value) => { value.exactIntent.implementationVersion = "fixed"; }],
    ["target label", (value) => { value.exactIntent.targetPreset = "Trusted checkout"; }],
    ["claim scope", (value) => { value.exactIntent.claimScope = "arbitrary_origin"; }],
    ["expected effect", (value) => { value.exactIntent.effects[1].status = "purchased"; }],
    ["argument key omission", (value) => {
      value.exactIntent.argumentKeys = [];
      value.boundaryBundle.invocation.argumentKeys = [];
      rehashBoundaryBundle(value.boundaryBundle);
    }],
    ["approval after execution", (value) => {
      value.approval.approvedAt = "2099-01-01T00:00:00.000Z";
      value.approval.expiresAt = "2099-01-01T00:10:00.000Z";
    }],
    ["retention before approval expiry", (value) => {
      value.retentionUntil = value.approval.expiresAt;
    }],
  ];
  for (const [name, mutate] of cases) {
    await t.test(name, async () => {
      const changed = structuredClone(evidence);
      mutate(changed);
      const verification = await verifyHostedAuditEvidence(changed);
      assert.equal(verification.valid, false);
      assert.equal(typeof verification.reason, "string");
    });
  }
});

test("historical signed semantics remain verifiable after the current source artifact and release version advance", async () => {
  const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
  const { evidence } = await completeHostedAudit(record, { now: now + 2_000 });
  const historical = structuredClone(evidence);
  historical.exactIntent.releaseManifest.version = "2026.08.01-vulnerable.1";
  historical.exactIntent.releaseManifest.artifact.digest = "H".repeat(43);
  const historicalReleaseHash = hashGeneratedRelease(historical.exactIntent.releaseManifest);
  historical.exactIntent.release = {
    ...historical.exactIntent.release,
    version: historical.exactIntent.releaseManifest.version,
    artifact: structuredClone(historical.exactIntent.releaseManifest.artifact),
    hash: historicalReleaseHash,
  };
  historical.exactIntent.releaseHash = historicalReleaseHash;
  historical.approval.reviewedReleaseHash = historicalReleaseHash;

  assert.deepEqual(await verifyHostedAuditEvidence(historical), { valid: true });
});

test("public completed results are derived from signed evidence and reject post-sign duplicate tampering", async () => {
  const record = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
  const result = await completeHostedAudit(record, { now: now + 2_000 });
  record.state = "completed";
  record.result = {
    ...result,
    attestation: { payloadHash: result.payloadHash, algorithm: "Ed25519", keyId: "test-key" },
    verification: { semanticValid: false, hashValid: false },
  };

  const visible = await publicHostedAudit(record);
  assert.equal(visible.result.verdict, result.evidence.releaseVerdict);
  assert.deepEqual(visible.result.findings, result.findings);
  assert.deepEqual(visible.result.verification, {
    semanticValid: true,
    hashValid: true,
    projectionValid: true,
  });

  record.result.verdict = "pass";
  await assert.rejects(() => publicHostedAudit(record), /diverges from signed evidence/);
});

test("a signed result cannot be transplanted onto another hosted audit record", async () => {
  const source = approve(await createHostedAudit({ id: vulnerableId, version: "vulnerable", privateApproval, now }));
  source.state = "completed";
  const result = await completeHostedAudit(source, { now: now + 2_000 });
  source.result = {
    ...result,
    attestation: { payloadHash: result.payloadHash, algorithm: "Ed25519", keyId: "test-key" },
  };

  const target = approve(await createHostedAudit({ id: fixedId, version: "fixed", privateApproval, now }));
  target.state = "completed";
  target.result = structuredClone(source.result);

  assert.deepEqual(await verifyHostedAuditRecord(target), {
    valid: false,
    reason: "hosted_record_evidence_mismatch",
  });
  await assert.rejects(() => publicHostedAudit(target), /hosted_record_evidence_mismatch/);
});

test("a completed record cannot display unsigned approval or retention metadata beside a valid signed proof", async () => {
  const record = approve(await createHostedAudit({ id: fixedId, version: "fixed", privateApproval, now }));
  const result = await completeHostedAudit(record, { now: now + 2_000 });
  record.state = "completed";
  record.result = {
    ...result,
    attestation: { payloadHash: result.payloadHash, algorithm: "Ed25519", keyId: "test-key" },
  };
  record.approvalExpiresAt = "2099-01-01T00:00:00.000Z";

  assert.deepEqual(await verifyHostedAuditRecord(record), {
    valid: false,
    reason: "hosted_record_evidence_mismatch",
  });
  await assert.rejects(() => publicHostedAudit(record), /hosted_record_evidence_mismatch/);

  const retentionTamper = approve(await createHostedAudit({ id: fixedId, version: "fixed", privateApproval, now }));
  const retainedResult = await completeHostedAudit(retentionTamper, { now: now + 2_000 });
  retentionTamper.state = "completed";
  retentionTamper.result = {
    ...retainedResult,
    attestation: { payloadHash: retainedResult.payloadHash, algorithm: "Ed25519", keyId: "test-key" },
  };
  retentionTamper.retentionUntil = "2099-01-01T00:00:00.000Z";
  assert.deepEqual(await verifyHostedAuditRecord(retentionTamper), {
    valid: false,
    reason: "hosted_record_evidence_mismatch",
  });
});

function approve(record) {
  record.approval = {
    status: "approved",
    method: "one_time_interface_session_capability",
    nonceId: privateApproval.nonceId,
    approvedAt: new Date(now + 1_000).toISOString(),
    expiresAt: record.approvalExpiresAt,
    sessionCommitment: privateApproval.sessionHash,
    reviewerClaim: "same_origin_interface_session_controller",
    assuranceClaim: "session_capability_verified_human_presence_not_attested",
    reviewedTargetHash: record.review.targetHash,
    reviewedReleaseHash: record.review.release.hash,
    reviewedAgentHash: record.review.agent.hash,
    reviewedPrincipalHash: record.review.principal.hash,
    reviewedToolDefinitionHash: record.review.toolDefinitionHash,
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

function hash(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("base64url");
}

function rehashBoundaryBundle(bundle) {
  const { bundleHash: _bundleHash, attestation, ...body } = bundle;
  bundle.bundleHash = hash(body);
  bundle.attestation = attestation;
}
