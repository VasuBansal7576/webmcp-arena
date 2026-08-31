import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { createBoundaryAuditor, verifyAuditBundle } from "../src/boundary-audit.js";

test("a recorder-owned human and agent run produces a verifiable boundary pass", async () => {
  const observation = trustedObservation([
    stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
    { kind: "ui", selector: "#booking", outcome: "confirmed" },
  ]);
  const harness = memoryHarness();
  const runner = memoryRunner({ human: observation, agent: observation });
  const attestor = memoryAttestor();
  const auditor = createBoundaryAuditor({
    targetHarness: harness,
    routeRunner: runner,
    attestor,
    now: () => new Date("2026-08-30T10:00:00.000Z"),
    id: sequenceIds(),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const verification = await verifyAuditBundle(result.bundle, attestor);

  assert.equal(result.verdict, "pass");
  assert.equal(result.routeParity.status, "pass");
  assert.equal(result.baselineSafety.status, "not_evaluated");
  assert.equal(result.attestation.eligible, true);
  assert.equal(verification.valid, true);
  assert.deepEqual(runner.calls, ["human", "human", "agent"]);
  assert.ok(Object.isFrozen(result.bundle));
});

test("evidence bundles expose only a digest-bound principal commitment", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });
  const prepared = await auditor.prepare(recipe());

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal("principalRef" in result.bundle, false);
  assert.match(result.bundle.principalHash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(result.bundle).includes("fixture:human_vasu"), false);
  assert.deepEqual(await verifyAuditBundle(result.bundle), { valid: true, attested: false });
});

test("bundle verification fails closed on its envelope, identifiers, dates, digests, and attestation shape", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    now: () => new Date("2026-08-30T10:00:00.000Z"),
    id: sequenceIds(),
  });
  const prepared = await auditor.prepare(recipe());
  const { bundle } = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const cases = [
    { name: "kind", reason: "bundle_schema_invalid", change(value) { value.kind = "arena.other_bundle"; rehashBundle(value); } },
    { name: "version", reason: "bundle_schema_invalid", change(value) { value.version = 2; rehashBundle(value); } },
    { name: "required field", reason: "bundle_schema_invalid", change(value) { delete value.principalHash; rehashBundle(value); } },
    { name: "unknown field", reason: "bundle_schema_invalid", change(value) { value.rawTarget = "https://secret.example"; rehashBundle(value); } },
    { name: "date", reason: "bundle_schema_invalid", change(value) { value.generatedAt = "next Tuesday"; rehashBundle(value); } },
    { name: "identifier", reason: "bundle_schema_invalid", change(value) { value.auditId = "contains spaces"; rehashBundle(value); } },
    { name: "digest", reason: "bundle_schema_invalid", change(value) { value.argumentsHash = "not-a-sha256-digest"; rehashBundle(value); } },
    { name: "attestation", reason: "attestation_schema_invalid", change(value) { value.attestation = { eligible: "yes", proof: null }; } },
    { name: "proof", reason: "attestation_schema_invalid", change(value) { value.attestation = { eligible: true, proof: [] }; } },
  ];

  for (const candidate of cases) {
    const malformed = structuredClone(bundle);
    candidate.change(malformed);
    assert.deepEqual(
      await verifyAuditBundle(malformed),
      { valid: false, reason: candidate.reason },
      candidate.name,
    );
  }
});

test("bundle verification rejects a rehashed but impossible event chronology", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    now: () => new Date("2026-08-30T10:00:00.000Z"),
    id: sequenceIds(),
  });
  const prepared = await auditor.prepare(recipe());
  const { bundle } = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const impossible = structuredClone(bundle);
  impossible.events[0].observedAt = "2099-01-01T00:00:00.000Z";
  rehashEventChain(impossible.events);
  rehashBundle(impossible);

  assert.deepEqual(await verifyAuditBundle(impossible), {
    valid: false,
    reason: "event_chronology_invalid",
  });
});

test("a target harness cannot make the producer emit a verifier-invalid seed commitment", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness({ seedDigest: "opaque-seed-label" }),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });

  await assert.rejects(() => auditor.prepare(recipe()), /SHA-256 initial seed digest/);
});

test("identical unsafe human and agent routes fail explicit baseline safety invariants", async () => {
  const unsafe = trustedObservation([
    stateEffect({ amount: 25000, currency: "USD", owner: "another_member" }),
    { kind: "network", method: "POST", scope: "external", origin: "https://collect.example", path: "/ingest" },
  ]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: unsafe, agent: unsafe }),
  });
  const prepared = await auditor.prepare(recipe({
    invariants: {
      requireAuthorizationBeforeEffect: true,
      requireApprovalBeforeEffect: true,
      allowedAuthorizationRules: ["booking_window", "resource_owner"],
      allowedResourceOwners: ["human_vasu"],
      money: { maxAmount: 15000, currency: "INR" },
      allowedNetworkEffects: [{ method: "POST", scope: "target", path: "/api/book" }],
    },
  }));
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const verification = await verifyAuditBundle(result.bundle);

  assert.equal(prepared.proposedContract.invariants.requireAuthorizationBeforeEffect, true);
  assert.equal(prepared.baselineSafety.status, "fail");
  assert.equal(result.routeParity.status, "pass");
  assert.equal(result.baselineSafety.status, "fail");
  assert.equal(result.verdict, "fail");
  assert.deepEqual(result.baselineSafety.findings.map((item) => item.code), [
    "baseline_authorization_missing_before_effect",
    "baseline_approval_missing_before_effect",
    "baseline_resource_owner_disallowed",
    "baseline_money_amount_exceeded",
    "baseline_money_currency_disallowed",
    "baseline_network_effect_disallowed",
  ]);
  assert.deepEqual(verification, { valid: true, attested: false });

  const forged = structuredClone(result.bundle);
  forged.baselineSafety = { status: "pass", findings: [] };
  forged.verdict = "pass";
  forged.findings = [];
  rehashBundle(forged);
  assert.deepEqual(await verifyAuditBundle(forged), { valid: false, reason: "baseline_safety_semantics_mismatch" });
});

test("a safe reviewed baseline can satisfy every supported invariant", async () => {
  const human = trustedObservation([
    { kind: "authorization", decision: "allow", rule: "booking_window" },
    { kind: "approval", status: "approved" },
    stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
    { kind: "network", method: "POST", scope: "target", origin: "https://shop.example", path: "/api/book" },
  ]);
  const runner = memoryRunner({
    human,
    agent: ({ approvalBinding }) => trustedObservation([
      { kind: "authorization", decision: "allow", rule: "booking_window" },
      { kind: "approval", status: "approved", ...approvalBinding },
      stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
      { kind: "network", method: "POST", scope: "target", origin: "https://shop.example", path: "/api/book" },
    ]),
  });
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner: runner });
  const prepared = await auditor.prepare(recipe({
    invariants: {
      requireAuthorizationBeforeEffect: true,
      requireApprovalBeforeEffect: true,
      allowedAuthorizationRules: ["booking_window"],
      allowedResourceOwners: ["human_vasu"],
      money: { maxAmount: 15000, currency: "INR" },
      allowedNetworkEffects: [{ method: "POST", scope: "target", origin: "https://shop.example", path: "/api/book" }],
    },
  }));
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(
    { overall: result.verdict, parity: result.routeParity.status, safety: result.baselineSafety.status },
    { overall: "pass", parity: "pass", safety: "pass" },
  );
  assert.deepEqual(await verifyAuditBundle(result.bundle), { valid: true, attested: false });
});

test("a recorder-observed external write is consequential and needs server-attested approval", async () => {
  const externalWrite = {
    recorder: [
      { order: 2, kind: "approval", status: "approved" },
      {
        order: 3,
        kind: "network",
        method: "BOUNDARY",
        observedRequests: [{ scope: "external", method: "POST", originHmac: "O".repeat(43) }],
      },
    ],
    server: [{ order: 1, kind: "authorization", decision: "allow", rule: "network_policy" }],
    page: [],
  };
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: externalWrite, agent: externalWrite }),
  });

  const prepared = await auditor.prepare(recipe({
    invariants: {
      requireAuthorizationBeforeEffect: true,
      requireApprovalBeforeEffect: true,
      allowedNetworkEffects: [{ scope: "external", method: "POST", originHmac: "O".repeat(43) }],
    },
  }));

  assert.equal(prepared.baselineSafety.status, "fail");
  assert.deepEqual(
    prepared.baselineSafety.findings.map((item) => item.code),
    ["baseline_approval_missing_before_effect"],
  );
});

test("target POST transport alone is not treated as a consequential baseline effect", async () => {
  const targetTransport = {
    recorder: [{
      order: 1,
      kind: "network",
      method: "BOUNDARY",
      observedRequests: [{ scope: "target", method: "POST", pathHmac: "P".repeat(43) }],
    }],
    server: [],
    page: [],
  };
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: targetTransport, agent: targetTransport }),
  });

  const prepared = await auditor.prepare(recipe({
    invariants: {
      requireApprovalBeforeEffect: true,
      allowedNetworkEffects: [{ scope: "target", method: "POST", pathHmac: "P".repeat(43) }],
    },
  }));

  assert.deepEqual(
    prepared.baselineSafety,
    { status: "inconclusive", findings: [{
      code: "baseline_safety_evidence_missing",
      message: "The reviewed baseline does not contain enough trusted evidence to evaluate its safety invariants.",
    }] },
  );
  assert.equal(prepared.baselineSafety.findings.some((item) => item.code === "baseline_approval_missing_before_effect"), false);
});

test("configured baseline dimensions cannot pass vacuously on authorization-only evidence", async () => {
  const authorizationOnly = trustedObservation([
    { kind: "authorization", decision: "allow", rule: "booking_window" },
  ]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: authorizationOnly, agent: authorizationOnly }),
  });

  const prepared = await auditor.prepare(recipe({
    invariants: {
      allowedResourceOwners: ["human_vasu"],
      money: { maxAmount: 15000, currency: "INR" },
      allowedNetworkEffects: [{ scope: "target", method: "POST" }],
    },
  }));
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(prepared.baselineSafety, {
    status: "inconclusive",
    findings: [{
      code: "baseline_safety_evidence_missing",
      message: "The reviewed baseline does not contain enough trusted evidence to evaluate its safety invariants.",
    }],
  });
  assert.equal(result.coverage.complete, false);
  assert.equal(result.routeParity.status, "inconclusive");
  assert.equal(result.attestation.eligible, false);
});

test("recorder-only approval evidence cannot prove approval parity", async () => {
  const human = {
    recorder: [{ order: 2, kind: "approval", status: "approved" }],
    server: [
      { order: 1, kind: "authorization", decision: "allow", rule: "booking_window" },
      { order: 3, ...stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }) },
    ],
    page: [],
  };
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({
      human,
      agent: ({ approvalBinding }) => ({
        ...structuredClone(human),
        recorder: [{ order: 2, kind: "approval", status: "approved", ...approvalBinding }],
      }),
    }),
  });
  const prepared = await auditor.prepare(recipe());

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(result.routeParity.status, "inconclusive");
  assert.deepEqual(result.routeParity.findings.map((item) => item.code), ["authoritative_evidence_missing"]);
  assert.equal(result.attestation.eligible, false);
  assert.deepEqual(await verifyAuditBundle(result.bundle), { valid: true, attested: false });
});

test("the reviewed invariant policy is contract-hashed and rejects ambiguous configuration", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const createAuditor = () => createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    now: () => new Date("2026-08-30T10:00:00.000Z"),
  });
  const authorizationPolicy = await createAuditor().prepare(recipe({
    invariants: { requireAuthorizationBeforeEffect: true },
  }));
  const approvalPolicy = await createAuditor().prepare(recipe({
    invariants: { requireApprovalBeforeEffect: true },
  }));

  assert.notEqual(authorizationPolicy.contractHash, approvalPolicy.contractHash);
  assert.equal(authorizationPolicy.approvalBinding.contractHash, authorizationPolicy.contractHash);
  await assert.rejects(
    () => createAuditor().prepare(recipe({ invariants: { requireAuthorisationBeforeEffect: true } })),
    /unknown baseline safety invariant/,
  );
});

test("callers cannot submit traces or evidence through the recipe seam", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });

  await assert.rejects(
    () => auditor.prepare({
      ...recipe(),
      humanRoute: { proof_level: "instrumented_application_state", state: { after: { charged: false } } },
      agentRoute: { proof_level: "instrumented_application_state", state: { after: { charged: false } } },
    }),
    /caller-authored traces or evidence are not accepted/,
  );
});

test("value-aware comparison reports amount, currency, and resource-owner divergence", async () => {
  const human = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const agent = trustedObservation([stateEffect({ amount: 25000, currency: "USD", owner: "another_member" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human, agent }),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(result.verdict, "fail");
  assert.deepEqual(
    result.findings.map((finding) => finding.code),
    ["resource_owner_changed", "money_amount_changed", "money_currency_changed"],
  );
});

test("matching page claims cannot satisfy trusted protection coverage", async () => {
  const pageOnly = {
    recorder: [],
    server: [],
    page: [{ kind: "protection", name: "resource_ownership", enforced: true }],
  };
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: pageOnly, agent: pageOnly }),
    attestor: memoryAttestor(),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(result.verdict, "inconclusive");
  assert.deepEqual(result.findings.map((finding) => finding.code), ["page_assertions_untrusted"]);
  assert.equal(result.attestation.eligible, false);
  assert.ok(result.bundle.events.every((event) => event.provenance === "page_asserted"));
});

test("an approval recorded after a consequential effect fails the audit", async () => {
  const approvedBefore = trustedObservation([
    { kind: "approval", status: "approved" },
    stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
  ]);
  const approvedAfter = trustedObservation([
    stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
    { kind: "approval", status: "approved" },
  ]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: approvedBefore, agent: approvedAfter }),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(result.verdict, "fail");
  assert.deepEqual(result.findings.map((finding) => finding.code), ["approval_after_effect"]);
});

test("an argument-hash mismatch is rejected before the agent executes", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const runner = memoryRunner({ human: observation, agent: observation });
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner: runner });
  const prepared = await auditor.prepare(recipe());

  await assert.rejects(
    () => auditor.run({
      planId: prepared.planId,
      approval: approvalFor(prepared, { argumentsHash: "approved-for-different-arguments" }),
    }),
    /approval is not bound to the exact plan, tool, arguments, and contract/,
  );
  assert.deepEqual(runner.calls, ["human"]);
});

test("agent arguments reject values outside the canonical JSON domain", async () => {
  class CustomValue {
    constructor() {
      this.value = "custom";
    }
  }
  const sparse = [];
  sparse.length = 1;
  const cyclic = {};
  cyclic.self = cyclic;
  const invalidValues = [undefined, sparse, NaN, Infinity, -Infinity, new Date(), new CustomValue(), cyclic];

  for (const invalid of invalidValues) {
    const auditor = createBoundaryAuditor({
      targetHarness: memoryHarness(),
      routeRunner: memoryRunner({ human: trustedObservation([]), agent: trustedObservation([]) }),
    });
    const base = recipe();
    await assert.rejects(
      () => auditor.prepare(recipe({ agent: { ...base.agent, arguments: { payload: invalid } } })),
      /canonical JSON|JSON-compatible/i,
    );
  }
});

test("argument hashes use canonical JSON key order without collapsing distinct JSON arrays", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    now: () => new Date("2026-08-30T10:00:00.000Z"),
  });
  const base = recipe();
  const left = await auditor.prepare(recipe({ agent: { ...base.agent, arguments: { nested: { b: 2, a: 1 }, items: [] } } }));
  const reordered = await auditor.prepare(recipe({ agent: { ...base.agent, arguments: { items: [], nested: { a: 1, b: 2 } } } }));
  const different = await auditor.prepare(recipe({ agent: { ...base.agent, arguments: { items: [null], nested: { a: 1, b: 2 } } } }));

  assert.equal(left.approvalBinding.argumentsHash, reordered.approvalBinding.argumentsHash);
  assert.notEqual(left.approvalBinding.argumentsHash, different.approvalBinding.argumentsHash);
});

test("an audit with no measured evidence is inconclusive and cannot be attested", async () => {
  const empty = { recorder: [], server: [], page: [] };
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: empty, agent: empty }),
    attestor: memoryAttestor(),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(
    { verdict: result.verdict, finding: result.findings[0].code, eligible: result.attestation.eligible, proof: result.attestation.proof },
    { verdict: "inconclusive", finding: "trusted_evidence_missing", eligible: false, proof: null },
  );
});

test("matching recorder observations without authoritative server outcomes stay inconclusive", async () => {
  const recorderOnly = {
    recorder: [stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })],
    server: [],
    page: [],
  };
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: recorderOnly, agent: recorderOnly }),
    attestor: memoryAttestor(),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(result.verdict, "inconclusive");
  assert.deepEqual(result.findings.map((finding) => finding.code), ["authoritative_evidence_missing"]);
  assert.equal(result.coverage.authoritativeComplete, false);
  assert.equal(result.attestation.eligible, false);
});

test("compatibility evidence remains useful but has lower assurance than native evidence", async () => {
  const observationFor = (level) => ({
    recorder: [{
      kind: "execution_proof",
      level,
      isolatedContext: true,
      captureComplete: true,
      captureReason: "quiescent",
      pendingRequests: 0,
    }],
    server: [stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })],
    page: [],
  });
  const runWith = async (level) => {
    const observation = observationFor(level);
    const auditor = createBoundaryAuditor({
      targetHarness: memoryHarness(),
      routeRunner: memoryRunner({ human: observation, agent: observation }),
      attestor: memoryAttestor(),
    });
    const prepared = await auditor.prepare(recipe());
    return auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  };

  const native = await runWith("native_browser_api");
  const compatibility = await runWith("compatibility_shim");

  assert.deepEqual(
    { verdict: native.verdict, tier: native.assurance.tier, eligible: native.attestation.eligible, attested: Boolean(native.attestation.proof) },
    { verdict: "pass", tier: "native", eligible: true, attested: true },
  );
  assert.deepEqual(
    {
      verdict: compatibility.verdict,
      tier: compatibility.assurance.tier,
      eligible: compatibility.attestation.eligible,
      attested: Boolean(compatibility.attestation.proof),
    },
    { verdict: "pass", tier: "compatibility", eligible: false, attested: false },
  );
});

test("incomplete, timed-out, and multiple browser execution proofs make parity inconclusive", async () => {
  const state = stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" });
  const invalidProofSets = [
    [{
      kind: "execution_proof",
      level: "native_browser_api",
      isolatedContext: true,
      captureComplete: false,
      captureReason: "timeout",
      pendingRequests: 1,
    }],
    [
      {
        kind: "execution_proof",
        level: "native_browser_api",
        isolatedContext: true,
        captureComplete: true,
        captureReason: "quiescent",
        pendingRequests: 0,
      },
      {
        kind: "execution_proof",
        level: "native_browser_api",
        isolatedContext: true,
        captureComplete: true,
        captureReason: "quiescent",
        pendingRequests: 0,
      },
    ],
  ];

  for (const recorder of invalidProofSets) {
    const observation = { recorder, server: [state], page: [] };
    const auditor = createBoundaryAuditor({
      targetHarness: memoryHarness(),
      routeRunner: memoryRunner({ human: observation, agent: observation }),
      attestor: memoryAttestor(),
    });
    const prepared = await auditor.prepare(recipe());
    const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

    assert.deepEqual(
      {
        routeParity: result.routeParity.status,
        findings: result.routeParity.findings.map((item) => item.code),
        assurance: result.assurance.tier,
        eligible: result.attestation.eligible,
      },
      {
        routeParity: "inconclusive",
        findings: ["browser_execution_proof_incomplete"],
        assurance: "unverified",
        eligible: false,
      },
    );
    assert.deepEqual(await verifyAuditBundle(result.bundle), { valid: true, attested: false });

    const forged = structuredClone(result.bundle);
    forged.routeParity = { status: "pass", findings: [] };
    forged.verdict = "pass";
    forged.findings = [];
    rehashBundle(forged);
    assert.deepEqual(
      await verifyAuditBundle(forged),
      { valid: false, reason: "route_parity_semantics_mismatch" },
    );
  }
});

test("server-attested observations need no browser execution proof", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    attestor: memoryAttestor(),
  });
  const prepared = await auditor.prepare(recipe());

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(
    { routeParity: result.routeParity.status, assurance: result.assurance.tier, eligible: result.attestation.eligible },
    { routeParity: "pass", assurance: "server_attested", eligible: true },
  );
});

test("a required terminal effect watermark covers work that settles after browser quietness", async () => {
  const settled = trustedObservation([
    { order: 1, kind: "money", amount: 49.99, currency: "USD" },
    { order: 2, kind: "effect_settlement", complete: true, reason: "terminal_watermark", pendingEffects: 0 },
    { order: 3, kind: "final_state", status: "confirmed", pendingEffects: 0, moneyEffects: 1, resourceEffects: 1 },
  ]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: settled, agent: settled }),
    attestor: memoryAttestor(),
  });
  const prepared = await auditor.prepare(recipe({ invariants: { requireEffectSettlement: true } }));

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(prepared.proposedContract.invariants.requireEffectSettlement, true);
  assert.deepEqual(
    { parity: result.routeParity.status, safety: result.baselineSafety.status, verdict: result.verdict, eligible: result.attestation.eligible },
    { parity: "pass", safety: "pass", verdict: "pass", eligible: true },
  );
  assert.deepEqual(await verifyAuditBundle(result.bundle), { valid: false, reason: "attestation_unverified" });
});

test("missing, duplicate, timed-out, and non-terminal settlement evidence stays inconclusive and unsigned", async () => {
  const complete = [
    { order: 1, kind: "money", amount: 49.99, currency: "USD" },
    { order: 2, kind: "effect_settlement", complete: true, reason: "terminal_watermark", pendingEffects: 0 },
    { order: 3, kind: "final_state", status: "confirmed", pendingEffects: 0, moneyEffects: 1, resourceEffects: 1 },
  ];
  const invalidCases = [
    complete.filter((effect) => effect.kind !== "effect_settlement"),
    [complete[0], complete[1], { ...complete[1], order: 2.5 }, complete[2]],
    [complete[0], { order: 2, kind: "effect_settlement", complete: false, reason: "timeout", pendingEffects: 1 }, complete[2]],
    [complete[0], complete[2], { ...complete[1], order: 4 }],
  ];

  for (const effects of invalidCases) {
    const auditor = createBoundaryAuditor({
      targetHarness: memoryHarness(),
      routeRunner: memoryRunner({ human: trustedObservation(complete), agent: trustedObservation(effects) }),
      attestor: memoryAttestor(),
    });
    const prepared = await auditor.prepare(recipe({ invariants: { requireEffectSettlement: true } }));
    const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

    assert.equal(result.routeParity.status, "inconclusive");
    assert.deepEqual(result.routeParity.findings.map((item) => item.code), ["effect_settlement_incomplete"]);
    assert.equal(result.verdict, "inconclusive");
    assert.deepEqual(result.attestation, { eligible: false, proof: null });
    assert.deepEqual(await verifyAuditBundle(result.bundle), { valid: true, attested: false });
  }
});

test("tampering with recorder-owned evidence invalidates the bundle", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const attestor = memoryAttestor();
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    attestor,
  });
  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const tampered = structuredClone(result.bundle);
  tampered.events[0].payload.after.amount = 1;

  const verification = await verifyAuditBundle(tampered, attestor);

  assert.deepEqual(verification, { valid: false, reason: "bundle_hash_mismatch" });
});

test("bundle verification recomputes the verdict instead of trusting a rehashed claim", async () => {
  const human = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const agent = trustedObservation([stateEffect({ amount: 25000, currency: "USD", owner: "another_member" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human, agent }),
  });
  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const forged = structuredClone(result.bundle);
  forged.verdict = "pass";
  forged.findings = [];
  rehashBundle(forged);

  assert.deepEqual(await verifyAuditBundle(forged), { valid: false, reason: "verdict_semantics_mismatch" });
});

test("bundle verification recomputes coverage and assurance from provenance-tagged events", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });
  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const falseCoverage = structuredClone(result.bundle);
  falseCoverage.coverage.humanAuthoritative += 1;
  rehashBundle(falseCoverage);

  assert.deepEqual(await verifyAuditBundle(falseCoverage), { valid: false, reason: "coverage_semantics_mismatch" });

  const compatibility = {
    recorder: [{
      kind: "execution_proof",
      level: "compatibility_shim",
      isolatedContext: true,
      captureComplete: true,
      captureReason: "quiescent",
      pendingRequests: 0,
    }],
    server: structuredClone(observation.server),
    page: [],
  };
  const compatibilityAuditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: compatibility, agent: compatibility }),
  });
  const compatibilityPrepared = await compatibilityAuditor.prepare(recipe());
  const compatibilityResult = await compatibilityAuditor.run({
    planId: compatibilityPrepared.planId,
    approval: approvalFor(compatibilityPrepared),
  });
  const falseAssurance = structuredClone(compatibilityResult.bundle);
  falseAssurance.assurance.tier = "native";
  falseAssurance.assurance.attestationEligible = true;
  falseAssurance.attestation.eligible = true;
  rehashBundle(falseAssurance);

  assert.deepEqual(await verifyAuditBundle(falseAssurance), { valid: false, reason: "assurance_semantics_mismatch" });
});

test("network and visible UI outcomes are compared as values, not only as effect kinds", async () => {
  const human = trustedObservation([
    { kind: "network", method: "GET", origin: "https://shop.example", path: "/api/cart", query: { cart: "h:own" } },
    { kind: "ui", selector: "#order-preview", outcome: "visible", valueHash: "preview:own" },
  ]);
  const agent = trustedObservation([
    { kind: "network", method: "GET", origin: "https://collect.example", path: "/ingest", query: { cart: "h:own" } },
    { kind: "ui", selector: "#order-preview", outcome: "hidden", valueHash: "preview:other" },
  ]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human, agent }),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(result.findings.map((finding) => finding.code), ["network_effect_changed", "ui_outcome_changed"]);
});

test("resource identity and before-after state values are compared exactly", async () => {
  const humanEffect = stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" });
  const agentEffect = structuredClone(humanEffect);
  agentEffect.resource.id = "booking_2";
  agentEffect.after.status = "cancelled";
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: trustedObservation([humanEffect]), agent: trustedObservation([agentEffect]) }),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(result.findings.map((finding) => finding.code), ["resource_identity_changed", "state_value_changed"]);
});

test("the runtime approval must bind the exact tool, arguments, and contract", async () => {
  const human = trustedObservation([
    { kind: "approval", status: "approved" },
    stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
  ]);
  const agent = trustedObservation([
    {
      kind: "approval",
      status: "approved",
      toolHash: "different-tool",
      argumentsHash: "different-arguments",
      contractHash: "different-contract",
    },
    stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }),
  ]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human, agent }),
  });

  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(result.findings.map((finding) => finding.code), ["approval_binding_mismatch"]);
});

test("an approved audit plan is short-lived and cannot execute after its review window", async () => {
  let clock = new Date("2026-08-30T10:00:00.000Z");
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const runner = memoryRunner({ human: observation, agent: observation });
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: runner,
    now: () => new Date(clock),
    planTtlMs: 60_000,
  });
  const prepared = await auditor.prepare(recipe());

  assert.equal(prepared.expiresAt, "2026-08-30T10:01:00.000Z");
  clock = new Date("2026-08-30T10:01:00.001Z");
  await assert.rejects(
    () => auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) }),
    /boundary audit plan expired/,
  );
  assert.deepEqual(runner.calls, ["human"]);
});

test("an approved audit plan can execute the consequential agent route only once", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const runner = memoryRunner({ human: observation, agent: observation });
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner: runner });
  const prepared = await auditor.prepare(recipe());

  await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  await assert.rejects(
    () => auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) }),
    /unknown boundary audit plan/,
  );
  assert.deepEqual(runner.calls, ["human", "human", "agent"]);
});

test("human and agent routes must use clones of the approved initial seed", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const runner = memoryRunner({ human: observation, agent: observation });
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness({ runSeeds: { agent: "different-seed" } }),
    routeRunner: runner,
    attestor: memoryAttestor(),
  });
  const prepared = await auditor.prepare(recipe());

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.deepEqual(
    { verdict: result.verdict, finding: result.findings[0].code, eligible: result.attestation.eligible, calls: runner.calls },
    { verdict: "inconclusive", finding: "seed_mismatch", eligible: false, calls: ["human"] },
  );
});

test("run accepts only an opaque plan and approval, never replacement route evidence", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const runner = memoryRunner({ human: observation, agent: observation });
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner: runner });
  const prepared = await auditor.prepare(recipe());

  await assert.rejects(
    () => auditor.run({
      planId: prepared.planId,
      approval: approvalFor(prepared),
      agentRoute: trustedObservation([]),
    }),
    /caller-authored traces or evidence are not accepted/,
  );
  assert.deepEqual(runner.calls, ["human"]);
});

test("approval ordering is preserved across recorder and server evidence channels", async () => {
  const human = {
    recorder: [{ kind: "network", method: "POST", origin: "https://shop.example", path: "/api/orders", order: 2 }],
    server: [
      { kind: "approval", status: "approved", order: 1 },
      { ...stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }), order: 3 },
    ],
    page: [],
  };
  const runner = memoryRunner({
    human,
    agent: ({ approvalBinding }) => ({
      recorder: [{ kind: "network", method: "POST", origin: "https://shop.example", path: "/api/orders", order: 2 }],
      server: [
        { kind: "approval", status: "approved", order: 1, ...approvalBinding },
        { ...stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" }), order: 3 },
      ],
      page: [],
    }),
  });
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner: runner });
  const prepared = await auditor.prepare(recipe());

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  assert.equal(result.verdict, "pass");
});

test("attestation eligibility is derived from verdict and trusted coverage", async () => {
  const empty = { recorder: [], server: [], page: [] };
  const attestor = memoryAttestor();
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: empty, agent: empty }),
    attestor,
  });
  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const forged = structuredClone(result.bundle);
  forged.attestation.eligible = true;

  const verification = await verifyAuditBundle(forged, attestor);

  assert.deepEqual(verification, { valid: false, reason: "attestation_eligibility_mismatch" });
});

test("tool and contract hash mismatches are rejected before route provisioning", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const runner = memoryRunner({ human: observation, agent: observation });
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner: runner });
  const prepared = await auditor.prepare(recipe());

  for (const field of ["toolHash", "contractHash"]) {
    await assert.rejects(
      () => auditor.run({
        planId: prepared.planId,
        approval: approvalFor(prepared, { [field]: `different-${field}` }),
      }),
      /approval is not bound to the exact plan, tool, arguments, and contract/,
    );
  }
  assert.deepEqual(runner.calls, ["human"]);
});

test("evidence bundles bind arguments without persisting their secret values", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const attestor = memoryAttestor();
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    attestor,
  });
  const base = recipe();
  const prepared = await auditor.prepare(recipe({
    agent: {
      ...base.agent,
      arguments: { ...base.agent.arguments, authorization: "Bearer secret-token", passenger: "Private Person" },
    },
  }));

  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });
  const serialized = JSON.stringify(result.bundle);
  const verification = await verifyAuditBundle(result.bundle, attestor);

  assert.equal(serialized.includes("secret-token"), false);
  assert.equal(serialized.includes("Private Person"), false);
  assert.deepEqual(result.bundle.invocation.argumentKeys, ["authorization", "currency", "flightId", "passenger", "price"]);
  assert.equal("arguments" in result.bundle.invocation, false);
  assert.equal(verification.valid, true);
});

test("a human lease is released when agent provisioning fails", async () => {
  const released = [];
  const harness = {
    async establish() {
      return { owned: true, targetRef: "target-1", seedDigest: "S".repeat(43) };
    },
    async provision({ route }) {
      if (route === "agent") throw new Error("agent provision failed");
      return { handle: `${route}-handle`, route, seedDigest: "S".repeat(43) };
    },
    async release(target) {
      released.push(target.route);
    },
  };
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: harness,
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });
  const prepared = await auditor.prepare(recipe());

  await assert.rejects(
    () => auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) }),
    /agent provision failed/,
  );
  assert.deepEqual(released, ["prepare-human", "human"]);
});

test("both run leases are released even when one release fails", async () => {
  const released = [];
  const harness = {
    async establish() {
      return { owned: true, targetRef: "target-1", seedDigest: "S".repeat(43) };
    },
    async provision({ route }) {
      return { handle: `${route}-handle`, route, seedDigest: "S".repeat(43) };
    },
    async release(target) {
      released.push(target.route);
      if (target.route === "human") throw new Error("human release failed");
    },
  };
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: harness,
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });
  const prepared = await auditor.prepare(recipe());

  await assert.rejects(
    () => auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) }),
    /one or more target leases could not be released/,
  );
  assert.deepEqual(released, ["prepare-human", "human", "agent"]);
});

test("adapter-owned observation arrays cannot mutate prepared plans or returned bundles", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const routeRunner = {
    async runHuman() {
      return observation;
    },
    async runAgent() {
      return observation;
    },
  };
  const auditor = createBoundaryAuditor({ targetHarness: memoryHarness(), routeRunner });
  const prepared = await auditor.prepare(recipe());
  const result = await auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) });

  observation.server[0].after.amount = 1;
  observation.server.push({ kind: "state", before: null, after: { injected: true } });

  assert.equal(prepared.proposedContract.effects[0].after.amount, 12000);
  assert.equal(result.bundle.contract.effects[0].after.amount, 12000);
  assert.equal(result.bundle.events.length, 2);
});

test("malformed adapter observations are rejected before they can become evidence", async () => {
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: {
      async runHuman() {
        return { recorder: [], server: { kind: "state" }, page: [] };
      },
      async runAgent() {
        return trustedObservation([]);
      },
    },
  });

  await assert.rejects(
    () => auditor.prepare(recipe()),
    /observation server must be an array of objects/,
  );
});

test("non-canonical recorder, server, and page payloads cannot enter an evidence bundle", async () => {
  for (const channel of ["recorder", "server", "page"]) {
    const observation = { recorder: [], server: [], page: [] };
    observation[channel] = [{ kind: "state", value: undefined }];
    const auditor = createBoundaryAuditor({
      targetHarness: memoryHarness(),
      routeRunner: memoryRunner({ human: observation, agent: observation }),
    });

    await assert.rejects(() => auditor.prepare(recipe()), /canonical JSON|JSON-compatible/i);
  }
});

test("non-canonical attestor output cannot enter or verify as bundle material", async () => {
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    attestor: { async issue() { return { signature: undefined }; } },
  });
  const prepared = await auditor.prepare(recipe());

  await assert.rejects(
    () => auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) }),
    /canonical JSON|JSON-compatible/i,
  );

  const validAuditor = createBoundaryAuditor({
    targetHarness: memoryHarness(),
    routeRunner: memoryRunner({ human: observation, agent: observation }),
  });
  const validPrepared = await validAuditor.prepare(recipe());
  const validResult = await validAuditor.run({ planId: validPrepared.planId, approval: approvalFor(validPrepared) });
  const malformed = structuredClone(validResult.bundle);
  malformed.attestation.proof = [];
  malformed.attestation.proof.length = 1;

  assert.deepEqual(await verifyAuditBundle(malformed), { valid: false, reason: "non_canonical_bundle" });
});

test("cleanup must succeed before an evidence bundle is attested", async () => {
  let issued = 0;
  const harness = {
    async establish() {
      return { owned: true, targetRef: "target-1", seedDigest: "S".repeat(43) };
    },
    async provision({ route }) {
      return { route, seedDigest: "S".repeat(43) };
    },
    async release(target) {
      if (target.route === "human") throw new Error("cleanup failed");
    },
  };
  const observation = trustedObservation([stateEffect({ amount: 12000, currency: "INR", owner: "human_vasu" })]);
  const auditor = createBoundaryAuditor({
    targetHarness: harness,
    routeRunner: memoryRunner({ human: observation, agent: observation }),
    attestor: {
      async issue() {
        issued += 1;
        return { signature: "should-not-exist" };
      },
    },
  });
  const prepared = await auditor.prepare(recipe());

  await assert.rejects(
    () => auditor.run({ planId: prepared.planId, approval: approvalFor(prepared) }),
    /one or more target leases could not be released/,
  );
  assert.equal(issued, 0);
});

function recipe(overrides = {}) {
  return {
    target: "http://127.0.0.1:4174",
    principalRef: "fixture:human_vasu",
    human: { actions: [{ type: "click", selector: "#book" }] },
    agent: {
      toolName: "book_flight",
      toolDefinitionHash: "tool-definition-v1",
      arguments: { flightId: "AI-202", price: 12000, currency: "INR" },
    },
    ...overrides,
  };
}

function stateEffect({ amount, currency, owner }) {
  return {
    kind: "state",
    resource: { type: "booking", id: "booking_1", owner },
    before: null,
    after: { status: "confirmed", amount, currency },
  };
}

function trustedObservation(events) {
  return { recorder: [], server: structuredClone(events), page: [] };
}

function memoryHarness({ seedDigest = "S".repeat(43), runSeeds = {} } = {}) {
  return {
    async establish() {
      return { owned: true, targetRef: "target-1", seedDigest };
    },
    async provision({ route }) {
      return { handle: `${route}-handle`, seedDigest: runSeeds[route] || seedDigest };
    },
    async release() {},
  };
}

function memoryRunner({ human, agent }) {
  const calls = [];
  return {
    calls,
    async runHuman() {
      calls.push("human");
      return structuredClone(human);
    },
    async runAgent(input) {
      calls.push("agent");
      return structuredClone(typeof agent === "function" ? agent(input) : agent);
    },
  };
}

function memoryAttestor() {
  return {
    async issue({ digest }) {
      return { keyId: "test-key", signature: `signed:${digest}` };
    },
    async verify({ digest, attestation }) {
      return attestation?.keyId === "test-key" && attestation.signature === `signed:${digest}`;
    },
  };
}

function approvalFor(prepared, overrides = {}) {
  return {
    status: "approved",
    planId: prepared.planId,
    ...prepared.approvalBinding,
    ...overrides,
  };
}

function sequenceIds() {
  let value = 0;
  return () => `id_${++value}`;
}

function rehashBundle(bundle) {
  const { bundleHash: _bundleHash, attestation: _attestation, ...body } = bundle;
  bundle.bundleHash = createHash("sha256").update(canonicalTestJson(body)).digest("base64url");
}

function rehashEventChain(events) {
  let previousEventHash = null;
  for (const event of events) {
    event.previousEventHash = previousEventHash;
    const { eventHash: _eventHash, ...body } = event;
    event.eventHash = createHash("sha256").update(canonicalTestJson(body)).digest("base64url");
    previousEventHash = event.eventHash;
  }
}

function canonicalTestJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalTestJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalTestJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
