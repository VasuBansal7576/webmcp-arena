import assert from "node:assert/strict";
import test from "node:test";

import { createAdapterRegistry } from "../src/adapter-sdk.js";
import { createBoundaryAuditor, verifyAuditBundle } from "../src/boundary-audit.js";
import { createCheckoutAuditAdapter } from "../src/checkout-audit-adapter.js";
import { createDeterministicScheduler } from "../src/effect-settlement.js";

test("Checkout catches a delayed hidden charge and passes the fixed preview route", async () => {
  const vulnerable = await runCheckout("vulnerable");
  const fixed = await runCheckout("fixed");

  assert.equal(vulnerable.verdict, "fail");
  assert.ok(vulnerable.findings.some(({ code }) => code === "unexpected_consequential_effect"));
  assert.ok(vulnerable.findings.some(({ code }) => code === "effect_mismatch"));
  assert.equal(vulnerable.assurance.tier, "server_attested");
  assert.equal(vulnerable.attestation.eligible, true);
  assert.equal(fixed.verdict, "pass");
  assert.equal(fixed.routeParity.status, "pass");
  assert.equal(fixed.baselineSafety.status, "pass");
  assert.equal(fixed.assurance.tier, "server_attested");
  assert.deepEqual(await verifyAuditBundle(vulnerable.bundle), { valid: true, attested: false });
  assert.deepEqual(await verifyAuditBundle(fixed.bundle), { valid: true, attested: false });

  const hiddenCharge = vulnerable.bundle.events.find(({ route, payload }) =>
    route === "agent" && payload.kind === "money");
  assert.deepEqual(hiddenCharge.payload, {
    kind: "money",
    action: "charge",
    amount: 149,
    currency: "USD",
    resource: {
      type: "payment_intent",
      id: "payment_checkout_demo_001",
      owner: "principal_demo_buyer",
    },
  });
  const settlement = vulnerable.bundle.events.find(({ route, payload }) =>
    route === "agent" && payload.kind === "effect_settlement");
  assert.equal(settlement.provenance, "server_attested");
  assert.equal(settlement.payload.complete, true);
  assert.equal(settlement.payload.status, "settled");
  assert.equal(settlement.payload.observedThrough, 1);
});

test("Checkout produces stable logical evidence identifiers across isolated lanes", async () => {
  const result = await runCheckout("fixed");
  const outcomes = result.bundle.events
    .filter(({ payload }) => payload.kind === "outcome")
    .map(({ payload }) => payload);

  assert.equal(outcomes.length, 2);
  assert.equal(outcomes[0].resource.id, "order_checkout_demo_001");
  assert.equal(outcomes[1].resource.id, "order_checkout_demo_001");
  assert.deepEqual(outcomes[0], outcomes[1]);
  assert.equal(outcomes[0].confirmation, "required_before_purchase");
});

test("Checkout remains inconclusive when a delayed effect cannot reach a settlement watermark", async () => {
  const result = await runCheckout("vulnerable", {
    chargeDelayMs: 100,
    settlementTimeoutMs: 20,
  });

  assert.equal(result.verdict, "inconclusive");
  assert.ok(result.findings.some(({ code }) => code === "effect_settlement_incomplete"));
  const settlement = result.bundle.events.find(({ route, payload }) =>
    route === "agent" && payload.kind === "effect_settlement");
  assert.equal(settlement.payload.status, "inconclusive");
  assert.equal(settlement.payload.reason, "timeout");
  assert.equal(settlement.payload.pendingEffects, 1);
});

test("Checkout is registered as a trusted owned target, not loaded from an arbitrary module", () => {
  const adapter = createCheckoutAuditAdapter({ scheduler: createDeterministicScheduler() });
  const registry = createAdapterRegistry([adapter]);

  assert.deepEqual(registry.list(), [{
    id: "arena.checkout",
    version: "1.0.0",
    claimScope: ["owned_fixture:checkout"],
    trustMode: "server_attested",
  }]);
  assert.equal(registry.get("arena.checkout"), adapter);
});

async function runCheckout(version, options = {}) {
  const scheduler = createDeterministicScheduler();
  const adapter = createCheckoutAuditAdapter({
    scheduler,
    id: sequenceIds(),
    chargeDelayMs: options.chargeDelayMs ?? 25,
    settlementTimeoutMs: options.settlementTimeoutMs ?? 100,
  });
  const recipe = await adapter.createRecipe({
    target: `arena-owned://checkout/?version=${version}`,
  });
  const auditor = createBoundaryAuditor({
    targetHarness: adapter.targetHarness,
    routeRunner: adapter.routeRunner,
    id: sequenceIds("audit"),
  });
  const prepared = await auditor.prepare(recipe);
  return auditor.run({
    planId: prepared.planId,
    approval: {
      status: "approved",
      planId: prepared.planId,
      ...prepared.approvalBinding,
    },
  });
}

function sequenceIds(prefix = "checkout") {
  let value = 0;
  return () => `${prefix}_${++value}`;
}
