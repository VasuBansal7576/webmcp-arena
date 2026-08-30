import assert from "node:assert/strict";
import test from "node:test";

import { createArenaServer } from "../scripts/arena-server.js";
import { createBoundaryAuditor } from "../src/boundary-audit.js";

test("the bundle inspection endpoint verifies unsigned semantic evidence without claiming producer authenticity", async (t) => {
  const server = createArenaServer({ secret: "test-secret-with-enough-entropy" });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bundle = await createUnsignedBoundaryBundle();

  const response = await fetch(`${origin}/api/boundary-bundles/inspect`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bundle }),
  });
  const inspection = await response.json();
  const serialized = JSON.stringify(inspection);

  assert.equal(response.status, 200);
  assert.deepEqual(
    {
      kind: inspection.kind,
      source: inspection.source,
      valid: inspection.verification.valid,
      hashValid: inspection.verification.hash_valid,
      authenticity: inspection.authenticity.status,
      verdict: inspection.summary.verdict,
      routeParity: inspection.layers.route_parity.status,
      baselineSafety: inspection.layers.baseline_safety.status,
      findings: inspection.summary.finding_codes,
      coverage: inspection.summary.coverage.complete,
      assurance: inspection.summary.assurance.tier,
      tool: inspection.contract.tool_name,
      effectKinds: inspection.contract.effect_kinds,
      routes: [...new Set(inspection.timeline.events.map((event) => event.route))],
      provenances: [...new Set(inspection.timeline.events.map((event) => event.provenance))],
    },
    {
      kind: "arena.boundary_bundle_inspection",
      source: "semantically_consistent_boundary_bundle",
      valid: true,
      hashValid: true,
      authenticity: "unsigned",
      verdict: "fail",
      routeParity: "fail",
      baselineSafety: "not_evaluated",
      findings: ["resource_owner_changed", "money_amount_changed", "money_currency_changed"],
      coverage: true,
      assurance: "native",
      tool: "book_flight",
      effectKinds: ["execution_proof", "state"],
      routes: ["human", "agent"],
      provenances: ["recorder_observed", "server_attested", "page_asserted"],
    },
  );
  assert.ok(inspection.timeline.rows.every((row) => Object.hasOwn(row, "human") && Object.hasOwn(row, "agent")));
  assert.ok(inspection.timeline.events.every((event) => Number.isSafeInteger(event.sequence) && event.kind));
  assert.ok(inspection.differences.some((difference) =>
    difference.finding_codes.includes("money_amount_changed") &&
    difference.human?.value?.amount === 12000 &&
    difference.agent?.value?.amount === 25000));
  assert.deepEqual(inspection.capture_gaps, []);
  assert.doesNotMatch(serialized, /human_vasu|other_member|page-secret-must-not-leak/);
});

test("tampered, synthetic, and externally untrusted bundles are never presented as authenticated evidence", async (t) => {
  const server = createArenaServer({ secret: "test-secret-with-enough-entropy" });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const bundle = await createUnsignedBoundaryBundle();

  const tampered = structuredClone(bundle);
  tampered.events[1].payload.after.amount = 1;
  const tamperedResponse = await inspect(origin, tampered);
  assert.deepEqual(
    {
      status: tamperedResponse.response.status,
      source: tamperedResponse.body.source,
      semanticValid: tamperedResponse.body.verification.semantic_valid,
      hashValid: tamperedResponse.body.verification.hash_valid,
      verdict: tamperedResponse.body.summary.verdict,
      timelineVerified: tamperedResponse.body.timeline.verified,
      trustedSources: tamperedResponse.body.timeline.events.filter((event) => event.trusted_source).length,
      differences: tamperedResponse.body.differences,
    },
    {
      status: 200,
      source: "unverified_boundary_bundle",
      semanticValid: false,
      hashValid: false,
      verdict: "unverified",
      timelineVerified: false,
      trustedSources: 0,
      differences: [],
    },
  );

  const externallySigned = structuredClone(bundle);
  externallySigned.attestation = { eligible: true, proof: { signature: "not-backed-by-a-configured-trust-anchor" } };
  const signedResponse = await inspect(origin, externallySigned);
  assert.deepEqual(
    {
      valid: signedResponse.body.verification.valid,
      semanticValid: signedResponse.body.verification.semantic_valid,
      reason: signedResponse.body.verification.reason,
      authenticity: signedResponse.body.authenticity,
      verdict: signedResponse.body.summary.verdict,
    },
    {
      valid: false,
      semanticValid: true,
      reason: "attestation_unverified",
      authenticity: { status: "signer_untrusted", proof_present: true, authenticated: false },
      verdict: "fail",
    },
  );

  const syntheticResponse = await inspect(origin, {
    kind: "arena.boundary_evidence_bundle",
    version: 1,
    source: "synthetic_fixture",
  });
  assert.equal(syntheticResponse.response.status, 400);
  assert.match(syntheticResponse.body.error, /authored incident fixtures are not measured/);
});

test("the workbench keeps boundary bundle inspection separate from authored incident fixtures", async (t) => {
  const server = createArenaServer({ secret: "test-secret-with-enough-entropy" });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const [pageResponse, scriptResponse] = await Promise.all([
    fetch(origin),
    fetch(`${origin}/arena.js`),
  ]);
  const page = await pageResponse.text();
  const script = await scriptResponse.text();

  assert.equal(pageResponse.status, 200);
  assert.equal(scriptResponse.status, 200);
  assert.match(page, /Synthetic threat lab/);
  assert.match(page, /Authored human route/);
  assert.match(page, /Authored agent route/);
  assert.match(page, /Measured Boundary Bundle/);
  assert.match(page, /data-evidence-source="submitted-boundary-bundle"/);
  for (const id of [
    "measured-bundle-input",
    "measured-verify-button",
    "measured-authenticity-state",
    "measured-contract-summary",
    "measured-route-parity-state",
    "measured-baseline-safety-state",
    "measured-human-timeline",
    "measured-agent-timeline",
    "measured-capture-gaps",
    "measured-differences",
  ]) assert.match(page, new RegExp(`id="${id}"`));
  assert.match(script, /inspect_boundary_bundle/);
  assert.match(script, /\/api\/boundary-bundles\/inspect/);
  assert.match(script, /renderBoundaryInspection/);
  assert.doesNotThrow(() => new Function(script));
});

async function createUnsignedBoundaryBundle() {
  const human = observation({ amount: 12000, currency: "INR", owner: "human_vasu" });
  const agent = observation({ amount: 25000, currency: "USD", owner: "other_member" });
  const auditor = createBoundaryAuditor({
    targetHarness: targetHarness(),
    routeRunner: {
      async runHuman() {
        return structuredClone(human);
      },
      async runAgent() {
        return structuredClone(agent);
      },
    },
    now: () => new Date("2026-08-30T10:00:00.000Z"),
    id: sequenceIds(),
  });
  const prepared = await auditor.prepare({
    target: "https://owned.example.test/checkout",
    principalRef: "principal:human_vasu",
    human: { actions: [{ type: "click", selector: "#book" }] },
    agent: {
      toolName: "book_flight",
      toolDefinitionHash: "definition-hash",
      arguments: { flightId: "AI-202", price: 12000 },
    },
  });
  const result = await auditor.run({
    planId: prepared.planId,
    approval: { status: "approved", planId: prepared.planId, ...prepared.approvalBinding },
  });
  return result.bundle;
}

function observation({ amount, currency, owner }) {
  return {
    recorder: [{
      order: 1,
      kind: "execution_proof",
      level: "native_browser_api",
      isolatedContext: true,
      executionTransport: "cdp_browser_agent",
      captureComplete: true,
      captureReason: "quiescent",
      captureWaitedMs: 300,
      pendingRequests: 0,
    }],
    server: [{
      order: 10,
      kind: "state",
      resource: { type: "flight_booking", id: "booking_1", owner },
      before: { status: "pending", amount: 0, currency },
      after: { status: "confirmed", amount, currency },
    }],
    page: [{ order: 20, kind: "page_context", note: "page-secret-must-not-leak" }],
  };
}

function targetHarness() {
  return {
    async establish() {
      return { owned: true, targetRef: "owned_target", seedDigest: "S".repeat(43) };
    },
    async provision({ route, seedDigest }) {
      return { route, seedDigest };
    },
    async release() {},
  };
}

function sequenceIds() {
  let value = 0;
  return () => `bundle_view_${++value}`;
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

async function inspect(origin, bundle) {
  const response = await fetch(`${origin}/api/boundary-bundles/inspect`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ bundle }),
  });
  return { response, body: await response.json() };
}
