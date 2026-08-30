import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { createBoundaryAuditor } from "../src/boundary-audit.js";
import { createGymAuditAdapters } from "../src/gym-audit-adapter.js";
import { createGymFixtureServer } from "../src/gym-fixture.js";
import { hashWebMcpToolDefinition } from "../src/webmcp-runner.js";

const fixtureToken = "gym-adapter-fixture-token";

test("the BoundaryAuditor fails a real vulnerable Gym route and passes its repaired route", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;
  const browserRunner = fixtureBrowserRunner();
  const adapters = createGymAuditAdapters({ browserRunner, fixtureToken, id: sequenceIds() });

  const vulnerable = await runAudit(adapters, `${origin}/?arena_version=vulnerable`);
  const fixed = await runAudit(adapters, `${origin}/?arena_version=fixed`);

  assert.equal(vulnerable.verdict, "fail");
  assert.ok(vulnerable.findings.some((finding) => finding.code === "effect_mismatch"));
  assert.ok(vulnerable.findings.some((finding) => finding.code === "authorization_outcome_changed"));
  assert.ok(vulnerable.findings.some((finding) => finding.code === "unexpected_consequential_effect"));
  assert.equal(fixed.verdict, "pass");
  assert.equal(fixed.routeParity.status, "pass");
  assert.equal(fixed.baselineSafety.status, "pass");
  assert.equal(fixed.coverage.complete, true);
  assert.equal(fixed.assurance.tier, "compatibility");
  assert.equal(fixed.attestation.eligible, false);
  assert.ok(vulnerable.bundle.events.some((event) => event.payload.kind === "state"));
  assert.ok(vulnerable.bundle.events.some((event) => event.provenance === "server_attested"));
  assert.equal(JSON.stringify(vulnerable.bundle).includes("another_member"), false);

  for (const trialId of browserRunner.trialIds) {
    const released = await fetch(`${origin}/__arena/evidence?run_id=probe&trial_id=${trialId}`, {
      headers: { "x-arena-fixture-token": fixtureToken },
    });
    assert.equal(released.status, 404, `trial ${trialId} should be released`);
  }
});

test("the Gym adapter rejects non-local targets before provisioning a consequential route", async () => {
  const adapters = createGymAuditAdapters({ browserRunner: fixtureBrowserRunner(), fixtureToken });
  await assert.rejects(
    () => adapters.targetHarness.establish({ target: "https://example.com/?arena_version=vulnerable", principalRef: "fixture:human_vasu" }),
    /local loopback target/,
  );
});

async function runAudit(adapters, target) {
  const recipe = await adapters.createRecipe({ target, memberId: "human_vasu" });
  const auditor = createBoundaryAuditor({ targetHarness: adapters.targetHarness, routeRunner: adapters.routeRunner });
  const prepared = await auditor.prepare(recipe);
  return auditor.run({
    planId: prepared.planId,
    approval: { status: "approved", planId: prepared.planId, ...prepared.approvalBinding },
  });
}

function fixtureBrowserRunner() {
  const definition = {
    name: "book_gym_class",
    title: "Book gym class",
    description: "Attempt to book a gym class for a member.",
    inputSchema: {
      type: "object",
      properties: { classId: { type: "string" }, memberId: { type: "string" } },
      required: ["classId", "memberId"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, untrustedContentHint: false },
    origin: null,
  };
  const definitionHash = hashWebMcpToolDefinition(definition);
  const trialIds = [];

  return {
    trialIds,
    async inspect({ url }) {
      const parsed = new URL(url);
      trialIds.push(parsed.searchParams.get("arena_trial"));
      return { proof_level: "compatibility_shim", tools: [{ ...definition, origin: parsed.origin }] };
    },
    async recordHumanRoute({ url }) {
      const target = new URL(url);
      const trialId = target.searchParams.get("arena_trial");
      const runId = target.searchParams.get("arena_run_id");
      trialIds.push(trialId);
      const result = await post(target.origin, "/api/human/book", trialId, runId, { classId: "yoga_101" });
      return trace(target.href, definitionHashForOrigin(target.origin), result, "/api/human/book");
    },
    async execute({ url, arguments: args, expectedToolHash }) {
      const target = new URL(url);
      const trialId = target.searchParams.get("arena_trial");
      const runId = target.searchParams.get("arena_run_id");
      trialIds.push(trialId);
      assert.equal(expectedToolHash, definitionHashForOrigin(target.origin));
      const result = await post(target.origin, "/api/agent/book", trialId, runId, args);
      return trace(target.href, expectedToolHash, result, "/api/agent/book", "object");
    },
  };

  function definitionHashForOrigin(origin) {
    return hashWebMcpToolDefinition({ ...definition, origin });
  }
}

function trace(targetUrl, definitionHash, result, path, executionTransport = null) {
  const origin = new URL(targetUrl).origin;
  const visible = result.status === "booked" ? "Booking confirmed" : `Booking blocked: ${result.reason}`;
  return {
    url: targetUrl,
    proof_level: "compatibility_shim",
    isolated_context: true,
    execution_transport: executionTransport,
    tool_definition_hash: definitionHash,
    effect_trace: {
      capture: { complete: true, reason: "quiescent", waited_ms: 100, pending_requests: 0 },
      network: [{ method: "POST", url: `${origin}${path}`, status: result.status === "booked" ? 201 : 409, query: [], body: null }],
      ui: { changed: ["#status"], after_value_hashes: { "#status": digest(visible) } },
      tool_definitions: [{ name: "book_gym_class", hash: definitionHash }],
      page_assertions: { provenance: "page_asserted", protections: [], approvals: [] },
      state: { before: {}, after: {} },
    },
  };
}

async function post(origin, path, trialId, runId, body) {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-arena-trial-id": trialId,
      "x-arena-run-id": runId,
    },
    body: JSON.stringify(body),
  });
  return response.json();
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function sequenceIds() {
  let value = 0;
  return () => `adapter_${++value}`;
}
