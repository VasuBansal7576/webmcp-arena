import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { createBoundaryAuditor } from "../src/boundary-audit.js";
import { createGymAuditAdapters } from "../src/gym-audit-adapter.js";
import { hashWebMcpToolDefinition } from "../src/webmcp-runner.js";

const TARGET = "http://127.0.0.1:41789/?arena_version=fixed";
const FIXTURE_TOKEN = "adversarial-fixture-token";

test("empty, unisolated browser claims cannot produce an attestable pass", async () => {
  const fixture = fakeFixture();
  const adapters = adaptersFor({ fixture, humanTrace: emptyTrace, agentTrace: emptyTrace });

  await assert.rejects(() => runAudit(adapters), /proof level|isolated|measured execution evidence/i);
});

test("an incomplete browser capture cannot produce a decisive audit", async () => {
  const fixture = fakeFixture({ eventsForRun: matchingAuthorizationEvents });
  const adapters = adaptersFor({
    fixture,
    humanTrace: () => trace({ capture: { complete: false, reason: "timeout", waited_ms: 1500, pending_requests: 1 } }),
  });

  await assert.rejects(() => runAudit(adapters), /effect capture.*complete|incomplete browser effect capture/i);
});

test("validated agent execution transport is retained in the recorder proof", async () => {
  const fixture = fakeFixture({ eventsForRun: matchingAuthorizationEvents });
  const result = await runAudit(adaptersFor({ fixture }));
  const proofs = result.bundle.events.filter((event) => event.payload?.kind === "execution_proof");

  assert.equal(result.verdict, "pass");
  assert.equal(result.baselineSafety.status, "pass");
  assert.equal(result.bundle.contract.invariants.requireAuthorizationBeforeEffect, true);
  assert.deepEqual(result.bundle.contract.invariants.allowedAuthorizationRules, ["booking_window"]);
  assert.deepEqual(
    proofs.map((event) => ({ route: event.route, transport: event.payload.executionTransport })),
    [{ route: "human", transport: null }, { route: "agent", transport: "cdp_browser_agent" }],
  );

  const invalid = adaptersFor({
    fixture: fakeFixture({ eventsForRun: matchingAuthorizationEvents }),
    agentTrace: () => ({ ...trace(), execution_transport: "page_claimed_native" }),
  });
  await assert.rejects(() => runAudit(invalid), /execution transport/i);
});

test("capture timing is eligibility metadata, not part of the approved security contract", async () => {
  let humanRuns = 0;
  const adapters = adaptersFor({
    fixture: fakeFixture({ eventsForRun: matchingAuthorizationEvents }),
    humanTrace: () => trace({
      capture: {
        complete: true,
        reason: "quiescent",
        waited_ms: humanRuns++ === 0 ? 300 : 301,
        pending_requests: 0,
      },
    }),
  });

  const result = await runAudit(adapters);

  assert.equal(result.verdict, "pass");
  assert.equal(JSON.stringify(result.bundle).includes("waited_ms"), false);
  assert.equal(JSON.stringify(result.bundle).includes("captureWaitedMs"), false);
});

test("page-authored protection strings cannot leak raw secrets into an evidence bundle", async () => {
  const secret = "customer-password=correct-horse-battery-staple";
  const fixture = fakeFixture();
  const traceWithSecret = () => trace({ protections: [secret] });
  const adapters = adaptersFor({ fixture, humanTrace: traceWithSecret, agentTrace: traceWithSecret });

  const result = await runAudit(adapters);

  assert.equal(JSON.stringify(result.bundle).includes(secret), false);
});

test("redacted network value divergence is not erased during normalization", async () => {
  const fixture = fakeFixture({ eventsForRun: matchingAuthorizationEvents });
  const request = (valueHmac) => ({
    method: "POST",
    url: "https://payments.example.test/charge",
    status: 201,
    query: [{ name: "member", value_hmac: valueHmac }],
    body: { json_keys: ["amount", "currency"], value_hmac: valueHmac },
  });
  const adapters = adaptersFor({
    fixture,
    humanTrace: () => trace({ network: [request("A".repeat(43))] }),
    agentTrace: () => trace({ network: [request("B".repeat(43))] }),
  });

  const result = await runAudit(adapters);

  assert.equal(result.verdict, "fail");
  assert.equal(result.baselineSafety.status, "fail");
  assert.ok(result.findings.some((finding) => finding.code === "network_effect_changed"));
});

test("same-origin requests remain observable and expose an extra consequential endpoint", async () => {
  const fixture = fakeFixture({ eventsForRun: matchingAuthorizationEvents });
  const adapters = adaptersFor({
    fixture,
    humanTrace: ({ url }) => trace({
      network: [{ method: "POST", url: `${new URL(url).origin}/api/human/book`, status: 409, query: [], body: null }],
    }),
    agentTrace: ({ url }) => trace({
      network: [
        { method: "POST", url: `${new URL(url).origin}/api/agent/book`, status: 409, query: [], body: null },
        { method: "POST", url: `${new URL(url).origin}/api/admin/delete`, status: 204, query: [], body: null },
      ],
    }),
  });

  const result = await runAudit(adapters);

  assert.equal(result.verdict, "fail");
  assert.equal(result.baselineSafety.status, "pass");
  assert.ok(result.findings.some((finding) => finding.code === "network_effect_changed"));
});

test("events with foreign correlation and page authority cannot become server-attested evidence", async () => {
  const fixture = fakeFixture({
    eventsForRun: () => [{
      kind: "authorization",
      run_id: "foreign_run",
      trial_id: "foreign_trial",
      provenance: "page_asserted",
      authority: "browser_page",
      decision: "allow",
      rule: "spoofed_allow",
    }],
  });
  const adapters = adaptersFor({ fixture });
  const established = await adapters.targetHarness.establish({ target: TARGET, principalRef: "fixture:human_vasu" });
  const handle = await adapters.targetHarness.provision({
    targetRef: established.targetRef,
    seedDigest: established.seedDigest,
    route: "human",
  });

  try {
    await assert.rejects(
      () => adapters.routeRunner.runHuman({ target: handle, actions: [{ type: "click", selector: "#human-book" }] }),
      /event.*(?:run|trial|authority)|correlation|server-attested/i,
    );
  } finally {
    await adapters.targetHarness.release(handle);
  }
});

test("authoritative event sequence is preserved even when mutation precedes authorization", async () => {
  const fixture = fakeFixture({
    eventsForRun: ({ runId, trialId }) => [
      {
        ...eventEnvelope({ runId, trialId, sequence: 1 }),
        kind: "mutation",
        resource: { type: "gym_reservation", id: "yoga_101:human_vasu", owner: "human_vasu" },
        before: null,
        after: "booked_early",
      },
      {
        ...eventEnvelope({ runId, trialId, sequence: 2 }),
        kind: "authorization",
        decision: "allow",
        rule: "late_authorization",
      },
    ],
  });
  const adapters = adaptersFor({ fixture });
  const established = await adapters.targetHarness.establish({ target: TARGET, principalRef: "fixture:human_vasu" });
  const handle = await adapters.targetHarness.provision({
    targetRef: established.targetRef,
    seedDigest: established.seedDigest,
    route: "human",
  });

  try {
    const observation = await adapters.routeRunner.runHuman({ target: handle, actions: [{ type: "click", selector: "#human-book" }] });
    assert.deepEqual(observation.server.map((event) => event.kind), ["state", "authorization", "final_state"]);
    assert.ok(observation.server[0].order < observation.server[1].order);
  } finally {
    await adapters.targetHarness.release(handle);
  }
});

test("release refuses forged handles without making a network request", async () => {
  const calls = [];
  const adapters = createGymAuditAdapters({
    browserRunner: browserRunner(),
    fixtureToken: FIXTURE_TOKEN,
    fetchImpl: async (url, options = {}) => {
      calls.push({ url: String(url), method: options.method || "GET" });
      return response(404, { error: "not_found" });
    },
  });

  await assert.rejects(
    () => adapters.targetHarness.release({
      kind: "gym_boundary",
      origin: "http://169.254.169.254",
      trialId: "forged_trial",
      released: false,
    }),
    /issued|live Gym trial handle/i,
  );
  assert.deepEqual(calls, []);
});

test("a cross-origin trial path cannot redirect the browser away from the audited fixture", async () => {
  const fixture = fakeFixture({
    pathForTrial: ({ trialId }) => trialId === "trial_2"
      ? "http://169.254.169.254/latest/meta-data"
      : `/?arena_trial=${trialId}`,
  });
  const adapters = adaptersFor({ fixture });
  const established = await adapters.targetHarness.establish({ target: TARGET, principalRef: "fixture:human_vasu" });

  await assert.rejects(
    () => adapters.targetHarness.provision({
      targetRef: established.targetRef,
      seedDigest: established.seedDigest,
      route: "human",
    }),
    /relative to the audited origin|escaped the audited origin/i,
  );
  assert.ok(fixture.deletedTrials.includes("trial_2"), "the rejected cross-origin trial must be released");
});

test("a trial is released when its descriptor cannot be converted into a route handle", async () => {
  const fixture = fakeFixture({
    pathForTrial: ({ trialId }) => trialId === "trial_2" ? "http://[" : `/?arena_trial=${trialId}`,
  });
  const adapters = adaptersFor({ fixture });
  const established = await adapters.targetHarness.establish({ target: TARGET, principalRef: "fixture:human_vasu" });

  await assert.rejects(
    () => adapters.targetHarness.provision({
      targetRef: established.targetRef,
      seedDigest: established.seedDigest,
      route: "human",
    }),
    /trial path|Invalid URL/i,
  );
  assert.ok(fixture.deletedTrials.includes("trial_2"), "the acquired trial must be released after handle construction fails");
});

test("the execution trace must confirm the inspected tool definition hash", async () => {
  const fixture = fakeFixture();
  const adapters = adaptersFor({
    fixture,
    humanTrace: () => trace(),
    agentTrace: () => ({ ...trace(), tool_definition_hash: "changed-after-inspection" }),
  });

  await assert.rejects(() => runAudit(adapters), /tool definition hash.*(?:match|changed)|hash.*mismatch/i);
});

async function runAudit(adapters) {
  const recipe = await adapters.createRecipe({ target: TARGET, memberId: "human_vasu" });
  const auditor = createBoundaryAuditor({ targetHarness: adapters.targetHarness, routeRunner: adapters.routeRunner });
  const prepared = await auditor.prepare(recipe);
  return auditor.run({
    planId: prepared.planId,
    approval: { status: "approved", planId: prepared.planId, ...prepared.approvalBinding },
  });
}

function adaptersFor({ fixture, humanTrace = () => trace(), agentTrace = () => trace() }) {
  return createGymAuditAdapters({
    browserRunner: browserRunner({ humanTrace, agentTrace }),
    fixtureToken: FIXTURE_TOKEN,
    fetchImpl: fixture.fetchImpl,
    id: sequenceIds(),
    redactionKey: Buffer.alloc(32, 7),
  });
}

function browserRunner({ humanTrace = () => trace(), agentTrace = () => trace() } = {}) {
  return {
    async inspect({ url }) {
      return {
        proof_level: "native_browser_api",
        tools: [toolDefinition(new URL(url).origin)],
      };
    },
    async recordHumanRoute(input) {
      const definition = toolDefinition(new URL(input.url).origin);
      return completeTrace(humanTrace(input), input.url, hashWebMcpToolDefinition(definition));
    },
    async execute(input) {
      const result = completeTrace(agentTrace(input), input.url, input.expectedToolHash);
      if (!result.execution_transport) {
        result.execution_transport = result.proof_level === "compatibility_shim" ? "object" : "cdp_browser_agent";
      }
      return result;
    },
  };
}

function toolDefinition(origin) {
  return {
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
    origin,
  };
}

function completeTrace(value, url, expectedToolHash) {
  const result = structuredClone(value);
  result.url = url;
  if (result.proof_level === "unknown") return result;
  if (!result.tool_definition_hash) result.tool_definition_hash = expectedToolHash;
  if (!Array.isArray(result.effect_trace.tool_definitions) || !result.effect_trace.tool_definitions.length) {
    result.effect_trace.tool_definitions = [{ name: "book_gym_class", hash: expectedToolHash }];
  }
  return result;
}

function emptyTrace() {
  return { proof_level: "unknown", isolated_context: false, effect_trace: {} };
}

function trace({
  network = [],
  protections = [],
  capture = { complete: true, reason: "quiescent", waited_ms: 100, pending_requests: 0 },
} = {}) {
  return {
    proof_level: "native_browser_api",
    isolated_context: true,
    tool_definition_hash: null,
    effect_trace: {
      proof_level: "native_browser_api",
      capture,
      network,
      ui: { after_value_hashes: { "#status": "C".repeat(43) } },
      tool_definitions: [],
      page_assertions: { protections, approvals: [] },
    },
  };
}

function fakeFixture({ eventsForRun = () => [], pathForTrial = ({ trialId }) => `/?arena_trial=${trialId}` } = {}) {
  const calls = [];
  const deletedTrials = [];
  const trials = new Map();
  let trialNumber = 0;

  async function fetchImpl(rawUrl, options = {}) {
    const url = new URL(rawUrl);
    const method = options.method || "GET";
    calls.push({ url: url.href, method });

    if (method === "POST" && url.pathname === "/__arena/provision") {
      const version = JSON.parse(options.body).version;
      const trialId = `trial_${++trialNumber}`;
      trials.set(trialId, version);
      return response(201, {
        fixture: "gym_boundary",
        version,
        trial_id: trialId,
        seed_digest: digest("stable-seed-digest"),
        path: pathForTrial({ trialId, version }),
      });
    }

    if (method === "DELETE" && url.pathname.startsWith("/__arena/trials/")) {
      const trialId = decodeURIComponent(url.pathname.slice("/__arena/trials/".length));
      deletedTrials.push(trialId);
      trials.delete(trialId);
      return response(200, { status: "released", trial_id: trialId });
    }

    if (method === "GET" && url.pathname === "/__arena/evidence") {
      const trialId = url.searchParams.get("trial_id");
      const runId = url.searchParams.get("run_id");
      return response(200, {
        fixture: "gym_boundary",
        trial_id: trialId,
        version: trials.get(trialId),
        seed_digest: digest("stable-seed-digest"),
        state: { booking_open: false, reservations: {} },
        events: eventsForRun({ runId, trialId, version: trials.get(trialId) }),
      });
    }

    return response(404, { error: "not_found" });
  }

  return { fetchImpl, calls, deletedTrials };
}

function matchingAuthorizationEvents({ runId, trialId }) {
  return [{
    ...eventEnvelope({ runId, trialId, sequence: 1 }),
    kind: "authorization",
    decision: "deny",
    rule: "booking_window",
  }];
}

function eventEnvelope({ runId, trialId, sequence }) {
  const agentRoute = runId.includes("_agent_");
  return {
    id: `event_${sequence}`,
    run_id: runId,
    trial_id: trialId,
    sequence,
    observed_at: "2026-08-30T10:00:00.000Z",
    provenance: "synthetic_fixture",
    authority: "application_backend",
    tool_name: agentRoute ? "book_gym_class" : "human_book_gym_class",
    arguments_hash: agentRoute
      ? digest('{"classId":"yoga_101","memberId":"human_vasu"}')
      : digest('{"classId":"yoga_101"}'),
  };
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function response(status, body) {
  return {
    status,
    ok: status >= 200 && status < 300,
    async json() {
      return structuredClone(body);
    },
  };
}

function sequenceIds() {
  let value = 0;
  return () => `adversarial_${++value}`;
}
