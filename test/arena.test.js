import assert from "node:assert/strict";
import test from "node:test";

import { createArenaServer } from "../scripts/arena-server.js";
import { hashArenaAttestation } from "../src/arena-proof.js";
import { createMemoryRepository } from "../src/state-store.js";

test("Arena exposes WebMCP tools and enforces delegated approval over HTTP", async (t) => {
  const server = createArenaServer({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
  });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const page = await fetch(origin).then((response) => response.text());
  const client = await fetch(`${origin}/arena.js`).then((response) => response.text());
  const runtime = await fetch(`${origin}/api/status`).then((response) => response.json());
  assert.match(page, /Arena/);
  assert.match(page, /Authored human route/);
  assert.match(page, /Authored agent route/);
  assert.match(page, /Boundary Rehearsal/);
  assert.match(page, /Synthetic threat lab/);
  assert.match(client, /document\.modelContext\.registerTool/);
  assert.match(client, /AbortController/);
  assert.match(client, /untrustedContentHint/);
  assert.match(client, /exposedTo/);
  assert.doesNotMatch(client, /exposedTo:\["self"\]/);
  assert.match(client, /run_synthetic_fixture[\s\S]*readOnly:false/);
  assert.doesNotThrow(() => new Function(client));
  assert.deepEqual({ identity: runtime.identity_mode, persistence: runtime.persistence, proof: runtime.remote_browser.proof_mode }, {
    identity: "local_demo_allowed",
    persistence: "memory",
    proof: "disabled",
  });
  for (const tool of ["list_incident_scenarios", "select_incident_scenario", "run_synthetic_fixture", "compare_fixed_fixture", "explain_finding", "verify_attestation", "export_ci_artifacts"]) {
    assert.match(client, new RegExp(tool));
  }

  const passport = await json(origin, "/api/passports", {
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:read", "flights:book"],
    maxAmount: 15000,
    ttlSeconds: 1800,
  });
  const search = await json(origin, "/api/tools/execute", {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "search_flights",
    arguments: { from: "DEL", to: "BOM" },
    idempotencyKey: "search-http-1",
  });
  const pending = await json(origin, "/api/tools/execute", {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: search.result.flights[0].id, price: search.result.flights[0].price },
    idempotencyKey: "book-http-1",
  });
  const completed = await json(origin, `/api/approvals/${pending.approval.id}`, {
    principalId: "human_vasu",
    decision: "approved",
  });
  const proofKey = await fetch(`${origin}/.well-known/arena-proof.json`).then((response) => response.json());
  const verification = await json(origin, "/api/proof/verify", { attestation: completed.receipt });
  const state = await fetch(`${origin}/api/state`).then((response) => response.json());

  assert.deepEqual(
    {
      search: search.status,
      bookingBeforeApproval: pending.status,
      bookingAfterApproval: completed.status,
      receiptVerified: completed.receipt_verified,
      receiptAlgorithm: completed.receipt.proof.algorithm,
      publicKeyAlgorithm: proofKey.algorithm,
      independentlyVerified: verification.valid,
      timeline: state.timeline.map((event) => event.status),
      bookings: state.bookings.length,
    },
    {
      search: "executed",
      bookingBeforeApproval: "approval_required",
      bookingAfterApproval: "executed",
      receiptVerified: true,
      receiptAlgorithm: "Ed25519",
      publicKeyAlgorithm: "Ed25519",
      independentlyVerified: true,
      timeline: ["passport_issued", "executed", "approval_required", "approved", "executed"],
      bookings: 1,
    },
  );
});

test("remote WebMCP execution receives a governance permit before the runner is called", async (t) => {
  const calls = [];
  const server = createArenaServer({
    secret: "test-secret-with-enough-entropy",
    remoteInspectionEnabled: true,
    remoteExecutionEnabled: true,
    operatorToken: "operator-secret-with-enough-entropy",
    browserRunner: {
      inspect: async ({ url }) => ({ url, proof_level: "native_browser_api", tools: [{ name: "search" }] }),
      execute: async (input) => {
        calls.push(input);
        return { url: input.url, proof_level: "native_browser_api", tool_name: input.toolName, result: { ok: true } };
      },
    },
  });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const unauthenticated = await post(origin, "/api/browser/inspect", { url: "https://example.com" });
  const inspected = await post(origin, "/api/browser/inspect", { url: "https://example.com" }, "operator-secret-with-enough-entropy");
  const checkboxOnly = await post(origin, "/api/browser/execute", {
    url: "https://example.com",
    toolName: "search",
    arguments: {},
    humanApproval: { approved: true, principalId: "human_vasu" },
  }, "operator-secret-with-enough-entropy");
  const passport = await post(origin, "/api/passports", {
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["browser:execute"],
    ttlSeconds: 1800,
  });
  const pending = await post(origin, "/api/browser/execute", {
    passport: passport.body.token,
    agentId: "chatgpt",
    url: "https://example.com",
    toolName: "search",
    arguments: { query: "DEL to BOM" },
    idempotencyKey: "remote-search-1",
  }, "operator-secret-with-enough-entropy");
  const executed = await post(origin, `/api/approvals/${pending.body.approval.id}`, {
    principalId: "human_vasu",
    decision: "approved",
  });
  const state = await fetch(`${origin}/api/state`).then((response) => response.json());

  assert.deepEqual(
    {
      unauthenticated: unauthenticated.status,
      inspected: inspected.body.proof_level,
      checkboxOnly: checkboxOnly.body.reason,
      pending: pending.body.status,
      executed: executed.body.result.result,
      calls: calls.length,
      recordedOperations: state.browser_runs.map((run) => run.operation),
    },
    {
      unauthenticated: 401,
      inspected: "native_browser_api",
      checkboxOnly: "invalid_passport",
      pending: "approval_required",
      executed: { ok: true },
      calls: 1,
      recordedOperations: ["inspect", "execute"],
    },
  );
});

test("Arena Lab labels authored scenarios as synthetic and refuses caller-authored audit evidence", async (t) => {
  const server = createArenaServer({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
  });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const catalog = await fetch(`${origin}/api/scenarios`).then((response) => response.json());
  const vulnerable = await json(origin, "/api/scenarios/gym_waitlist/run", { version: "vulnerable", mode: "enforce" });
  const fixed = await json(origin, "/api/scenarios/gym_waitlist/run", { version: "fixed", mode: "enforce" });
  const callerAuthoredAudit = await post(origin, "/api/boundary-audits/run", {
    humanRoute: vulnerable.routes.human,
    agentRoute: vulnerable.routes.agent,
    contract: { ...vulnerable.contract, review_status: "approved", approved_by: "attacker" },
    delegation: { principal_id: "human_vasu", constraints: {} },
  });
  const callerAuthoredMining = await post(origin, "/api/contracts/mine", {
    routeName: "attacker_claim",
    trace: vulnerable.routes.human,
  });
  const unregisteredContract = await post(origin, "/api/contracts/approve", {
    principalId: "human_vasu",
    contract: { ...vulnerable.contract, tool_name: "attacker_claim" },
  });
  const approvedContract = await json(origin, "/api/contracts/approve", { principalId: "human_vasu", contract: vulnerable.contract });
  const secondCallerAuthoredAudit = await post(origin, "/api/boundary-audits/run", {
    humanRoute: vulnerable.routes.human,
    agentRoute: vulnerable.routes.agent,
    contract: approvedContract.contract,
    delegation: { principal_id: "human_vasu", constraints: { booking_window: true, resource_owner: "human_vasu" } },
  });
  const verification = await json(origin, "/api/proof/verify", { attestation: vulnerable.attestation });
  const ci = await json(origin, "/api/ci/artifacts", { reports: [vulnerable.report, fixed.report] });
  const agentRegression = await json(origin, "/api/agents/compare", {
    baseline: [{ agent: { provider: "a", model: "m", version: "1", harness: "h" }, trials: 10, completed: 9, refused: 1, unauthorized_attempts: 0, approval_requests: 1, injection_follows: 0 }],
    current: [{ agent: { provider: "a", model: "m", version: "2", harness: "h" }, trials: 10, completed: 10, refused: 0, unauthorized_attempts: 2, approval_requests: 1, injection_follows: 1, arena_denials: 2 }],
  });
  const state = await fetch(`${origin}/api/state`).then((response) => response.json());

  assert.ok(catalog.scenarios.length >= 7);
  assert.deepEqual(
    {
      vulnerable: vulnerable.report.verdict,
      enforcement: vulnerable.enforcement.status,
      fixed: fixed.report.verdict,
      proof: vulnerable.attestation.proof.algorithm,
      proofKind: vulnerable.attestation.kind,
      claimScope: vulnerable.attestation.claim_scope,
      measured: vulnerable.report.measured_by_arena,
      evidenceLevel: vulnerable.report.evidence_level,
      verified: verification.valid,
      storedRuns: state.incident_runs.length,
      ciPassed: ci.summary.passed,
      sarifFindings: ci.sarif.runs[0].results.length,
      agentBoundary: agentRegression.profiles[0].boundary_outcome,
      contractStatus: approvedContract.contract.review_status,
      callerAuthoredAudit: callerAuthoredAudit.status,
      callerAuthoredError: callerAuthoredAudit.body.error,
      callerAuthoredMining: callerAuthoredMining.status,
      unregisteredContract: unregisteredContract.status,
      secondCallerAuthoredAudit: secondCallerAuthoredAudit.status,
      storedContracts: state.effect_contracts.length,
    },
    {
      vulnerable: "fail",
      enforcement: "denied",
      fixed: "pass",
      proof: "Ed25519",
      proofKind: "arena.synthetic_fixture_receipt",
      claimScope: "synthetic_fixture",
      measured: false,
      evidenceLevel: "synthetic_fixture",
      verified: true,
      storedRuns: 2,
      ciPassed: false,
      sarifFindings: vulnerable.report.findings.length,
      agentBoundary: "contained",
      contractStatus: "approved",
      callerAuthoredAudit: 410,
      callerAuthoredError: "caller-authored boundary evidence is no longer accepted; use the recorder-owned target audit",
      callerAuthoredMining: 410,
      unregisteredContract: 403,
      secondCallerAuthoredAudit: 410,
      storedContracts: 1,
    },
  );
});

test("production human routes reject callers without the operator credential", async (t) => {
  const server = createArenaServer({
    secret: "test-secret-with-enough-entropy",
    protectHumanRoutes: true,
    operatorToken: "operator-secret-with-enough-entropy",
  });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const passportBody = {
    principalId: "human_vasu",
    agentId: "local_test_agent",
    scopes: ["flights:read", "flights:book"],
    maxAmount: 15000,
    ttlSeconds: 60,
  };

  const deniedPassport = await post(origin, "/api/passports", passportBody);
  const allowedPassport = await post(origin, "/api/passports", passportBody, "operator-secret-with-enough-entropy");
  const deniedState = await fetch(`${origin}/api/state`);
  const allowedState = await fetch(`${origin}/api/state`, { headers: { authorization: "Bearer operator-secret-with-enough-entropy" } });
  const pending = await post(origin, "/api/tools/execute", {
    passport: allowedPassport.body.token,
    agentId: "local_test_agent",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "protected-booking",
  });
  const deniedApproval = await post(origin, `/api/approvals/${pending.body.approval.id}`, { principalId: "human_vasu", decision: "approved" });
  const allowedApproval = await post(origin, `/api/approvals/${pending.body.approval.id}`, { principalId: "human_vasu", decision: "approved" }, "operator-secret-with-enough-entropy");

  assert.deepEqual(
    {
      deniedPassport: deniedPassport.status,
      allowedPassport: allowedPassport.status,
      passportAgent: allowedPassport.body.delegation.agent_id,
      deniedState: deniedState.status,
      allowedState: allowedState.status,
      deniedApproval: deniedApproval.status,
      allowedApproval: allowedApproval.status,
    },
    {
      deniedPassport: 401,
      allowedPassport: 200,
      passportAgent: "local_test_agent",
      deniedState: 401,
      allowedState: 200,
      deniedApproval: 401,
      allowedApproval: 200,
    },
  );
});

test("the public proof chain survives an Arena server restart", async () => {
  const repository = createMemoryRepository();
  const firstServer = createArenaServer({ secret: "test-secret-with-enough-entropy", repository });
  await listen(firstServer);
  const firstOrigin = `http://127.0.0.1:${firstServer.address().port}`;
  const first = await json(firstOrigin, "/api/scenarios/gym_waitlist/run", { version: "vulnerable", mode: "enforce" });
  await close(firstServer);

  const secondServer = createArenaServer({ secret: "test-secret-with-enough-entropy", repository });
  await listen(secondServer);
  const secondOrigin = `http://127.0.0.1:${secondServer.address().port}`;
  const second = await json(secondOrigin, "/api/scenarios/gym_waitlist/run", { version: "fixed", mode: "enforce" });
  await close(secondServer);

  assert.equal(second.attestation.previous_attestation_hash, hashArenaAttestation(first.attestation));
});

test("two live Arena workers issue one serialized proof chain", async () => {
  const repository = createMemoryRepository();
  const firstServer = createArenaServer({ secret: "test-secret-with-enough-entropy", repository });
  const secondServer = createArenaServer({ secret: "test-secret-with-enough-entropy", repository });
  await listen(firstServer);
  await listen(secondServer);
  const firstOrigin = `http://127.0.0.1:${firstServer.address().port}`;
  const secondOrigin = `http://127.0.0.1:${secondServer.address().port}`;

  const first = await json(firstOrigin, "/api/scenarios/gym_waitlist/run", { version: "vulnerable", mode: "enforce" });
  const second = await json(secondOrigin, "/api/scenarios/gym_waitlist/run", { version: "fixed", mode: "enforce" });
  await close(firstServer);
  await close(secondServer);

  assert.equal(second.attestation.previous_attestation_hash, hashArenaAttestation(first.attestation));
});

test("the persisted proof issuer never stores its private signing key in plaintext", () => {
  const repository = createMemoryRepository();
  createArenaServer({ secret: "test-secret-with-enough-entropy", repository });

  const persisted = JSON.stringify(repository.read("proof_keys", null));

  assert.doesNotMatch(persisted, /BEGIN PRIVATE KEY|PRIVATE KEY-----/);
  assert.match(persisted, /A256GCM/);
});

async function json(origin, path, body) {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(response.status, 200);
  return response.json();
}

async function post(origin, path, body, token = "") {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function sequenceIds() {
  let value = 0;
  return () => `id_${++value}`;
}
