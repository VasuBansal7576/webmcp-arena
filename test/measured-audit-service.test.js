import assert from "node:assert/strict";
import test from "node:test";

import { createMeasuredAuditService } from "../src/measured-audit-service.js";
import { createMemoryRepository } from "../src/state-store.js";

test("an agent can start and poll a preset audit while only the human callback can approve execution", async () => {
  const repository = createMemoryRepository();
  let humanDecision;
  let runCount = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository,
    clock: fixedClock("2026-08-30T10:00:00.000Z"),
    id: () => "audit_1",
    async prepare({ preset }) {
      assert.deepEqual(preset, { recipe: "server-owned" });
      return {
        execution: { planId: "private_plan" },
        review: { contractHash: "reviewed_hash", effectKinds: ["authorization", "state"] },
        expiresAt: "2026-08-30T10:10:00.000Z",
      };
    },
    async run({ execution, approval }) {
      runCount += 1;
      assert.deepEqual(execution, { planId: "private_plan" });
      assert.deepEqual(approval, {
        status: "approved",
        humanId: "human_vasu",
        approvedAt: "2026-08-30T10:00:00.000Z",
      });
      return { verdict: "pass", bundleHash: "bundle_hash" };
    },
    onApprovalRequired({ audit, decide }) {
      assert.equal(audit.state, "awaiting_approval");
      humanDecision = decide;
    },
  });

  const started = await service.start({
    presetId: "gym_booking",
    idempotencyKey: "agent-request-1",
    actor: { type: "agent", id: "browser_agent" },
  });

  assert.equal(started.state, "awaiting_approval");
  assert.deepEqual(started.review, { contractHash: "reviewed_hash", effectKinds: ["authorization", "state"] });
  assert.equal(Object.hasOwn(started, "execution"), false);
  assert.equal(service.approve, undefined);
  assert.equal(typeof humanDecision, "function");
  assert.equal((await service.poll({ auditId: "audit_1", actor: { type: "agent", id: "browser_agent" } })).state, "awaiting_approval");

  const completed = await humanDecision({ decision: "approve", humanId: "human_vasu" });

  assert.equal(runCount, 1);
  assert.equal(completed.state, "completed");
  assert.deepEqual(completed.result, { verdict: "pass", bundleHash: "bundle_hash" });
  assert.deepEqual(completed.history.map((entry) => entry.state), [
    "preparing",
    "awaiting_approval",
    "running",
    "waiting_for_effects",
    "completed",
  ]);
});

test("concurrent retries of the same start request prepare one audit", async () => {
  const repository = createMemoryRepository();
  let releasePreparation;
  const preparationGate = new Promise((resolve) => { releasePreparation = resolve; });
  let prepareCount = 0;
  let approvalRequestCount = 0;
  let nextId = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository,
    clock: fixedClock("2026-08-30T10:00:00.000Z"),
    id: () => `audit_${++nextId}`,
    async prepare() {
      prepareCount += 1;
      await preparationGate;
      return { execution: { planId: "private_plan" }, review: { contractHash: "reviewed_hash" } };
    },
    async run() {
      return { verdict: "pass" };
    },
    onApprovalRequired() {
      approvalRequestCount += 1;
    },
  });
  const request = {
    presetId: "gym_booking",
    idempotencyKey: "same-agent-request",
    actor: { type: "agent", id: "browser_agent" },
  };

  const first = service.start(request);
  const retry = service.start(structuredClone(request));
  releasePreparation();
  const [firstResult, retryResult] = await Promise.all([first, retry]);
  const laterRetry = await service.start(structuredClone(request));

  assert.equal(prepareCount, 1);
  assert.equal(approvalRequestCount, 1);
  assert.equal(firstResult.id, "audit_1");
  assert.equal(retryResult.id, "audit_1");
  assert.equal(laterRetry.id, "audit_1");
  assert.equal(laterRetry.state, "awaiting_approval");
});

test("concurrent human approvals execute the consequential route exactly once", async () => {
  const repository = createMemoryRepository();
  let decide;
  let releaseRun;
  const runGate = new Promise((resolve) => { releaseRun = resolve; });
  let runCount = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository,
    clock: fixedClock("2026-08-30T10:00:00.000Z"),
    id: () => "audit_concurrent_approval",
    async prepare() {
      return { execution: { planId: "private_plan" }, review: { contractHash: "reviewed_hash" } };
    },
    async run() {
      runCount += 1;
      await runGate;
      return { verdict: "fail", findingCodes: ["authorization_outcome_changed"] };
    },
    onApprovalRequired(input) {
      decide = input.decide;
    },
  });
  await service.start({
    presetId: "gym_booking",
    idempotencyKey: "approval-race",
    actor: { type: "agent", id: "browser_agent" },
  });

  const firstApproval = decide({ decision: "approve", humanId: "human_vasu" });
  const duplicateApproval = decide({ decision: "approve", humanId: "human_vasu" });
  releaseRun();
  const [firstResult, duplicateResult] = await Promise.all([firstApproval, duplicateApproval]);

  assert.equal(runCount, 1);
  assert.equal(firstResult.state, "completed");
  assert.equal(duplicateResult.state, "completed");
  assert.deepEqual(firstResult.history.map((entry) => entry.state), [
    "preparing",
    "awaiting_approval",
    "running",
    "waiting_for_effects",
    "completed",
  ]);
});

test("public operations reject caller-authored recipes, routes, evidence, and approval fields", async () => {
  let prepareCount = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository: createMemoryRepository(),
    clock: fixedClock("2026-08-30T10:00:00.000Z"),
    id: () => "audit_reject_input",
    async prepare() {
      prepareCount += 1;
      return { execution: {}, review: {} };
    },
    async run() {
      return { verdict: "pass" };
    },
    onApprovalRequired() {},
  });
  const base = {
    presetId: "gym_booking",
    idempotencyKey: "reject-caller-evidence",
    actor: { type: "agent", id: "browser_agent" },
  };

  for (const forbidden of [
    { recipe: { target: "caller-target" } },
    { routes: { human: [], agent: [] } },
    { evidence: [{ kind: "state" }] },
    { approval: { status: "approved" } },
  ]) {
    await assert.rejects(service.start({ ...base, ...forbidden }), /unsupported start field/);
  }
  await assert.rejects(service.start({ ...base, actor: { ...base.actor, evidence: [] } }), /unsupported actor field/);
  await assert.rejects(service.poll({ auditId: "audit_reject_input", actor: base.actor, approval: true }), /unsupported poll field/);
  assert.equal(prepareCount, 0);
});

test("an audit awaiting human approval expires without executing", async () => {
  const clock = controllableClock("2026-08-30T10:00:00.000Z");
  let decide;
  let runCount = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository: createMemoryRepository(),
    clock: clock.now,
    id: () => "audit_expiring",
    async prepare() {
      return {
        execution: { planId: "private_plan" },
        review: { contractHash: "reviewed_hash" },
        expiresAt: "2026-08-30T10:01:00.000Z",
      };
    },
    async run() {
      runCount += 1;
      return { verdict: "pass" };
    },
    onApprovalRequired(input) {
      decide = input.decide;
    },
  });
  await service.start({
    presetId: "gym_booking",
    idempotencyKey: "expires-before-approval",
    actor: { type: "agent", id: "browser_agent" },
  });

  clock.set("2026-08-30T10:02:00.000Z");
  const expired = await service.poll({ auditId: "audit_expiring", actor: { type: "agent", id: "browser_agent" } });
  const lateApproval = await decide({ decision: "approve", humanId: "human_vasu" });

  assert.equal(expired.state, "expired");
  assert.equal(lateApproval.state, "expired");
  assert.equal(runCount, 0);
  assert.deepEqual(expired.history.map((entry) => entry.state), ["preparing", "awaiting_approval", "expired"]);
});

test("restored transient audits fail closed without preparing or retrying agent execution", async () => {
  const repository = createMemoryRepository({
    measured_audits: [
      storedAudit("restored_preparing", "preparing"),
      storedAudit("restored_approval", "awaiting_approval"),
      storedAudit("restored_running", "running"),
      storedAudit("restored_effects", "waiting_for_effects"),
      storedAudit("restored_completed", "completed"),
    ],
  });
  let prepareCount = 0;
  let runCount = 0;
  let approvalRequestCount = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository,
    clock: fixedClock("2026-08-30T11:00:00.000Z"),
    async prepare() {
      prepareCount += 1;
      return { execution: {}, review: {} };
    },
    async run() {
      runCount += 1;
      return { verdict: "pass" };
    },
    onApprovalRequired() {
      approvalRequestCount += 1;
    },
  });
  const actor = { type: "agent", id: "browser_agent" };

  assert.equal((await service.poll({ auditId: "restored_preparing", actor })).state, "expired");
  assert.equal((await service.poll({ auditId: "restored_approval", actor })).state, "expired");
  assert.equal((await service.poll({ auditId: "restored_running", actor })).state, "outcome_unknown");
  assert.equal((await service.poll({ auditId: "restored_effects", actor })).state, "outcome_unknown");
  assert.equal((await service.poll({ auditId: "restored_completed", actor })).state, "completed");
  assert.equal(prepareCount, 0);
  assert.equal(runCount, 0);
  assert.equal(approvalRequestCount, 0);
});

test("a human can deny a pending audit without running the agent route", async () => {
  let decide;
  let runCount = 0;
  const service = createMeasuredAuditService({
    presets: { gym_booking: { recipe: "server-owned" } },
    repository: createMemoryRepository(),
    clock: fixedClock("2026-08-30T10:00:00.000Z"),
    id: () => "audit_denied",
    async prepare() {
      return { execution: { planId: "private_plan" }, review: { contractHash: "reviewed_hash" } };
    },
    async run() {
      runCount += 1;
      return { verdict: "pass" };
    },
    onApprovalRequired(input) {
      decide = input.decide;
    },
  });
  await service.start({
    presetId: "gym_booking",
    idempotencyKey: "human-denies",
    actor: { type: "agent", id: "browser_agent" },
  });

  const denied = await decide({ decision: "deny", humanId: "human_vasu" });

  assert.equal(denied.state, "failed");
  assert.deepEqual(denied.error, { code: "approval_denied" });
  assert.equal(runCount, 0);
  assert.deepEqual(denied.history.map((entry) => entry.state), ["preparing", "awaiting_approval", "failed"]);
});

test("inconclusive and uncertain runner outcomes terminate without automatic retry", async () => {
  const cases = [
    {
      name: "explicit inconclusive",
      execute: async () => ({ verdict: "inconclusive", findingCodes: ["trusted_evidence_missing"] }),
      expectedState: "inconclusive",
      expectedError: null,
    },
    {
      name: "runner failure after execution starts",
      execute: async () => { throw new Error("raw runner secret"); },
      expectedState: "outcome_unknown",
      expectedError: { code: "execution_outcome_unknown" },
    },
    {
      name: "runner returns no trustworthy verdict",
      execute: async () => ({ receipt: "ambiguous" }),
      expectedState: "outcome_unknown",
      expectedError: { code: "execution_result_invalid" },
    },
  ];

  for (const scenario of cases) {
    let decide;
    let runCount = 0;
    const service = createMeasuredAuditService({
      presets: { gym_booking: { recipe: "server-owned" } },
      repository: createMemoryRepository(),
      clock: fixedClock("2026-08-30T10:00:00.000Z"),
      id: () => `audit_${scenario.expectedState}`,
      async prepare() {
        return { execution: { planId: "private_plan" }, review: { contractHash: "reviewed_hash" } };
      },
      async run() {
        runCount += 1;
        return scenario.execute();
      },
      onApprovalRequired(input) {
        decide = input.decide;
      },
    });
    await service.start({
      presetId: "gym_booking",
      idempotencyKey: scenario.name,
      actor: { type: "agent", id: "browser_agent" },
    });

    const firstDecision = await decide({ decision: "approve", humanId: "human_vasu" });
    const duplicateDecision = await decide({ decision: "approve", humanId: "human_vasu" });

    assert.equal(firstDecision.state, scenario.expectedState, scenario.name);
    assert.deepEqual(firstDecision.error, scenario.expectedError, scenario.name);
    assert.equal(duplicateDecision.state, scenario.expectedState, scenario.name);
    assert.equal(runCount, 1, scenario.name);
    assert.doesNotMatch(JSON.stringify(firstDecision), /raw runner secret/);
  }
});

function fixedClock(iso) {
  return () => new Date(iso);
}

function controllableClock(initial) {
  let value = initial;
  return {
    now: () => new Date(value),
    set(next) {
      value = next;
    },
  };
}

function storedAudit(id, state) {
  return {
    id,
    presetId: "gym_booking",
    idempotencyKey: id,
    idempotencyScope: `agent:browser_agent:${id}`,
    starter: { type: "agent", id: "browser_agent" },
    state,
    createdAt: "2026-08-30T10:00:00.000Z",
    updatedAt: "2026-08-30T10:00:00.000Z",
    expiresAt: "2026-08-30T10:10:00.000Z",
    review: {},
    execution: {},
    approval: state === "running" || state === "waiting_for_effects" ? { status: "approved" } : null,
    result: state === "completed" ? { verdict: "pass" } : null,
    error: null,
    history: [{ state, at: "2026-08-30T10:00:00.000Z" }],
  };
}
