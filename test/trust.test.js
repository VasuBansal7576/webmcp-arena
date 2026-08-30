import assert from "node:assert/strict";
import test from "node:test";

import { createTrustGateway } from "../src/trust.js";

test("a delegated read tool executes without human approval", async () => {
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "search_flights",
      scope: "flights:read",
      risk: "read_only",
      execute: async ({ from, to }) => ({ route: `${from}-${to}`, price: 12000 }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:read"],
    ttlSeconds: 1800,
  });

  const result = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "search_flights",
    arguments: { from: "DEL", to: "BOM" },
    idempotencyKey: "search-1",
  });

  assert.deepEqual(
    { status: result.status, result: result.result, receiptVerified: gateway.verifyReceipt(result.receipt) },
    { status: "executed", result: { route: "DEL-BOM", price: 12000 }, receiptVerified: true },
  );
});

test("a consequential tool waits for the principal before it executes", async () => {
  let bookings = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async ({ flightId }) => ({ bookingId: `booking_${flightId}_${++bookings}` }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
    ttlSeconds: 1800,
  });

  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "book-1",
  });
  const bookingsBeforeApproval = bookings;
  const completed = await gateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    {
      pendingStatus: pending.status,
      bookingsBeforeApproval,
      completedStatus: completed.status,
      bookingId: completed.result.bookingId,
      receiptVerified: gateway.verifyReceipt(completed.receipt),
    },
    {
      pendingStatus: "approval_required",
      bookingsBeforeApproval: 0,
      completedStatus: "executed",
      bookingId: "booking_AI-202_1",
      receiptVerified: true,
    },
  );
});

test("idempotency prevents duplicate execution and rejects changed replay arguments", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "search_flights",
      scope: "flights:read",
      risk: "read_only",
      execute: async ({ to }) => ({ to, execution: ++executions }),
    }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["flights:read"] });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "search_flights",
    arguments: { to: "BOM" },
    idempotencyKey: "same-request",
  };

  const first = await gateway.requestToolExecution(request);
  const retry = await gateway.requestToolExecution(request);
  const conflict = await gateway.requestToolExecution({ ...request, arguments: { to: "BLR" } });

  assert.deepEqual(
    {
      executions,
      firstReceipt: first.receipt.id,
      retryReceipt: retry.receipt.id,
      conflict: { status: conflict.status, reason: conflict.reason },
    },
    {
      executions: 1,
      firstReceipt: first.receipt.id,
      retryReceipt: first.receipt.id,
      conflict: { status: "denied", reason: "idempotency_conflict" },
    },
  );
});

test("concurrent idempotent retries share one direct execution", async () => {
  let executions = 0;
  let releaseExecution;
  let markStarted;
  const started = new Promise((resolve) => { markStarted = resolve; });
  const release = new Promise((resolve) => { releaseExecution = resolve; });
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "read_catalog",
      scope: "catalog:read",
      risk: "read_only",
      execute: async () => {
        executions += 1;
        markStarted();
        await release;
        return { executions };
      },
    }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["catalog:read"] });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "read_catalog",
    arguments: {},
    idempotencyKey: "concurrent-read",
  };

  const firstPromise = gateway.requestToolExecution(request);
  await started;
  const retryPromise = gateway.requestToolExecution(request);
  releaseExecution();
  const [first, retry] = await Promise.all([firstPromise, retryPromise]);

  assert.deepEqual(
    {
      executions,
      first: first.status,
      retry: retry.status,
      firstReceipt: first.receipt.id,
      retryReceipt: retry.receipt.id,
    },
    {
      executions: 1,
      first: "executed",
      retry: "executed",
      firstReceipt: first.receipt.id,
      retryReceipt: first.receipt.id,
    },
  );
});

test("a failed direct execution leaves an idempotent retry fail closed", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "charge_card",
      scope: "payments:write",
      risk: "financial",
      amount: ({ amount }) => amount,
      execute: async () => {
        executions += 1;
        throw new Error("provider outcome unavailable");
      },
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["payments:write"],
    maxAmount: 15000,
  });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "charge_card",
    arguments: { amount: 12000 },
    idempotencyKey: "ambiguous-charge",
  };

  await assert.rejects(() => gateway.requestToolExecution(request), /provider outcome unavailable/);
  const retry = await gateway.requestToolExecution(request);

  assert.deepEqual(
    { retry: { status: retry.status, reason: retry.reason }, executions },
    { retry: { status: "denied", reason: "execution_outcome_unknown" }, executions: 1 },
  );
});

test("a spend limit denial is visible in the authorization timeline", async () => {
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async () => ({ status: "confirmed" }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });

  const result = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-999", price: 25000 },
    idempotencyKey: "over-limit",
  });
  const lastEvent = gateway.getSnapshot().timeline.at(-1);

  assert.deepEqual(
    { result: { status: result.status, reason: result.reason }, event: { status: lastEvent.status, reason: lastEvent.reason } },
    { result: { status: "denied", reason: "amount_exceeds_delegation" }, event: { status: "denied", reason: "amount_exceeds_delegation" } },
  );
});

test("a delegation spend limit is cumulative across direct executions", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "buy_item",
      scope: "shop:buy",
      risk: "financial",
      amount: ({ price }) => price,
      execute: async ({ price }) => ({ price, execution: ++executions }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["shop:buy"],
    maxAmount: 15000,
  });

  const first = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "buy_item",
    arguments: { price: 9000 },
    idempotencyKey: "buy-1",
  });
  const second = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "buy_item",
    arguments: { price: 7000 },
    idempotencyKey: "buy-2",
  });

  assert.deepEqual(
    {
      first: first.status,
      second: { status: second.status, reason: second.reason },
      executions,
    },
    {
      first: "executed",
      second: { status: "denied", reason: "amount_exceeds_delegation" },
      executions: 1,
    },
  );
});

test("pending approvals reserve delegation budget and cannot overbook it", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async () => ({ execution: ++executions }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });

  const first = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 9000 },
    idempotencyKey: "pending-1",
  });
  const second = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-203", price: 7000 },
    idempotencyKey: "pending-2",
  });

  assert.deepEqual(
    {
      first: first.status,
      second: { status: second.status, reason: second.reason },
      pending: gateway.getSnapshot().approvals.filter((approval) => approval.status === "pending").length,
      executions,
    },
    {
      first: "approval_required",
      second: { status: "denied", reason: "amount_exceeds_delegation" },
      pending: 1,
      executions: 0,
    },
  );
});

test("approval execution uses the exact arguments captured at request time", async () => {
  const observed = [];
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ booking }) => booking.price,
      execute: async (args) => {
        observed.push(structuredClone(args));
        return { booked: args.booking.flightId, price: args.booking.price };
      },
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const args = { booking: { flightId: "AI-202", price: 12000 } };
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: args,
    idempotencyKey: "bound-arguments",
  });

  args.booking.flightId = "AI-999";
  args.booking.price = 1;
  pending.approval.arguments.booking.flightId = "AI-666";
  pending.approval.arguments.booking.price = 25000;

  const completed = await gateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    {
      status: completed.status,
      result: completed.result,
      observed,
      receiptArguments: completed.receipt.arguments,
    },
    {
      status: "executed",
      result: { booked: "AI-202", price: 12000 },
      observed: [{ booking: { flightId: "AI-202", price: 12000 } }],
      receiptArguments: { booking: { flightId: "AI-202", price: 12000 } },
    },
  );
});

test("approval execution stays bound to the tool handler and context captured at request time", async () => {
  const tool = {
    name: "book_flight",
    scope: "flights:book",
    risk: "financial",
    requiresApproval: true,
    priceMultiplier: 1,
    amount({ price }) {
      return price * this.priceMultiplier;
    },
    async execute({ price }) {
      return { handler: "original", charged: price * this.priceMultiplier };
    },
  };
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [tool],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { price: 12000 },
    idempotencyKey: "bound-tool-context",
  });

  tool.priceMultiplier = 100;
  tool.execute = async () => ({ handler: "replacement", charged: 1 });

  const completed = await gateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    { status: completed.status, result: completed.result },
    { status: "executed", result: { handler: "original", charged: 12000 } },
  );
});

test("a persisted context label cannot rebind an approval after restart", async () => {
  const stateStore = memoryStateStore();
  let executions = 0;
  const execute = async ({ flightId }) => ({ flightId, execution: ++executions });
  const tool = () => ({
    name: "book_flight",
    scope: "flights:book",
    risk: "financial",
    requiresApproval: true,
    approvalContextId: "book_flight:v1",
    amount: ({ price }) => price,
    execute,
  });
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool()],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const pending = await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "restart-same-context",
  });

  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool()],
  });
  const completed = await restartedGateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    { status: completed.status, reason: completed.reason, executions },
    { status: "denied", reason: "approval_context_unavailable", executions: 0 },
  );
});

test("a restart cannot infer hidden handler context without an explicit context identity", async () => {
  const stateStore = memoryStateStore();
  let executions = 0;
  const execute = async () => ({ execution: ++executions });
  const tool = () => ({
    name: "book_flight",
    scope: "flights:book",
    risk: "financial",
    requiresApproval: true,
    amount: ({ price }) => price,
    execute,
  });
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool()],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const pending = await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { price: 12000 },
    idempotencyKey: "restart-hidden-context",
  });

  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool()],
  });
  const result = await restartedGateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    { status: result.status, reason: result.reason, executions },
    { status: "denied", reason: "approval_context_unavailable", executions: 0 },
  );
});

test("a restored approval fails closed and releases its budget when tool context changed", async () => {
  const stateStore = memoryStateStore();
  const originalTool = {
    name: "book_flight",
    scope: "flights:book",
    risk: "financial",
    requiresApproval: true,
    approvalContextId: "book_flight:v1",
    amount: ({ price }) => price,
    execute: async () => ({ handler: "original" }),
  };
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [originalTool],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const pending = await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "restart-old-context",
  });

  let executions = 0;
  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [{
      ...originalTool,
      execute: async () => ({ handler: "replacement", execution: ++executions }),
    }],
  });
  const denied = await restartedGateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });
  const replacement = await restartedGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-203", price: 12000 },
    idempotencyKey: "restart-new-context",
  });

  assert.deepEqual(
    {
      denied: { status: denied.status, reason: denied.reason },
      replacement: replacement.status,
      executions,
    },
    {
      denied: { status: "denied", reason: "approval_context_unavailable" },
      replacement: "approval_required",
      executions: 0,
    },
  );
});

test("a restart never rebinds an approval to an indistinguishable function with different closure state", async () => {
  const stateStore = memoryStateStore();
  let executions = 0;
  const tool = (destination) => ({
    name: "send_payment",
    scope: "payments:send",
    risk: "financial",
    requiresApproval: true,
    approvalContextId: "send_payment:v1",
    amount: ({ amount }) => amount,
    execute: async () => ({ destination, execution: ++executions }),
  });
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool("merchant-approved")],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["payments:send"],
    maxAmount: 15000,
  });
  const pending = await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "send_payment",
    arguments: { amount: 12000 },
    idempotencyKey: "closure-bound-payment",
  });

  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool("attacker-controlled")],
  });
  const result = await restartedGateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    { status: result.status, reason: result.reason, executions },
    { status: "denied", reason: "approval_context_unavailable", executions: 0 },
  );
});

test("a human denial releases the pending budget reservation", async () => {
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async ({ flightId }) => ({ flightId }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const first = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 15000 },
    idempotencyKey: "deny-release-1",
  });
  const denied = await gateway.resolveApproval({
    approvalId: first.approval.id,
    principalId: "human_vasu",
    decision: "denied",
  });
  const second = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-203", price: 15000 },
    idempotencyKey: "deny-release-2",
  });

  assert.deepEqual(
    {
      denied: { status: denied.status, reason: denied.reason },
      second: second.status,
    },
    {
      denied: { status: "denied", reason: "human_denied" },
      second: "approval_required",
    },
  );
});

test("approved execution commits its reservation to cumulative delegation spend", async () => {
  const stateStore = memoryStateStore();
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async ({ flightId }) => ({ flightId }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const first = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 9000 },
    idempotencyKey: "approved-spend-1",
  });
  const completed = await gateway.resolveApproval({
    approvalId: first.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });
  const second = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-203", price: 7000 },
    idempotencyKey: "approved-spend-2",
  });
  const budget = stateStore.inspect().budgets[passport.delegation.id];

  assert.deepEqual(
    {
      completed: completed.status,
      second: { status: second.status, reason: second.reason },
      budget,
    },
    {
      completed: "executed",
      second: { status: "denied", reason: "amount_exceeds_delegation" },
      budget: { committed: 9000, reservations: {} },
    },
  );
});

test("approval is durably recorded before the consequential handler begins", async () => {
  const stateStore = memoryStateStore();
  let stateObservedByHandler = null;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async () => {
        const state = stateStore.inspect();
        stateObservedByHandler = {
          approval: Object.values(state.approvals)[0].status,
          committed: Object.values(state.budgets)[0].committed,
        };
        return { status: "confirmed" };
      },
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "approval-before-effect",
  });

  const completed = await gateway.resolveApproval({
    approvalId: pending.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });

  assert.deepEqual(
    { completed: completed.status, stateObservedByHandler },
    { completed: "executed", stateObservedByHandler: { approval: "approved", committed: 12000 } },
  );
});

test("approval idempotency survives response mutation and returns one final receipt", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async ({ flightId, price }) => ({ flightId, price, execution: ++executions }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "approval-idempotency",
  };
  const pending = await gateway.requestToolExecution(request);
  pending.approval.arguments.flightId = "MUTATED";
  pending.approval.arguments.price = 1;

  const pendingRetry = await gateway.requestToolExecution(request);
  const completed = await gateway.resolveApproval({
    approvalId: pendingRetry.approval.id,
    principalId: "human_vasu",
    decision: "approved",
  });
  const completedRetry = await gateway.requestToolExecution(request);

  assert.deepEqual(
    {
      pendingRetryArguments: pendingRetry.approval.arguments,
      completed: completed.status,
      completedRetry: completedRetry.status,
      firstReceipt: completed.receipt.id,
      retryReceipt: completedRetry.receipt.id,
      executions,
    },
    {
      pendingRetryArguments: { flightId: "AI-202", price: 12000 },
      completed: "executed",
      completedRetry: "executed",
      firstReceipt: completed.receipt.id,
      retryReceipt: completed.receipt.id,
      executions: 1,
    },
  );
});

test("a failed approved execution leaves its idempotent retry fail closed", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async () => {
        executions += 1;
        throw new Error("airline outcome unavailable");
      },
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "ambiguous-booking",
  };
  const pending = await gateway.requestToolExecution(request);

  await assert.rejects(
    () => gateway.resolveApproval({ approvalId: pending.approval.id, principalId: "human_vasu", decision: "approved" }),
    /airline outcome unavailable/,
  );
  const retry = await gateway.requestToolExecution(request);
  const approval = gateway.getSnapshot().approvals.find((candidate) => candidate.id === pending.approval.id);

  assert.deepEqual(
    {
      retry: { status: retry.status, reason: retry.reason },
      approval: approval.status,
      executions,
    },
    {
      retry: { status: "denied", reason: "execution_outcome_unknown" },
      approval: "approved",
      executions: 1,
    },
  );
});

test("legacy persisted state cannot erase previously consumed delegation budget", async () => {
  const stateStore = memoryStateStore();
  let executions = 0;
  const tool = {
    name: "buy_item",
    scope: "shop:buy",
    risk: "financial",
    amount: ({ price }) => price,
    execute: async ({ price }) => ({ price, execution: ++executions }),
  };
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["shop:buy"],
    maxAmount: 15000,
  });
  await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "buy_item",
    arguments: { price: 9000 },
    idempotencyKey: "legacy-spend-1",
  });

  const legacyState = stateStore.inspect();
  legacyState.version = 2;
  delete legacyState.budgets;
  stateStore.replace(legacyState);

  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool],
  });
  const result = await restartedGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "buy_item",
    arguments: { price: 1000 },
    idempotencyKey: "legacy-spend-2",
  });

  assert.deepEqual(
    { status: result.status, reason: result.reason, executions },
    { status: "denied", reason: "delegation_budget_state_unavailable", executions: 1 },
  );
});

test("malformed persisted budget state fails closed instead of resetting spend", async () => {
  const stateStore = memoryStateStore();
  const tool = {
    name: "buy_item",
    scope: "shop:buy",
    risk: "financial",
    amount: ({ price }) => price,
    execute: async ({ price }) => ({ price }),
  };
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["shop:buy"],
    maxAmount: 15000,
  });
  const malformed = stateStore.inspect();
  malformed.version = 3;
  delete malformed.integrity;
  malformed.approvals = {};
  malformed.idempotency = {};
  malformed.budgets[passport.delegation.id] = { committed: "unknown" };
  stateStore.replace(malformed);

  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool],
  });
  const result = await restartedGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "buy_item",
    arguments: { price: 1000 },
    idempotencyKey: "malformed-budget",
  });

  assert.deepEqual(
    { status: result.status, reason: result.reason },
    { status: "denied", reason: "delegation_budget_state_unavailable" },
  );
});

test("tampering with persisted replay state fails closed instead of re-executing an idempotent effect", async () => {
  const stateStore = memoryStateStore();
  let executions = 0;
  const tool = {
    name: "send_notification",
    scope: "notifications:send",
    risk: "external_write",
    execute: async () => ({ execution: ++executions }),
  };
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool],
  });
  const passport = firstGateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["notifications:send"] });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "send_notification",
    arguments: { message: "hello" },
    idempotencyKey: "durable-notification",
  };
  await firstGateway.requestToolExecution(request);
  const tampered = stateStore.inspect();
  delete tampered.idempotency[Object.keys(tampered.idempotency)[0]];
  stateStore.replace(tampered);

  const restartedGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:01.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [tool],
  });
  const replay = await restartedGateway.requestToolExecution(request);

  assert.deepEqual(
    { status: replay.status, reason: replay.reason, executions },
    { status: "denied", reason: "trust_state_integrity_failure", executions: 1 },
  );
});

test("revocation denies pending approvals and removes their persisted budget reservations", async () => {
  const stateStore = memoryStateStore();
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async ({ flightId }) => ({ flightId }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
  });
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "revoke-pending",
  });

  const revoked = gateway.revoke({
    passport: passport.token,
    principalId: "human_vasu",
    reason: "user_revoked",
  });
  const approval = gateway.getSnapshot().approvals.find((candidate) => candidate.id === pending.approval.id);
  const budget = stateStore.inspect().budgets[passport.delegation.id];

  assert.deepEqual(
    {
      revoked: revoked.status,
      approval: approval.status,
      reservations: budget.reservations,
    },
    {
      revoked: "revoked",
      approval: "denied",
      reservations: {},
    },
  );
});

test("invalid arguments are denied before a consequential action reaches approval", async () => {
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      validate: ({ flightId, price }) => !flightId || price <= 0 ? "flightId and a positive price are required" : null,
      execute: async () => ({ status: "confirmed" }),
    }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["flights:book"] });

  const result = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "", price: -1 },
    idempotencyKey: "invalid-booking",
  });

  assert.deepEqual(
    { status: result.status, reason: result.reason, pendingApprovals: gateway.getSnapshot().approvals.filter((item) => item.status === "pending").length },
    { status: "denied", reason: "invalid_arguments", pendingApprovals: 0 },
  );
});

test("an approval cannot outlive the delegation that authorized it", async () => {
  let current = new Date("2026-08-29T10:00:00.000Z");
  let executions = 0;
  const stateStore = memoryStateStore();
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => current,
    id: sequenceIds(),
    stateStore,
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async () => ({ execution: ++executions }),
    }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["flights:book"], maxAmount: 15000, ttlSeconds: 60 });
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "expires-before-approval",
  });
  current = new Date("2026-08-29T10:02:00.000Z");

  const result = await gateway.resolveApproval({ approvalId: pending.approval.id, principalId: "human_vasu", decision: "approved" });
  const budget = stateStore.inspect().budgets[passport.delegation.id];

  assert.deepEqual(
    { status: result.status, reason: result.reason, executions, reservations: budget.reservations },
    { status: "denied", reason: "expired_passport", executions: 0, reservations: {} },
  );
});

test("expired pending approvals are swept and release reservations without an approval callback", async () => {
  const stateStore = memoryStateStore();
  let current = new Date("2026-08-29T10:00:00.000Z");
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => current,
    id: sequenceIds(),
    stateStore,
    tools: [{
      name: "book_flight",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      execute: async () => ({ status: "confirmed" }),
    }],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["flights:book"],
    maxAmount: 15000,
    ttlSeconds: 1,
  });
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "expires-without-callback",
  });

  current = new Date("2026-08-29T10:00:02.000Z");
  const snapshot = gateway.getSnapshot();
  const persistedBudget = stateStore.inspect().budgets[passport.delegation.id];

  assert.deepEqual(
    {
      requested: pending.status,
      approval: snapshot.approvals[0].status,
      denialReason: snapshot.approvals[0].denial_reason,
      reservations: persistedBudget.reservations,
    },
    { requested: "approval_required", approval: "denied", denialReason: "expired_passport", reservations: {} },
  );
});

test("execution receipts carry observed tool latency", async () => {
  const ticks = [100, 137];
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    monotonic: () => ticks.shift(),
    id: sequenceIds(),
    tools: [{ name: "read_catalog", scope: "catalog:read", risk: "read_only", execute: async () => ({ items: 2 }) }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["catalog:read"] });

  const result = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "read_catalog",
    arguments: {},
    idempotencyKey: "timed-call",
  });

  assert.equal(result.receipt.duration_ms, 37);
});

test("a denied approval stays denied when an agent retries the same request", async () => {
  let executions = 0;
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{ name: "book_flight", scope: "flights:book", risk: "financial", requiresApproval: true, execute: async () => ({ execution: ++executions }) }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["flights:book"] });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "book_flight",
    arguments: { flightId: "AI-202", price: 12000 },
    idempotencyKey: "human-denied-booking",
  };
  const pending = await gateway.requestToolExecution(request);
  await gateway.resolveApproval({ approvalId: pending.approval.id, principalId: "human_vasu", decision: "denied" });

  const retry = await gateway.requestToolExecution(request);

  assert.deepEqual(
    { status: retry.status, reason: retry.reason, executions },
    { status: "denied", reason: "human_denied", executions: 0 },
  );
});

test("production delegation binds to a cryptographically verified agent identity", () => {
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    requireVerifiedAgents: true,
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
  });

  assert.throws(
    () => gateway.issuePassport({ principalId: "human_vasu", agentId: "self-asserted", scopes: [] }),
    /verified agent identity is required/,
  );

  assert.throws(
    () => gateway.issuePassport({
      principalId: "human_vasu",
      agentId: "different-agent",
      agentIdentity: {
        verified: true,
        issuer: "https://agents.example",
        subject: "agent-session-42",
        agent_id: "trusted-browser-agent",
        token_id: "attestation-9",
        algorithm: "EdDSA",
      },
      scopes: [],
    }),
    /does not match the verified identity/,
  );

  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentIdentity: {
      verified: true,
      issuer: "https://agents.example",
      subject: "agent-session-42",
      agent_id: "trusted-browser-agent",
      token_id: "attestation-9",
      algorithm: "EdDSA",
    },
    scopes: ["flights:read"],
  });

  assert.deepEqual(
    { agentId: passport.delegation.agent_id, identity: passport.delegation.agent_identity },
    {
      agentId: "trusted-browser-agent",
      identity: {
        verified: true,
        issuer: "https://agents.example",
        subject: "agent-session-42",
        token_id: "attestation-9",
        algorithm: "EdDSA",
      },
    },
  );
});

test("the governance interface revokes a delegation before its next action", async () => {
  let executions = 0;
  const kernel = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    tools: [{
      name: "read_catalog",
      scope: "catalog:read",
      risk: "read_only",
      execute: async () => ({ execution: ++executions }),
    }],
  });
  const passport = kernel.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["catalog:read"] });

  const revocation = kernel.revoke({ passport: passport.token, principalId: "human_vasu", reason: "user_revoked" });
  const result = await kernel.submit({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "read_catalog",
    arguments: {},
    idempotencyKey: "after-revocation",
  });

  assert.deepEqual(
    { revocation: revocation.status, result: result.status, reason: result.reason, executions },
    { revocation: "revoked", result: "denied", reason: "delegation_revoked", executions: 0 },
  );
});

test("two live gateways sharing durable state cannot spend the same delegation budget twice", async () => {
  const stateStore = memoryStateStore();
  let executions = 0;
  const tool = {
    name: "charge_account",
    scope: "account:charge",
    risk: "financial",
    amount: ({ amount }) => amount,
    execute: async () => ({ execution: ++executions }),
  };
  const firstGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: (() => { let value = 0; return () => `first_${++value}`; })(),
    stateStore,
    tools: [tool],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["account:charge"],
    maxAmount: 15000,
  });
  const secondGateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: (() => { let value = 0; return () => `second_${++value}`; })(),
    stateStore,
    tools: [tool],
  });

  const first = await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "charge_account",
    arguments: { amount: 9000 },
    idempotencyKey: "charge-one",
  });
  const second = await secondGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "charge_account",
    arguments: { amount: 9000 },
    idempotencyKey: "charge-two",
  });

  assert.deepEqual(
    { first: first.status, second: second.status, reason: second.reason, executions },
    { first: "executed", second: "denied", reason: "amount_exceeds_delegation", executions: 1 },
  );
});

test("delegation issuance rejects malformed limits instead of silently creating an unlimited passport", () => {
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
  });

  assert.throws(
    () => gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: [], maxAmount: "not-a-number" }),
    /maxAmount must be a finite non-negative number or null/,
  );
  assert.throws(
    () => gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: [], ttlSeconds: 0 }),
    /ttlSeconds must be a finite positive number/,
  );
});

test("sensitive tool arguments and results never enter public receipts or plaintext persisted state", async () => {
  const stateStore = memoryStateStore();
  const observed = [];
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [{
      name: "connect_account",
      scope: "account:connect",
      risk: "credentialed_write",
      requiresApproval: true,
      execute: async (args) => {
        observed.push(args);
        return { connected: true, accessToken: "result-access-token" };
      },
    }],
  });
  const passport = gateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["account:connect"] });
  const pending = await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "connect_account",
    arguments: { accountId: "acct_42", apiToken: "request-api-token", card: { number: "4111111111111111" } },
    idempotencyKey: "secret-bearing-request",
  });

  assert.equal(pending.approval.arguments.apiToken, "[REDACTED]");
  assert.doesNotMatch(JSON.stringify(stateStore.inspect()), /request-api-token|4111111111111111/);

  const completed = await gateway.resolveApproval({ approvalId: pending.approval.id, principalId: "human_vasu", decision: "approved" });

  assert.deepEqual(observed, [{ accountId: "acct_42", apiToken: "request-api-token", card: { number: "4111111111111111" } }]);
  assert.equal(completed.result.accessToken, "result-access-token");
  assert.doesNotMatch(JSON.stringify(completed.receipt), /request-api-token|4111111111111111|result-access-token/);
  assert.doesNotMatch(JSON.stringify(stateStore.inspect()), /request-api-token|4111111111111111|result-access-token/);
  assert.doesNotMatch(JSON.stringify(gateway.getSnapshot()), /request-api-token|4111111111111111|result-access-token/);
});

test("validator and handler error messages cannot inject secrets into the durable timeline", async () => {
  const stateStore = memoryStateStore();
  const gateway = createTrustGateway({
    secret: "test-secret-with-enough-entropy",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
    stateStore,
    tools: [
      {
        name: "validate_credential",
        scope: "credentials:validate",
        risk: "read_only",
        validate: ({ apiToken }) => `credential ${apiToken} was rejected`,
        execute: async () => ({ ok: true }),
      },
      {
        name: "failing_write",
        scope: "records:write",
        risk: "external_write",
        execute: async ({ password }) => { throw new Error(`backend included ${password}`); },
      },
    ],
  });
  const passport = gateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["credentials:validate", "records:write"],
  });
  await gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "validate_credential",
    arguments: { apiToken: "validator-secret-token" },
    idempotencyKey: "validator-secret",
  });
  await assert.rejects(gateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "failing_write",
    arguments: { password: "handler-secret-password" },
    idempotencyKey: "handler-secret",
  }));

  assert.doesNotMatch(JSON.stringify(stateStore.inspect()), /validator-secret-token|handler-secret-password/);
});

function memoryStateStore(initial = null) {
  let value = structuredClone(initial);
  return {
    load: () => structuredClone(value),
    save: (next) => { value = structuredClone(next); },
    withLock: (callback) => callback(),
    inspect: () => structuredClone(value),
    replace: (next) => { value = structuredClone(next); },
  };
}

function sequenceIds() {
  let value = 0;
  return () => `id_${++value}`;
}
