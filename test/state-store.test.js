import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createSqliteRepository, scopedStateStore } from "../src/state-store.js";
import { createTrustGateway } from "../src/trust.js";

test("trust state and replay protection survive a process-style restart", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "arena-state-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "arena.sqlite");
  const secret = "persistent-test-secret-123456";
  let firstExecutions = 0;
  const firstRepository = createSqliteRepository({ path });
  const firstGateway = createTrustGateway({
    secret,
    stateStore: scopedStateStore(firstRepository, "trust"),
    tools: [{ name: "read_catalog", scope: "catalog:read", risk: "read_only", execute: async () => ({ execution: ++firstExecutions }) }],
  });
  const passport = firstGateway.issuePassport({ principalId: "human_vasu", agentId: "chatgpt", scopes: ["catalog:read"] });
  const request = {
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "read_catalog",
    arguments: {},
    idempotencyKey: "persistent-read",
  };
  const first = await firstGateway.requestToolExecution(request);
  firstRepository.close();

  let restartedExecutions = 0;
  const secondRepository = createSqliteRepository({ path });
  t.after(() => secondRepository.close());
  const secondGateway = createTrustGateway({
    secret,
    stateStore: scopedStateStore(secondRepository, "trust"),
    tools: [{ name: "read_catalog", scope: "catalog:read", risk: "read_only", execute: async () => ({ execution: ++restartedExecutions }) }],
  });
  const replay = await secondGateway.requestToolExecution(request);

  assert.deepEqual(
    {
      firstExecutions,
      restartedExecutions,
      firstReceipt: first.receipt.id,
      replayReceipt: replay.receipt.id,
      persistedEvents: secondGateway.getSnapshot().timeline.map((event) => event.status),
    },
    {
      firstExecutions: 1,
      restartedExecutions: 0,
      firstReceipt: first.receipt.id,
      replayReceipt: first.receipt.id,
      persistedEvents: ["passport_issued", "executed"],
    },
  );
});

test("two SQLite-backed gateway workers serialize delegation budget reservations", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "arena-state-workers-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "arena.sqlite");
  const secret = "persistent-test-secret-123456";
  const firstRepository = createSqliteRepository({ path });
  const secondRepository = createSqliteRepository({ path });
  t.after(() => firstRepository.close());
  t.after(() => secondRepository.close());
  let executions = 0;
  const tool = {
    name: "charge_account",
    scope: "account:charge",
    risk: "financial",
    amount: ({ amount }) => amount,
    execute: async () => ({ execution: ++executions }),
  };
  const firstGateway = createTrustGateway({
    secret,
    stateStore: scopedStateStore(firstRepository, "trust"),
    tools: [tool],
  });
  const passport = firstGateway.issuePassport({
    principalId: "human_vasu",
    agentId: "chatgpt",
    scopes: ["account:charge"],
    maxAmount: 15000,
  });
  const secondGateway = createTrustGateway({
    secret,
    stateStore: scopedStateStore(secondRepository, "trust"),
    tools: [tool],
  });

  const first = await firstGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "charge_account",
    arguments: { amount: 9000 },
    idempotencyKey: "worker-one",
  });
  const second = await secondGateway.requestToolExecution({
    passport: passport.token,
    agentId: "chatgpt",
    toolName: "charge_account",
    arguments: { amount: 9000 },
    idempotencyKey: "worker-two",
  });

  assert.deepEqual(
    { first: first.status, second: second.status, reason: second.reason, executions },
    { first: "executed", second: "denied", reason: "amount_exceeds_delegation", executions: 1 },
  );
});
