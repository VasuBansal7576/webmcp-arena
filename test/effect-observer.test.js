import assert from "node:assert/strict";
import test from "node:test";

import {
  createDeterministicScheduler,
  createEffectSettlementObserver,
} from "../src/effect-settlement.js";

test("the observer waits through a delayed effect and emits a terminal settlement watermark", async () => {
  const scheduler = createDeterministicScheduler();
  const state = { watermark: 0, pendingEffects: 1 };
  scheduler.schedule(25, () => {
    state.watermark += 1;
    state.pendingEffects -= 1;
  }, { scopeId: "checkout_preview" });
  const observer = createEffectSettlementObserver({ scheduler, pollIntervalMs: 10, timeoutMs: 100 });

  const settlement = await observer.observe({
    logicalScopeId: "checkout_preview",
    read: async () => ({ ...state }),
  });

  assert.deepEqual(settlement, {
    kind: "effect_settlement",
    version: 1,
    logicalScopeId: "checkout_preview",
    complete: true,
    status: "settled",
    reason: "terminal_watermark",
    observedThrough: 1,
    pendingEffects: 0,
  });
  assert.equal(scheduler.now(), 30);
});

test("the observer reports an inconclusive terminal record when effects outlive its deadline", async () => {
  const scheduler = createDeterministicScheduler();
  const state = { watermark: 0, pendingEffects: 1 };
  scheduler.schedule(1_000, () => {
    state.watermark += 1;
    state.pendingEffects -= 1;
  }, { scopeId: "checkout_preview" });
  const observer = createEffectSettlementObserver({ scheduler, pollIntervalMs: 10, timeoutMs: 25 });

  const settlement = await observer.observe({
    logicalScopeId: "checkout_preview",
    read: () => ({ ...state }),
  });

  assert.deepEqual(settlement, {
    kind: "effect_settlement",
    version: 1,
    logicalScopeId: "checkout_preview",
    complete: false,
    status: "inconclusive",
    reason: "timeout",
    observedThrough: 0,
    pendingEffects: 1,
  });
  assert.equal(scheduler.now(), 25);
});

test("deterministic scheduler tasks are ordered and can be cancelled by owned scope", async () => {
  const scheduler = createDeterministicScheduler({ startMs: 50 });
  const order = [];
  scheduler.schedule(10, () => order.push("second"), { scopeId: "keep" });
  scheduler.schedule(5, () => order.push("first"), { scopeId: "keep" });
  scheduler.schedule(1, () => order.push("cancelled"), { scopeId: "drop" });
  assert.equal(scheduler.cancelScope("drop"), 1);

  await scheduler.sleep(10);

  assert.deepEqual(order, ["first", "second"]);
  assert.equal(scheduler.pendingCount("keep"), 0);
});
