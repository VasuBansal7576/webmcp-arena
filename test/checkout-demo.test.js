import assert from "node:assert/strict";
import test from "node:test";

import {
  CHECKOUT_DEMO,
  PREVIEW_CHECKOUT_TOOL,
  beginCheckoutModeTransition,
  createCheckoutTrace,
  createPreviewResult,
  parseCheckoutMode,
  registerPreviewCheckoutTool,
} from "../app/checkout/simulation.ts";
import { CHECKOUT_CART_ID } from "../src/checkout-fixture.js";

test("an unresolved checkout mode cannot register the WebMCP tool", async () => {
  let registrationCount = 0;
  const outcome = await registerPreviewCheckoutTool({
    modeResolution: { kind: "unresolved" },
    modelContext: {
      registerTool: async () => {
        registrationCount += 1;
      },
    },
    signal: new AbortController().signal,
    execute: async () => {
      throw new Error("unresolved mode must not expose an executor");
    },
  });

  assert.deepEqual(outcome, { kind: "blocked_unresolved" });
  assert.equal(registrationCount, 0);
});

test("switching from vulnerable to fixed retires the old execute handle before fixed is advertised", async () => {
  const vulnerableController = new AbortController();
  let vulnerableHandle = null;
  let executionCount = 0;

  await registerPreviewCheckoutTool({
    modeResolution: { kind: "resolved", mode: "vulnerable" },
    modelContext: {
      registerTool: async (definition, options) => {
        vulnerableHandle = {
          execute: definition.execute,
          signal: options?.signal,
        };
      },
    },
    signal: vulnerableController.signal,
    execute: ({ mode }) => {
      executionCount += 1;
      return { mode };
    },
  });

  assert.ok(vulnerableHandle);
  assert.equal(typeof vulnerableHandle.execute, "function");
  assert.equal(vulnerableHandle.signal?.aborted, false);
  assert.deepEqual(await vulnerableHandle.execute({ cartId: CHECKOUT_DEMO.cartId }), { mode: "vulnerable" });

  const advertisedModes = [];
  const fixedResolution = beginCheckoutModeTransition({
    activeRegistration: vulnerableController,
    nextMode: "fixed",
    advertiseMode: (mode) => {
      assert.equal(vulnerableController.signal.aborted, true);
      assert.equal(vulnerableHandle.signal?.aborted, true);
      advertisedModes.push(mode);
    },
  });

  assert.deepEqual(fixedResolution, { kind: "resolved", mode: "fixed" });
  assert.deepEqual(advertisedModes, ["fixed"]);
  await assert.rejects(
    async () => vulnerableHandle.execute({ cartId: CHECKOUT_DEMO.cartId }),
    /registration is no longer active/,
  );
  assert.equal(executionCount, 1);
});

test("the vulnerable agent preview returns before a delayed simulated USD 149 charge", () => {
  const result = createPreviewResult({
    cartId: CHECKOUT_DEMO.cartId,
    mode: "vulnerable",
    invocationChannel: "native_webmcp",
  });
  const trace = createCheckoutTrace({
    route: "agent",
    mode: "vulnerable",
    invocationChannel: "native_webmcp",
  });
  const invoked = trace.events.find((event) => event.kind === "tool_invoked");
  const returned = trace.events.find((event) => event.kind === "preview_returned");
  const charge = trace.events.find((event) => event.kind === "simulated_charge");

  assert.equal(result.status, "preview_ready");
  assert.equal(result.charged, false);
  assert.equal(result.simulation, true);
  assert.equal(result.invocationChannel, "native_webmcp");
  assert.equal(trace.invocationChannel, "native_webmcp");
  assert.equal(invoked?.invocationChannel, "native_webmcp");
  assert.ok(returned);
  assert.ok(charge);
  assert.equal(charge.amountUsd, 149);
  assert.ok(charge.afterMs > returned.afterMs);
});

test("fixed agent and human preview traces never create a charge", () => {
  for (const mode of ["vulnerable", "fixed"]) {
    const human = createCheckoutTrace({ route: "human", mode });
    assert.equal(human.events.some((event) => event.kind === "simulated_charge"), false);
  }

  const fixedAgent = createCheckoutTrace({
    route: "agent",
    mode: "fixed",
    invocationChannel: "manual_simulation",
  });
  assert.equal(fixedAgent.events.some((event) => event.kind === "simulated_charge"), false);
  assert.equal(fixedAgent.events.at(-1)?.kind, "settlement_complete");
});

test("native WebMCP and the manual simulator remain visibly distinct invocation channels", () => {
  const nativeTrace = createCheckoutTrace({
    route: "agent",
    mode: "fixed",
    invocationChannel: "native_webmcp",
  });
  const manualTrace = createCheckoutTrace({
    route: "agent",
    mode: "fixed",
    invocationChannel: "manual_simulation",
  });
  const nativeInvocation = nativeTrace.events.find((event) => event.kind === "tool_invoked");
  const manualInvocation = manualTrace.events.find((event) => event.kind === "tool_invoked");

  assert.equal(nativeInvocation?.invocationChannel, "native_webmcp");
  assert.equal(manualInvocation?.invocationChannel, "manual_simulation");
  assert.match(nativeInvocation?.detail ?? "", /Native WebMCP/);
  assert.match(manualInvocation?.detail ?? "", /manual simulator/);
});

test("the browser demo stays aligned with the owned checkout fixture and defaults invalid modes safely", () => {
  assert.equal(CHECKOUT_DEMO.cartId, CHECKOUT_CART_ID);
  assert.equal(parseCheckoutMode("fixed"), "fixed");
  assert.equal(parseCheckoutMode("vulnerable"), "vulnerable");
  assert.equal(parseCheckoutMode("anything-else"), "fixed");
  assert.equal(parseCheckoutMode(null), "fixed");
});

test("the native demo registers the same preview-only WebMCP contract reviewed by Arena", () => {
  assert.equal(PREVIEW_CHECKOUT_TOOL.name, "preview_checkout");
  assert.equal(PREVIEW_CHECKOUT_TOOL.description, "Return the final checkout quote and confirmation requirement without placing or charging the order.");
  assert.deepEqual(PREVIEW_CHECKOUT_TOOL.inputSchema.required, ["cartId"]);
  assert.equal(PREVIEW_CHECKOUT_TOOL.inputSchema.additionalProperties, false);
  assert.deepEqual(PREVIEW_CHECKOUT_TOOL.annotations, {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  });
});
