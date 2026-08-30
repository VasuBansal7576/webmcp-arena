import { createHash, randomUUID } from "node:crypto";

import { defineOwnedTargetAdapter } from "./adapter-sdk.js";
import {
  CHECKOUT_CART_ID,
  CHECKOUT_FIXTURE_ID,
  CHECKOUT_LOGICAL_SCOPE_ID,
  CHECKOUT_PRINCIPAL_ID,
  createCheckoutFixture,
} from "./checkout-fixture.js";
import {
  createDeterministicScheduler,
  createEffectSettlementObserver,
} from "./effect-settlement.js";
import { hashWebMcpToolDefinition } from "./webmcp-tool-definition.js";

const VERSIONS = new Set(["vulnerable", "fixed"]);

export const CHECKOUT_WEBMCP_TOOL = deepFreeze({
  name: "preview_checkout",
  title: "Preview checkout",
  description: "Return the final checkout quote and confirmation requirement without placing or charging the order.",
  inputSchema: {
    type: "object",
    properties: {
      cartId: { type: "string", description: "The owned cart to preview." },
    },
    required: ["cartId"],
    additionalProperties: false,
  },
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
  origin: null,
});

const TOOL_DEFINITION_HASH = hashWebMcpToolDefinition(CHECKOUT_WEBMCP_TOOL);

export function createCheckoutAuditAdapter({
  scheduler = createDeterministicScheduler(),
  id = randomUUID,
  chargeDelayMs = 25,
  settlementTimeoutMs = 1_000,
  settlementPollIntervalMs = 10,
} = {}) {
  if (typeof id !== "function") throw new Error("Checkout audit adapter requires an identifier source");
  const fixture = createCheckoutFixture({ scheduler, id, chargeDelayMs });
  const settlementObserver = createEffectSettlementObserver({
    scheduler,
    pollIntervalMs: settlementPollIntervalMs,
    timeoutMs: settlementTimeoutMs,
  });
  const targets = new Map();
  const leases = new WeakMap();

  const targetHarness = {
    async establish({ target, principalRef } = {}) {
      const descriptor = parseCheckoutTarget(target);
      const principal = String(principalRef || "");
      if (!principal) throw new Error("Checkout audit requires a principal reference");
      const targetRef = boundedId(`checkout_target_${id()}`);
      targets.set(targetRef, Object.freeze({ ...descriptor, principalRef: principal }));
      return deepFreeze({
        owned: true,
        targetRef,
        seedDigest: fixture.initialSeedDigest(),
        adapterId: "arena.checkout",
        trustMode: "server_attested",
      });
    },

    async provision({ targetRef, seedDigest, route } = {}) {
      const descriptor = targets.get(String(targetRef));
      if (!descriptor) throw new Error("unknown Checkout target reference");
      if (seedDigest !== fixture.initialSeedDigest()) throw new Error("Checkout fixture seed changed while provisioning the audit");
      const trial = fixture.createTrial({ version: descriptor.version });
      const handle = Object.freeze({
        kind: CHECKOUT_FIXTURE_ID,
        targetRef: String(targetRef),
        version: descriptor.version,
        trialId: trial.trialId,
        runId: boundedId(`checkout_${route || "route"}_${id()}`),
        seedDigest: trial.seedDigest,
        evidenceSource: trial.evidenceSource,
        trustMode: trial.trustMode,
      });
      leases.set(handle, {
        trialId: trial.trialId,
        version: descriptor.version,
        seedDigest: trial.seedDigest,
        released: false,
      });
      return handle;
    },

    async release(handle) {
      if (!handle) return;
      const lease = leases.get(handle);
      if (!lease) throw new Error("a live Checkout trial handle issued by this adapter is required");
      if (lease.released) return;
      fixture.releaseTrial({ trialId: lease.trialId });
      lease.released = true;
    },
  };

  const routeRunner = {
    async runHuman({ target, actions } = {}) {
      const lease = liveLease(target);
      validateHumanActions(actions);
      fixture.executeHumanPreview({ trialId: lease.trialId, runId: target.runId });
      return settledObservation(lease);
    },

    async runAgent({ target, invocation } = {}) {
      const lease = liveLease(target);
      validateInvocation(invocation);
      fixture.executeAgentPreview({
        trialId: lease.trialId,
        runId: target.runId,
        toolName: invocation.toolName,
        argumentsHash: digest(stableJson(invocation.arguments)),
      });
      return settledObservation(lease, invocation);
    },
  };

  async function settledObservation(lease, invocation = null) {
    const settlement = await settlementObserver.observe({
      logicalScopeId: CHECKOUT_LOGICAL_SCOPE_ID,
      read: () => fixture.readSettlement({ trialId: lease.trialId }),
    });
    if (settlement.status !== "settled") {
      return deepFreeze({ recorder: [], server: [{ order: 50, ...settlement }], page: [] });
    }
    const evidence = fixture.readEvidence({ trialId: lease.trialId });
    validateEvidence(evidence, lease, invocation, settlement);
    return normalizeObservation(evidence, settlement);
  }

  function liveLease(handle) {
    const lease = leases.get(handle);
    if (!lease || lease.released) throw new Error("a live Checkout trial handle issued by this adapter is required");
    return lease;
  }

  async function createRecipe({ target, principalRef = `fixture:${CHECKOUT_PRINCIPAL_ID}` } = {}) {
    const descriptor = parseCheckoutTarget(target);
    const principal = String(principalRef || "");
    if (!principal) throw new Error("Checkout recipe requires a principal reference");
    return deepFreeze({
      target: descriptor.href,
      principalRef: principal,
      human: {
        actions: [{ type: "preview_checkout", cartId: CHECKOUT_CART_ID, confirmation: "stop_before_purchase" }],
      },
      agent: {
        toolName: CHECKOUT_WEBMCP_TOOL.name,
        toolDefinitionHash: TOOL_DEFINITION_HASH,
        arguments: { cartId: CHECKOUT_CART_ID },
      },
      invariants: {
        requireAuthorizationBeforeEffect: true,
        requireEffectSettlement: true,
        allowedAuthorizationRules: ["checkout_preview"],
        allowedResourceOwners: [CHECKOUT_PRINCIPAL_ID],
        money: { maxAmount: 0, currency: "USD" },
      },
    });
  }

  return defineOwnedTargetAdapter({
    manifest: {
      id: "arena.checkout",
      version: "1.0.0",
      claimScope: ["owned_fixture:checkout"],
      trustMode: "server_attested",
    },
    targetHarness,
    routeRunner,
    createRecipe,
  });
}

function normalizeObservation(evidence, settlement) {
  const server = evidence.events.map((event) => {
    if (event.kind === "authorization") {
      return {
        order: 10,
        kind: "authorization",
        decision: event.decision,
        rule: event.rule,
      };
    }
    if (event.kind === "outcome") {
      return {
        order: 20,
        kind: "outcome",
        operation: event.operation,
        status: event.status,
        confirmation: event.confirmation,
        quote: structuredClone(event.quote),
        resource: structuredClone(event.resource),
      };
    }
    if (event.kind === "money") {
      return {
        order: 30,
        kind: "money",
        action: event.action,
        amount: event.amount,
        currency: event.currency,
        resource: structuredClone(event.resource),
      };
    }
    throw new Error("Checkout evidence contains an unsupported backend event");
  });
  server.push({ order: 40, ...structuredClone(settlement) });
  server.push({
    order: 50,
    kind: "final_state",
    stateHash: digest(stableJson(evidence.state)),
    resourceEffects: evidence.state.order.status === "preview" ? 0 : 1,
    moneyEffects: evidence.state.charges.length,
    pendingEffects: 0,
  });
  return deepFreeze({ recorder: [], server, page: [] });
}

function validateEvidence(evidence, lease, invocation, settlement) {
  if (!evidence || evidence.fixture !== CHECKOUT_FIXTURE_ID || evidence.version !== lease.version ||
      evidence.trialId !== lease.trialId || evidence.seedDigest !== lease.seedDigest ||
      evidence.evidenceSource !== "owned_checkout_backend" || evidence.trustMode !== "server_attested") {
    throw new Error("Checkout evidence is not bound to the owned fixture trial");
  }
  if (!Array.isArray(evidence.events) || !evidence.state || typeof evidence.state !== "object" ||
      !Array.isArray(evidence.state.charges) || !evidence.state.order ||
      !Number.isSafeInteger(evidence.settlement?.watermark) || evidence.settlement.watermark < 0 ||
      evidence.settlement.pendingEffects !== 0 || evidence.settlement.watermark !== settlement.observedThrough) {
    throw new Error("Checkout fixture returned incomplete server evidence");
  }
  stableJson(evidence.state);
  const expectedArgumentsHash = invocation ? digest(stableJson(invocation.arguments)) : null;
  for (let index = 0; index < evidence.events.length; index += 1) {
    const event = evidence.events[index];
    if (!event || event.sequence !== index + 1 || event.authority !== "application_backend" ||
        event.provenance !== "server_attested" || event.evidence_source !== "owned_checkout_backend" ||
        event.trial_id !== lease.trialId) {
      throw new Error("Checkout evidence is not server-attested by the owned backend");
    }
    if (invocation) {
      if (event.tool_name !== invocation.toolName || event.arguments_hash !== expectedArgumentsHash) {
        throw new Error("Checkout evidence is not bound to the executed tool and arguments");
      }
    } else if (event.tool_name !== null || event.arguments_hash !== null) {
      throw new Error("Checkout human evidence unexpectedly claims an agent invocation");
    }
  }
}

function validateHumanActions(actions) {
  const expected = [{ type: "preview_checkout", cartId: CHECKOUT_CART_ID, confirmation: "stop_before_purchase" }];
  if (stableJson(actions) !== stableJson(expected)) {
    throw new Error("Checkout human route must preview the cart and stop at the confirmation boundary");
  }
}

function validateInvocation(invocation) {
  if (!invocation || invocation.toolName !== CHECKOUT_WEBMCP_TOOL.name ||
      invocation.toolDefinitionHash !== TOOL_DEFINITION_HASH ||
      stableJson(invocation.arguments) !== stableJson({ cartId: CHECKOUT_CART_ID })) {
    throw new Error("Checkout agent route is not bound to the reviewed preview_checkout definition and arguments");
  }
}

function parseCheckoutTarget(rawTarget) {
  if (typeof rawTarget !== "string" || rawTarget.length > 512) throw new Error("Checkout target is invalid");
  let url;
  try {
    url = new URL(rawTarget);
  } catch {
    throw new Error("Checkout target is invalid");
  }
  const parameters = [...url.searchParams.keys()];
  const version = url.searchParams.get("version");
  if (url.protocol !== "arena-owned:" || url.hostname !== "checkout" || url.pathname !== "/" ||
      url.username || url.password || url.hash || parameters.length !== 1 || parameters[0] !== "version" ||
      !VERSIONS.has(version)) {
    throw new Error("Checkout audits require the explicit owned target arena-owned://checkout/?version=vulnerable|fixed");
  }
  return Object.freeze({ href: `arena-owned://checkout/?version=${version}`, version });
}

function boundedId(value) {
  const result = String(value || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(result)) throw new Error("Checkout adapter identifier is invalid");
  return result;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}
