import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { isIP } from "node:net";

import { hashWebMcpToolDefinition } from "./webmcp-tool-definition.js";

const FIXTURE_NAME = "gym_boundary";
const VERSIONS = new Set(["vulnerable", "fixed"]);

export function createGymAuditAdapters({
  browserRunner,
  fixtureToken,
  fetchImpl = globalThis.fetch,
  id = randomUUID,
  redactionKey = randomBytes(32),
} = {}) {
  if (!browserRunner?.inspect || !browserRunner?.recordHumanRoute || !browserRunner?.execute) {
    throw new Error("Gym audit adapters require a browser runner with inspect, recordHumanRoute, and execute");
  }
  if (typeof fetchImpl !== "function") throw new Error("Gym audit adapters require fetch");
  if (String(fixtureToken || "").length < 16) throw new Error("Gym audit adapters require a fixture token of at least 16 characters");

  const targets = new Map();
  const leases = new WeakMap();

  const targetHarness = {
    async establish({ target, principalRef }) {
      if (!principalRef) throw new Error("a principal reference is required");
      const descriptor = parseGymTarget(target);
      const probe = await provisionTrial(descriptor);
      try {
        const targetRef = `gym_target_${id()}`;
        targets.set(targetRef, Object.freeze({ ...descriptor, principalRef: String(principalRef) }));
        return { owned: true, targetRef, seedDigest: probe.seedDigest };
      } finally {
        await releaseTrial(descriptor.origin, probe.trialId);
      }
    },

    async provision({ targetRef, seedDigest, route }) {
      const descriptor = targets.get(targetRef);
      if (!descriptor) throw new Error("unknown Gym target reference");
      const trial = await provisionTrial(descriptor);
      try {
        if (trial.seedDigest !== seedDigest) throw new Error("Gym fixture seed changed while provisioning the audit");
        const runId = boundedId(`gym_${route || "route"}_${id()}`);
        const url = trialUrl(trial.path, descriptor.origin, trial.trialId);
        url.searchParams.set("arena_run_id", runId);
        const handle = Object.freeze({
          kind: FIXTURE_NAME,
          targetRef,
          origin: descriptor.origin,
          version: descriptor.version,
          trialId: trial.trialId,
          runId,
          seedDigest: trial.seedDigest,
          url: url.href,
        });
        leases.set(handle, {
          origin: descriptor.origin,
          version: descriptor.version,
          trialId: trial.trialId,
          runId,
          seedDigest: trial.seedDigest,
          url: url.href,
          released: false,
        });
        return handle;
      } catch (error) {
        return releaseAfterFailure(descriptor.origin, trial.trialId, error);
      }
    },

    async release(handle) {
      if (!handle) return;
      const lease = leases.get(handle);
      if (!lease) throw new Error("a live Gym trial handle issued by this adapter is required");
      if (lease.released) return;
      await releaseTrial(lease.origin, lease.trialId);
      lease.released = true;
    },
  };

  const routeRunner = {
    async runHuman({ target, actions }) {
      const lease = liveLease(target);
      const trace = await browserRunner.recordHumanRoute({ url: lease.url, actions });
      validateBrowserTrace(trace, { lease });
      const evidence = await readEvidence(lease);
      return normalizeObservation({ target: lease, trace, evidence });
    },

    async runAgent({ target, invocation }) {
      const lease = liveLease(target);
      const expectedToolHash = String(invocation?.toolDefinitionHash || "");
      if (!expectedToolHash) throw new Error("Gym agent execution requires the reviewed tool definition hash");
      const trace = await browserRunner.execute({
        url: lease.url,
        toolName: invocation.toolName,
        arguments: structuredClone(invocation.arguments || {}),
        expectedToolHash,
      });
      validateBrowserTrace(trace, { lease, expectedToolHash, expectedToolName: invocation.toolName });
      const evidence = await readEvidence(lease);
      validateAgentEvidence(evidence.events, invocation);
      return normalizeObservation({ target: lease, trace, evidence });
    },
  };

  function liveLease(handle) {
    const lease = leases.get(handle);
    if (!lease || lease.released) throw new Error("a live Gym trial handle issued by this adapter is required");
    return lease;
  }

  async function createRecipe({ target, memberId = "human_vasu" } = {}) {
    const descriptor = parseGymTarget(target);
    const trial = await provisionTrial(descriptor);
    try {
      const inspectionUrl = new URL(trial.path, descriptor.origin);
      inspectionUrl.searchParams.set("arena_run_id", boundedId(`gym_inspect_${id()}`));
      const inspection = await browserRunner.inspect({ url: inspectionUrl.href });
      const tool = inspection?.tools?.find((candidate) => candidate?.name === "book_gym_class");
      if (!tool) throw new Error("Gym target did not register the expected book_gym_class WebMCP tool");
      return {
        target: descriptor.href,
        principalRef: "fixture:human_vasu",
        human: { actions: [{ type: "click", selector: "#human-book" }] },
        agent: {
          toolName: tool.name,
          toolDefinitionHash: hashWebMcpToolDefinition(tool),
          arguments: { classId: "yoga_101", memberId: String(memberId) },
        },
        invariants: {
          requireAuthorizationBeforeEffect: true,
          allowedAuthorizationRules: ["booking_window"],
          allowedResourceOwners: [hmac("resource-owner\0human_vasu")],
          allowedNetworkEffects: [
            { scope: "target", method: "GET" },
            {
              scope: "target",
              method: "POST",
              originHmac: hmac(`origin\0${descriptor.origin}`),
              pathHmac: hmac("path-class\0gym-booking"),
              argumentEvidence: "server_attested",
            },
          ],
        },
      };
    } finally {
      await releaseTrial(descriptor.origin, trial.trialId);
    }
  }

  async function provisionTrial(descriptor) {
    const response = await requestJson(new URL("/__arena/provision", descriptor.origin), {
      method: "POST",
      headers: fixtureHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ version: descriptor.version }),
    });
    let trialId = null;
    try {
      if (!response || typeof response !== "object" || Array.isArray(response)) {
        throw new Error("Gym fixture returned an invalid trial descriptor");
      }
      if (response.trial_id) trialId = boundedId(response.trial_id);
      if (response.fixture !== FIXTURE_NAME || response.version !== descriptor.version) {
        throw new Error("target is not the expected Arena Gym fixture");
      }
      if (!trialId || !response.seed_digest || !response.path) throw new Error("Gym fixture returned an incomplete trial descriptor");
      const path = trialPath(response.path, descriptor.origin, trialId);
      return { trialId, seedDigest: String(response.seed_digest), path };
    } catch (error) {
      if (!trialId) throw error;
      return releaseAfterFailure(descriptor.origin, trialId, error);
    }
  }

  async function releaseTrial(origin, trialId) {
    const url = new URL(`/__arena/trials/${encodeURIComponent(boundedId(trialId))}`, origin);
    await requestJson(url, { method: "DELETE", headers: fixtureHeaders() }, { allowNotFound: true });
  }

  async function releaseAfterFailure(origin, trialId, cause) {
    try {
      await releaseTrial(origin, trialId);
    } catch (releaseError) {
      throw new AggregateError([cause, releaseError], "Gym trial setup failed and its trial could not be released");
    }
    throw cause;
  }

  async function readEvidence(lease) {
    const url = new URL("/__arena/evidence", lease.origin);
    url.searchParams.set("run_id", lease.runId);
    url.searchParams.set("trial_id", lease.trialId);
    const evidence = await requestJson(url, { headers: fixtureHeaders() });
    if (evidence.fixture !== FIXTURE_NAME || evidence.trial_id !== lease.trialId || evidence.version !== lease.version) {
      throw new Error("Gym evidence does not belong to the provisioned trial");
    }
    if (evidence.seed_digest !== lease.seedDigest || !Array.isArray(evidence.events)) {
      throw new Error("Gym evidence seed or event stream is invalid");
    }
    if (!evidence.state || typeof evidence.state !== "object" || Array.isArray(evidence.state)) {
      throw new Error("Gym evidence final state is invalid");
    }
    stableJson(evidence.state);
    validateServerEvents(evidence.events, lease);
    return structuredClone(evidence);
  }

  function validateBrowserTrace(trace, { lease, expectedToolHash = null, expectedToolName = null }) {
    const effectTrace = trace?.effect_trace;
    if (!effectTrace || typeof effectTrace !== "object" || Array.isArray(effectTrace)) {
      throw new Error("browser runner did not return an effect trace");
    }
    const proofLevel = String(trace.proof_level || "");
    if (!new Set(["native_browser_api", "compatibility_shim"]).has(proofLevel)) {
      throw new Error("browser runner returned an unsupported execution proof level");
    }
    if (effectTrace.proof_level && effectTrace.proof_level !== proofLevel) {
      throw new Error("browser runner returned mismatched execution proof levels");
    }
    validateEffectCapture(effectTrace.capture);
    if (trace.isolated_context !== true) throw new Error("Gym audits require an isolated browser execution context");
    validateExecutionTransport(trace.execution_transport, { proofLevel, agentExecution: Boolean(expectedToolHash) });
    if (typeof trace.url !== "string") throw new Error("browser runner did not bind its trace to the provisioned Gym URL");
    try {
      const observed = new URL(trace.url);
      const expected = new URL(lease.url);
      if (observed.origin !== expected.origin ||
          observed.searchParams.get("arena_trial") !== lease.trialId ||
          observed.searchParams.get("arena_run_id") !== lease.runId) {
        throw new Error("browser execution escaped the provisioned Gym trial");
      }
    } catch (error) {
      if (error?.message === "browser execution escaped the provisioned Gym trial") throw error;
      throw new Error("browser runner returned an invalid provisioned Gym URL");
    }
    const hasNetworkEvidence = Array.isArray(effectTrace.network) && effectTrace.network.length > 0;
    const hashes = effectTrace.ui?.after_value_hashes;
    const uiValues = hashes && typeof hashes === "object" && !Array.isArray(hashes) ? Object.values(hashes) : [];
    if (uiValues.some((value) => typeof value === "string" && !isSha256Digest(value))) {
      throw new Error("browser recorder returned an invalid UI value HMAC");
    }
    const hasUiEvidence = uiValues.some(isSha256Digest);
    if (!hasNetworkEvidence && !hasUiEvidence) throw new Error("browser runner returned no measured execution evidence");
    if (expectedToolHash) {
      if (trace.tool_definition_hash !== expectedToolHash) {
        throw new Error("executed WebMCP tool definition hash does not match the reviewed definition");
      }
      const definition = Array.isArray(effectTrace.tool_definitions)
        ? effectTrace.tool_definitions.find((tool) => tool?.name === expectedToolName)
        : null;
      if (definition?.hash !== expectedToolHash) {
        throw new Error("effect trace does not bind the executed WebMCP tool definition");
      }
    }
  }

  function validateServerEvents(events, lease) {
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      if (!event || typeof event !== "object" || Array.isArray(event)) throw new Error("Gym evidence event is invalid");
      if (event.run_id !== lease.runId || event.trial_id !== lease.trialId) {
        throw new Error("Gym evidence event correlation does not match the provisioned run and trial");
      }
      if (event.provenance !== "synthetic_fixture" || event.authority !== "application_backend") {
        throw new Error("Gym evidence event is not server-attested by the fixture backend");
      }
      if (event.sequence !== index + 1) throw new Error("Gym evidence event sequence is incomplete or out of order");
      if (!new Set(["authorization", "mutation"]).has(event.kind)) throw new Error("Gym evidence contains an unsupported backend event");
      if (event.kind === "authorization" && !new Set(["allow", "deny"]).has(event.decision)) {
        throw new Error("Gym authorization evidence has an invalid decision");
      }
      if (event.kind === "mutation" && (!event.resource?.type || !event.resource?.id || !event.resource?.owner)) {
        throw new Error("Gym mutation evidence has an invalid resource identity");
      }
    }
  }

  function validateAgentEvidence(events, invocation) {
    const expectedArgumentsHash = digest(stableJson(invocation.arguments || {}));
    for (const event of events) {
      if (event.tool_name !== invocation.toolName || event.arguments_hash !== expectedArgumentsHash) {
        throw new Error("Gym backend evidence is not bound to the executed tool and arguments");
      }
    }
  }

  function normalizeObservation({ target, trace, evidence }) {
    const effectTrace = trace?.effect_trace;
    const proofLevel = String(trace.proof_level);
    const toolDefinitions = Array.isArray(effectTrace.tool_definitions) ? effectTrace.tool_definitions : [];
    const recorder = [
      ...toolDefinitions
        .filter((tool) => tool?.name === "book_gym_class" && isSha256Digest(tool?.hash))
        .map((tool) => ({ order: 0, kind: "tool_definition", name: "book_gym_class", hash: tool.hash })),
      {
        order: 1,
        kind: "execution_proof",
        level: proofLevel,
        isolatedContext: trace.isolated_context === true,
        executionTransport: trace.execution_transport || null,
        captureComplete: effectTrace.capture.complete,
        captureReason: effectTrace.capture.reason,
        pendingRequests: effectTrace.capture.pending_requests,
      },
      normalizeNetworkBoundary(effectTrace.network, target.origin),
      normalizeUiOutcome(effectTrace.ui),
    ];
    const server = [
      ...evidence.events.map(normalizeServerEvent).filter(Boolean),
      {
        order: 1_000_000,
        kind: "final_state",
        stateHash: hmac(`final-state\0${stableJson(evidence.state)}`),
        resourceEffects: evidence.events.filter((event) => event.kind === "mutation").length,
        moneyEffects: evidence.events.filter((event) => event.kind === "money").length,
      },
    ];
    const page = [{
      order: 40,
      kind: "page_context",
      proofLevel,
      assertedProtectionCount: Array.isArray(effectTrace.page_assertions?.protections) ? effectTrace.page_assertions.protections.length : 0,
      assertedApprovalCount: Array.isArray(effectTrace.page_assertions?.approvals) ? effectTrace.page_assertions.approvals.length : 0,
    }];
    return { recorder, server, page };
  }

  function normalizeNetworkBoundary(records, targetOrigin) {
    const requests = (Array.isArray(records) ? records : [])
      .map((record) => safeNetworkRecord(record, targetOrigin))
      .sort((left, right) => stableJson(left).localeCompare(stableJson(right)));
    return {
      order: 20,
      kind: "network",
      method: "BOUNDARY",
      targetOriginHmac: hmac(`origin\0${targetOrigin}`),
      sameOriginPolicy: "recorded_with_server_bound_gym_booking_arguments",
      observedRequests: requests,
    };
  }

  function safeNetworkRecord(record, targetOrigin) {
    let url;
    try {
      url = new URL(String(record?.url || ""));
    } catch {
      return {
        scope: "invalid",
        method: "INVALID",
        originHmac: hmac("invalid-network-url"),
        pathHmac: null,
        status: null,
        query: [],
        bodyKeyHmacs: [],
        bodyValueHmac: null,
      };
    }
    const sameOrigin = url.origin === targetOrigin;
    const serverBoundGymBooking = sameOrigin && new Set(["/api/human/book", "/api/agent/book"]).has(url.pathname);
    const query = (Array.isArray(record?.query) ? record.query : []).map((entry) => ({
      nameHmac: hmac(`query-name\0${String(entry?.name || "")}`),
      valueHmac: recorderDigest(entry?.value_hmac, "network query value"),
    })).sort((left, right) => stableJson(left).localeCompare(stableJson(right)));
    const bodyValueHmac = record?.body === null || record?.body === undefined
      ? null
      : recorderDigest(record.body.value_hmac, "network body value");
    return {
      scope: sameOrigin ? "target" : "external",
      method: String(record?.method || "GET").toUpperCase(),
      originHmac: hmac(`origin\0${url.origin}`),
      pathHmac: serverBoundGymBooking ? hmac("path-class\0gym-booking") : hmac(`path\0${url.pathname}`),
      status: Number.isInteger(record?.status) ? record.status : null,
      query: serverBoundGymBooking ? [] : query,
      bodyKeyHmacs: serverBoundGymBooking ? [] : stringList(record?.body?.json_keys).map((key) => hmac(`body-key\0${key}`)),
      bodyValueHmac: serverBoundGymBooking ? null : bodyValueHmac,
      argumentEvidence: serverBoundGymBooking ? "server_attested" : "recorder_hmac",
    };
  }

  function normalizeUiOutcome(ui) {
    const hashes = ui?.after_value_hashes && typeof ui.after_value_hashes === "object" ? ui.after_value_hashes : {};
    const valueHash = hashes["#status"];
    return {
      order: 30,
      kind: "ui",
      selector: "#status",
      valueHash: typeof valueHash === "string" ? recorderDigest(valueHash, "UI value") : null,
    };
  }

  function normalizeServerEvent(event) {
    if (event?.kind === "authorization") {
      return {
        order: 10 + event.sequence,
        kind: "authorization",
        decision: event.decision === "allow" ? "allow" : "deny",
        rule: String(event.rule || "unknown"),
      };
    }
    if (event?.kind === "mutation") {
      return {
        order: 10 + event.sequence,
        kind: "state",
        resource: {
          type: String(event.resource?.type || "unknown"),
          id: hmac(`resource-id\0${event.resource?.id || ""}`),
          owner: hmac(`resource-owner\0${event.resource?.owner || ""}`),
        },
        before: hmac(`state-value\0${stableJson(event.before ?? null)}`),
        after: hmac(`state-value\0${stableJson(event.after ?? null)}`),
      };
    }
    return null;
  }

  function hmac(value) {
    return createHmac("sha256", redactionKey).update(String(value)).digest("base64url");
  }

  function recorderDigest(value, label) {
    if (!isSha256Digest(value)) throw new Error(`browser recorder returned an invalid ${label} HMAC`);
    return value;
  }

  function validateEffectCapture(capture) {
    if (!capture || capture.complete !== true || capture.reason !== "quiescent" || capture.pending_requests !== 0 ||
        !Number.isFinite(capture.waited_ms) || capture.waited_ms < 0) {
      throw new Error("Gym browser effect capture is incomplete or non-quiescent");
    }
  }

  function validateExecutionTransport(transport, { proofLevel, agentExecution }) {
    if (!agentExecution && (transport === null || transport === undefined)) return;
    const allowed = proofLevel === "compatibility_shim"
      ? new Set(["object"])
      : new Set(["cdp_browser_agent", "object", "json_string_legacy"]);
    if (typeof transport !== "string" || !allowed.has(transport)) {
      throw new Error("browser runner returned an unsupported execution transport");
    }
  }

  function fixtureHeaders(extra = {}) {
    return { "x-arena-fixture-token": fixtureToken, ...extra };
  }

  async function requestJson(url, options, { allowNotFound = false } = {}) {
    const response = await fetchImpl(url, { ...options, redirect: "error" });
    if (allowNotFound && response.status === 404) return null;
    let body;
    try {
      body = await response.json();
    } catch {
      throw new Error(`Gym fixture returned non-JSON response (${response.status})`);
    }
    if (!response.ok) throw new Error(`Gym fixture request failed (${response.status}): ${body?.error || "unknown error"}`);
    return body;
  }

  return { targetHarness, routeRunner, createRecipe };
}

function parseGymTarget(rawTarget) {
  if (typeof rawTarget !== "string" || rawTarget.length > 2_048) throw new Error("Gym target URL is invalid");
  const url = new URL(rawTarget);
  if (url.protocol !== "http:" || url.username || url.password || !isLoopbackHost(url.hostname)) {
    throw new Error("Gym audits require a local loopback target");
  }
  const version = url.searchParams.get("arena_version");
  if (!VERSIONS.has(version)) throw new Error("Gym target requires arena_version=vulnerable or arena_version=fixed");
  url.hash = "";
  return { href: url.href, origin: url.origin, version };
}

function isLoopbackHost(hostname) {
  const normalized = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (normalized === "localhost" || normalized.endsWith(".localhost") || normalized === "::1") return true;
  if (isIP(normalized) === 4) return normalized.startsWith("127.");
  return false;
}

function trialPath(value, origin, trialId) {
  const path = String(value || "");
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error("Gym fixture trial path must be relative to the audited origin");
  const url = new URL(path, origin);
  if (url.origin !== origin || url.username || url.password || url.hash) {
    throw new Error("Gym fixture trial path escaped the audited origin");
  }
  if (url.searchParams.get("arena_trial") !== trialId) throw new Error("Gym fixture trial path is not bound to its trial identifier");
  return `${url.pathname}${url.search}`;
}

function trialUrl(path, origin, trialId) {
  return new URL(trialPath(path, origin, trialId), origin);
}

function boundedId(value) {
  const result = String(value || "");
  if (!/^[a-zA-Z0-9._:-]{1,128}$/.test(result)) throw new Error("Gym fixture returned an invalid identifier");
  return result;
}

function stringList(value) {
  return (Array.isArray(value) ? value : []).map((item) => String(item)).sort();
}

function isSha256Digest(value) {
  return typeof value === "string" && /^[a-zA-Z0-9_-]{43}$/.test(value);
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
