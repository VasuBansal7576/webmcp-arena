import { lookup as dnsLookup } from "node:dns/promises";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { isIP } from "node:net";

import { chromium } from "playwright-core";
import { hashWebMcpToolDefinition } from "./webmcp-tool-definition.js";

export { hashWebMcpToolDefinition } from "./webmcp-tool-definition.js";

const MODES = new Set(["native", "compatibility"]);

export function createWebMcpBrowserRunner({
  executablePath,
  mode = "native",
  headless = mode !== "native",
  allowPrivateTargets = false,
  timeoutMs = 20_000,
  lookup = dnsLookup,
  browserType = chromium,
  redactionKey = randomBytes(32),
  effectObservationMs = 300,
  effectQuietWindowMs = 100,
  effectMaxWaitMs = 1_500,
} = {}) {
  if (!executablePath) throw new Error("WebMCP browser runner requires a browser executable");
  if (!MODES.has(mode)) throw new Error("WebMCP browser runner mode must be native or compatibility");
  if (mode === "native" && headless) throw new Error("native WebMCP verification requires a visible browser");

  async function inspect({ url }) {
    return run(url, async (_page, metadata, runtime) => ({
      ...metadata,
      tools: await runtime.getTools(),
    }));
  }

  async function execute({ url, toolName, arguments: args = {}, expectedToolHash = null }) {
    if (!toolName) throw new Error("toolName is required");
    return run(url, async (page, metadata, runtime) => {
      const definitions = await runtime.getTools();
      const definition = definitions.find((tool) => tool.name === toolName);
      if (!definition) throw new Error(`WebMCP tool not found: ${toolName}`);
      const toolDefinitionHash = hashWebMcpToolDefinition(definition);
      if (expectedToolHash && expectedToolHash !== toolDefinitionHash) {
        throw new Error(`WebMCP tool definition changed after review: ${toolName}`);
      }
      const recorded = await recordPageEffects(page, page.context(), metadata, () => runtime.execute(toolName, args), redactionKey, { effectObservationMs, effectQuietWindowMs, effectMaxWaitMs }, runtime);
      return {
        ...metadata,
        tool_name: toolName,
        tool_definition_hash: toolDefinitionHash,
        arguments: redactArguments(args, redactionKey),
        result: parseResult(recorded.result.value),
        execution_transport: recorded.result.transport,
        effect_trace: recorded.effectTrace,
      };
    });
  }

  async function recordHumanRoute({ url, actions = [] }) {
    if (!Array.isArray(actions) || !actions.length || actions.length > 50) throw new Error("human route requires between 1 and 50 actions");
    return run(url, async (page, metadata, runtime) => {
      const recorded = await recordPageEffects(page, page.context(), metadata, async () => {
        for (const action of actions) await performHumanAction(page, action);
        return { completed_actions: actions.length };
      }, redactionKey, { effectObservationMs, effectQuietWindowMs, effectMaxWaitMs }, runtime);
      return { ...metadata, route_kind: "human", actions: structuredClone(actions), result: recorded.result, effect_trace: recorded.effectTrace };
    });
  }

  async function run(rawUrl, operation) {
    const target = await resolveAllowedTarget(rawUrl, { allowPrivateTargets, lookup });
    const { url } = target;
    const launchArgs = mode === "native" ? [
      "--enable-experimental-web-platform-features",
      "--enable-features=WebMCP,WebMCPTesting,DevToolsWebMCPSupport",
    ] : [];
    if (target.pinnedAddress) {
      launchArgs.push(hostResolverRule(target.hostname, target.pinnedAddress));
      launchArgs.push("--no-proxy-server");
    }
    const browser = await browserType.launch({
      executablePath,
      headless,
      args: launchArgs,
    });
    try {
      const context = await browser.newContext({ acceptDownloads: false, serviceWorkers: "block" });
      const validationCache = new Map();
      await context.route("**/*", async (route) => {
        const requestUrl = route.request().url();
        if (/^(?:data|blob|about):/i.test(requestUrl)) return route.continue();
        try {
          const origin = new URL(requestUrl).origin;
          const sameTargetOrigin = origin === url.origin;
          if (!validationCache.has(origin)) {
            validationCache.set(origin, assertBrowserRequestAllowed(requestUrl, {
              target,
              allowPrivateTargets: sameTargetOrigin && allowPrivateTargets,
            }));
          }
          await validationCache.get(origin);
          return route.continue();
        } catch {
          return route.abort("blockedbyclient");
        }
      });
      if (mode === "compatibility") await context.addInitScript(installCompatibilityModelContext);
      const page = await context.newPage();
      page.setDefaultTimeout(timeoutMs);
      await page.goto(url.href, { waitUntil: "domcontentloaded", timeout: timeoutMs });
      const runtime = mode === "native"
        ? await createNativeCdpRuntime(context, page, { timeoutMs })
        : await createCompatibilityRuntime(page, timeoutMs);
      if (mode === "native") await assertNoPageAuthoredNativeSurface(page, runtime);
      const proofLevel = mode === "native" ? "native_browser_api" : "compatibility_shim";
      const result = await operation(page, {
        url: page.url(),
        proof_level: proofLevel,
        browser_version: browser.version(),
        isolated_context: true,
        execution_channel: runtime.channel,
      }, runtime);
      await context.close();
      return result;
    } finally {
      await browser.close();
    }
  }

  return { inspect, execute, recordHumanRoute, mode };
}

export async function assertAllowedUrl(rawUrl, { allowPrivateTargets = false, lookup = dnsLookup } = {}) {
  return (await resolveAllowedTarget(rawUrl, { allowPrivateTargets, lookup })).url;
}

export async function resolveAllowedTarget(rawUrl, { allowPrivateTargets = false, lookup = dnsLookup } = {}) {
  if (typeof rawUrl !== "string" || rawUrl.length > 2048) throw new Error("target URL is invalid");
  const url = new URL(rawUrl);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error("target URL must use HTTP or HTTPS");
  if (url.username || url.password) throw new Error("target URL must not contain credentials");
  const hostname = normalizeHostname(url.hostname);
  if (allowPrivateTargets) return { url, hostname, pinnedAddress: null };
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    throw new Error("private target URLs are blocked");
  }
  const addresses = isIP(hostname) ? [{ address: hostname }] : await lookup(hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) throw new Error("private target URLs are blocked");
  return { url, hostname, pinnedAddress: isIP(hostname) ? null : normalizeHostname(addresses[0].address) };
}

async function assertBrowserRequestAllowed(rawUrl, { target, allowPrivateTargets }) {
  const candidate = new URL(rawUrl);
  const hostname = normalizeHostname(candidate.hostname);
  if (allowPrivateTargets) return candidate;
  if (hostname === target.hostname && target.pinnedAddress) {
    return (await resolveAllowedTarget(rawUrl, { lookup: async () => [{ address: target.pinnedAddress }] })).url;
  }
  if (!isIP(hostname)) throw new Error("cross-origin remote hostnames are blocked because their DNS resolution is not pinned");
  return assertAllowedUrl(rawUrl);
}

function hostResolverRule(hostname, address) {
  const destination = isIP(address) === 6 ? `[${address}]` : address;
  return `--host-resolver-rules=MAP ${hostname} ${destination}`;
}

function readTools() {
  return document.modelContext.getTools().then((tools) => tools.map((tool) => {
    let inputSchema = tool.inputSchema || null;
    if (typeof inputSchema === "string") {
      try { inputSchema = JSON.parse(inputSchema); } catch { inputSchema = null; }
    }
    return {
      name: tool.name,
      title: tool.title || null,
      description: tool.description || "",
      inputSchema,
      annotations: tool.annotations || null,
      origin: tool.origin || location.origin,
    };
  }));
}

async function createCompatibilityRuntime(page, timeoutMs) {
  await page.waitForFunction(() => Boolean(document.modelContext?.getTools && document.modelContext?.executeTool), null, { timeout: timeoutMs });
  return {
    channel: "page_compatibility_shim",
    getTools: () => page.evaluate(readTools),
    execute: (toolName, input) => page.evaluate(executePageTool, { name: toolName, input }),
  };
}

async function createNativeCdpRuntime(context, page, { timeoutMs }) {
  const session = await context.newCDPSession(page);
  const tools = new Map();
  const bufferedResponses = new Map();
  const responseWaiters = new Map();
  const toolSurfaceListeners = new Set();
  let lastToolSurfaceChangeAt = null;
  const markToolSurfaceChange = () => {
    lastToolSurfaceChangeAt = Date.now();
    for (const listener of toolSurfaceListeners) listener();
  };
  session.on("WebMCP.toolsAdded", ({ tools: added = [] }) => {
    for (const tool of added) tools.set(`${tool.frameId}\0${tool.name}`, normalizeCdpTool(tool, page.url()));
    if (added.length) markToolSurfaceChange();
  });
  session.on("WebMCP.toolsRemoved", ({ tools: removed = [] }) => {
    for (const tool of removed) tools.delete(`${tool.frameId}\0${tool.name}`);
    if (removed.length) markToolSurfaceChange();
  });
  session.on("WebMCP.toolResponded", (response) => {
    const waiter = responseWaiters.get(response.invocationId);
    if (waiter) {
      responseWaiters.delete(response.invocationId);
      waiter(response);
    } else {
      bufferedResponses.set(response.invocationId, response);
    }
  });
  let mainFrameId;
  try {
    const frameTree = await session.send("Page.getFrameTree");
    mainFrameId = frameTree?.frameTree?.frame?.id;
    if (!mainFrameId) throw new Error("top-level frame identity is unavailable");
    await session.send("WebMCP.enable");
  } catch (error) {
    throw new Error(`browser-controlled WebMCP provenance could not be established: ${error.message}`);
  }
  await waitForCdpToolSurfaceSettle({
    subscribe(listener) {
      toolSurfaceListeners.add(listener);
      return () => toolSurfaceListeners.delete(listener);
    },
    getLastChangeAt: () => lastToolSurfaceChangeAt,
    maxWaitMs: Math.min(timeoutMs, 1_000),
    quietWindowMs: 100,
  });
  const getBrowserTools = () => {
    const registered = [...tools.values()];
    if (registered.some((tool) => tool.frameId !== mainFrameId)) {
      throw new Error("browser-controlled WebMCP provenance requires every tool to belong to the top-level frame");
    }
    return registered;
  };
  return {
    channel: "cdp_webmcp_domain",
    getTools: async () => getBrowserTools().map(({ frameId, ...tool }) => structuredClone(tool)),
    async execute(toolName, input) {
      const matches = getBrowserTools().filter((tool) => tool.name === toolName);
      if (matches.length !== 1) {
        if (!matches.length) throw new Error(`WebMCP tool not found: ${toolName}`);
        throw new Error(`WebMCP tool name is ambiguous across frames: ${toolName}`);
      }
      const { invocationId } = await session.send("WebMCP.invokeTool", {
        frameId: matches[0].frameId,
        toolName,
        input: structuredClone(input),
      });
      const response = bufferedResponses.has(invocationId)
        ? bufferedResponses.get(invocationId)
        : await waitForToolResponse(responseWaiters, invocationId, timeoutMs);
      bufferedResponses.delete(invocationId);
      if (response.status !== "Completed") throw new Error(response.errorText || `WebMCP tool invocation ${response.status.toLowerCase()}`);
      return { value: response.output, transport: "cdp_browser_agent" };
    },
  };
}

function waitForCdpToolSurfaceSettle({ subscribe, getLastChangeAt, maxWaitMs, quietWindowMs }) {
  return new Promise((resolve) => {
    let quietTimer = null;
    let maxTimer = null;
    let unsubscribe = () => {};
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      clearTimeout(quietTimer);
      clearTimeout(maxTimer);
      unsubscribe();
      resolve();
    };
    const scheduleQuietWindow = () => {
      clearTimeout(quietTimer);
      const lastChangeAt = getLastChangeAt();
      if (lastChangeAt === null) return;
      quietTimer = setTimeout(finish, Math.max(0, quietWindowMs - (Date.now() - lastChangeAt)));
    };
    unsubscribe = subscribe(scheduleQuietWindow);
    maxTimer = setTimeout(finish, maxWaitMs);
    scheduleQuietWindow();
  });
}

function normalizeCdpTool(tool, pageUrl) {
  return {
    frameId: tool.frameId,
    name: String(tool.name || ""),
    title: null,
    description: String(tool.description || ""),
    inputSchema: tool.inputSchema && typeof tool.inputSchema === "object" ? structuredClone(tool.inputSchema) : null,
    annotations: tool.annotations && typeof tool.annotations === "object" ? structuredClone(tool.annotations) : null,
    origin: new URL(pageUrl).origin,
  };
}

function waitForToolResponse(waiters, invocationId, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      waiters.delete(invocationId);
      reject(new Error(`WebMCP tool invocation timed out: ${invocationId}`));
    }, timeoutMs);
    waiters.set(invocationId, (response) => {
      clearTimeout(timer);
      resolve(response);
    });
  });
}

async function assertNoPageAuthoredNativeSurface(page, runtime) {
  const pageToolNames = await page.evaluate(async () => {
    if (!document.modelContext?.getTools) return [];
    try { return (await document.modelContext.getTools()).map((tool) => String(tool?.name || "")); }
    catch { return []; }
  });
  const browserToolNames = new Set((await runtime.getTools()).map((tool) => tool.name));
  if (pageToolNames.some((name) => !browserToolNames.has(name))) {
    throw new Error("browser-controlled WebMCP provenance could not be established for the page tool surface");
  }
}

async function executePageTool({ name, input }) {
  const tools = await document.modelContext.getTools();
  const selected = tools.find((tool) => tool.name === name);
  if (!selected) throw new Error(`WebMCP tool not found: ${name}`);
  // Chrome's first experimental page API exposed a JSON-string transport,
  // while the current draft accepts an object. Select by Web IDL arity before
  // invoking so a consequential callback is never executed and retried.
  const legacyStringTransport = window.__arenaWebMcpCompatibility !== true && document.modelContext.executeTool.length >= 2;
  const inputArguments = legacyStringTransport ? JSON.stringify(input) : input;
  return {
    value: await document.modelContext.executeTool(selected, inputArguments),
    transport: legacyStringTransport ? "json_string_legacy" : "object",
  };
}

function installCompatibilityModelContext() {
  if (document.modelContext) return;
  const tools = new Map();
  const modelContext = {
    async registerTool(tool, options = {}) {
      if (!tool?.name || !tool?.description || typeof tool.execute !== "function") throw new TypeError("invalid WebMCP tool");
      if (tools.has(tool.name)) throw new DOMException("duplicate WebMCP tool", "InvalidStateError");
      tools.set(tool.name, tool);
      options.signal?.addEventListener("abort", () => tools.delete(tool.name), { once: true });
    },
    async getTools() {
      return [...tools.values()];
    },
    async executeTool(tool, inputArguments, options = {}) {
      const selected = tools.get(tool?.name);
      if (!selected) throw new DOMException("WebMCP tool not found", "NotFoundError");
      if (!inputArguments || typeof inputArguments !== "object" || Array.isArray(inputArguments)) {
        throw new DOMException("WebMCP input must be an object", "DataError");
      }
      const controller = new AbortController();
      const abort = () => controller.abort(options.signal?.reason);
      options.signal?.addEventListener("abort", abort, { once: true });
      try {
        return await selected.execute(inputArguments, { signal: controller.signal });
      } finally {
        options.signal?.removeEventListener("abort", abort);
      }
    },
  };
  Object.defineProperty(Document.prototype, "modelContext", { configurable: true, get: () => modelContext });
  Object.defineProperty(window, "__arenaWebMcpCompatibility", { value: true });
}

function parseResult(value) {
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return value;
  }
}

async function capturePageState(page, runtime) {
  const tools = await runtime.getTools();
  const value = await page.evaluate(async () => {
    const regions = {};
    for (const element of document.querySelectorAll("[data-arena-evidence]")) {
      const selector = element.id ? `#${element.id}` : `[data-arena-evidence="${element.getAttribute("data-arena-evidence") || ""}"]`;
      regions[selector] = element.textContent || "";
    }
    const safeObject = (candidate) => {
      try { return JSON.parse(JSON.stringify(candidate || {})); } catch { return {}; }
    };
    return {
      url: location.href,
      body: document.body?.innerHTML || "",
      local: Object.fromEntries(Object.entries(localStorage)),
      session: Object.fromEntries(Object.entries(sessionStorage)),
      applicationState: safeObject(window.__arenaState),
      protections: Array.isArray(window.__arenaProtections) ? [...window.__arenaProtections] : [],
      approvals: Array.isArray(window.__arenaApprovals) ? safeObject(window.__arenaApprovals) : [],
      regions,
      untrustedContentDetected: window.__arenaUntrustedContentDetected === true,
    };
  });
  return {
    ...value,
    tools,
    dom_hash: digest(value.body),
    tool_hashes: tools.map((tool) => ({ name: tool.name, hash: hashWebMcpToolDefinition(tool) })),
  };
}

async function recordPageEffects(page, context, metadata, operation, redactionKey, quiescence, runtime) {
  const before = await capturePageState(page, runtime);
  const network = [];
  const requestRecords = new Map();
  const consoleEvents = [];
  const existingPages = new Set(context.pages());
  const openedPages = [];
  const inFlight = new Set();
  let lastActivityAt = Date.now();
  const markActivity = () => { lastActivityAt = Date.now(); };
  const onRequest = (request) => {
    if (!/^https?:/i.test(request.url())) return;
    const record = redactRequest(request, redactionKey);
    requestRecords.set(request, record);
    network.push(record);
    inFlight.add(request);
    markActivity();
  };
  const onResponse = (response) => {
    const record = requestRecords.get(response.request());
    if (record) record.status = response.status();
    markActivity();
  };
  const onRequestSettled = (request) => {
    inFlight.delete(request);
    markActivity();
  };
  const onConsole = (message) => {
    consoleEvents.push({ type: message.type(), text: redactConsole(message.text()) });
    markActivity();
  };
  const onPage = (openedPage) => {
    if (!existingPages.has(openedPage)) openedPages.push(openedPage);
    markActivity();
  };
  context.on("request", onRequest);
  context.on("response", onResponse);
  context.on("requestfinished", onRequestSettled);
  context.on("requestfailed", onRequestSettled);
  context.on("console", onConsole);
  context.on("page", onPage);
  let result;
  let after;
  let pages;
  let capture;
  try {
    result = await operation();
    capture = await waitForEffectQuiescence(page, { inFlight, getLastActivityAt: () => lastActivityAt, ...quiescence });
    after = await capturePageState(page, runtime);
    pages = {
      opened: await Promise.all(openedPages.map(async (openedPage) => ({
        url: openedPage.url(),
        closed: openedPage.isClosed(),
      }))),
    };
  } finally {
    context.off("request", onRequest);
    context.off("response", onResponse);
    context.off("requestfinished", onRequestSettled);
    context.off("requestfailed", onRequestSettled);
    context.off("console", onConsole);
    context.off("page", onPage);
  }
  return { result, effectTrace: buildEffectTrace({ metadata, before, after, network, consoleEvents, pages, capture }) };
}

async function waitForEffectQuiescence(page, {
  inFlight,
  getLastActivityAt,
  effectObservationMs,
  effectQuietWindowMs,
  effectMaxWaitMs,
}) {
  const startedAt = Date.now();
  while (true) {
    const current = Date.now();
    const elapsed = current - startedAt;
    const quietFor = current - getLastActivityAt();
    if (elapsed >= effectObservationMs && inFlight.size === 0 && quietFor >= effectQuietWindowMs) {
      return { complete: true, reason: "quiescent", waited_ms: elapsed, pending_requests: 0 };
    }
    if (elapsed >= effectMaxWaitMs) {
      return { complete: false, reason: "timeout", waited_ms: elapsed, pending_requests: inFlight.size };
    }
    await page.waitForTimeout(Math.min(25, effectMaxWaitMs - elapsed));
  }
}

async function performHumanAction(page, action) {
  if (!action || typeof action.selector !== "string" || action.selector.length > 500) throw new Error("each human action requires a bounded selector");
  const locator = page.locator(action.selector).first();
  if (action.type === "click") return locator.click();
  if (action.type === "fill") return locator.fill(String(action.value ?? ""));
  if (action.type === "select") return locator.selectOption(String(action.value ?? ""));
  if (action.type === "check") return locator.check();
  if (action.type === "uncheck") return locator.uncheck();
  throw new Error(`unsupported human action: ${action.type}`);
}

function buildEffectTrace({ metadata, before, after, network, consoleEvents, pages, capture }) {
  return {
    proof_level: metadata.proof_level,
    capture,
    network,
    pages,
    navigation: { before: before.url, after: after.url },
    state: { before: before.applicationState, after: after.applicationState },
    storage: {
      before: { local: before.local, session: before.session },
      after: { local: after.local, session: after.session },
    },
    ui: {
      before_hash: before.dom_hash,
      after_hash: after.dom_hash,
      changed: changedRegions(before.regions, after.regions),
      after_value_hashes: Object.fromEntries(Object.entries(after.regions).map(([selector, value]) => [selector, digest(value)])),
    },
    protections: after.protections,
    approvals: after.approvals,
    page_assertions: {
      provenance: "page_asserted",
      protections: after.protections,
      approvals: after.approvals,
    },
    evidence_sources: {
      network: "recorder_observed",
      navigation: "recorder_observed",
      storage: "recorder_observed",
      ui: "recorder_observed",
      application_state: "page_asserted",
      protections: "page_asserted",
      approvals: "page_asserted",
    },
    tool_changes: changedTools(before.tool_hashes, after.tool_hashes),
    tool_definitions: structuredClone(before.tool_hashes),
    console: consoleEvents,
    untrusted_content_detected: after.untrustedContentDetected,
  };
}

function changedRegions(before, after) {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((selector) => before[selector] !== after[selector])
    .sort();
}

function changedTools(before, after) {
  const left = new Map(before.map((tool) => [tool.name, tool.hash]));
  const right = new Map(after.map((tool) => [tool.name, tool.hash]));
  return [...new Set([...left.keys(), ...right.keys()])]
    .filter((name) => left.get(name) !== right.get(name))
    .map((name) => ({ name, before_hash: left.get(name) || null, after_hash: right.get(name) || null }));
}

function redactRequest(request, redactionKey) {
  const rawUrl = request.url();
  const method = request.method();
  const headers = request.headers();
  const postData = request.postData();
  const record = {
    method,
    url: stripQuery(rawUrl),
    status: null,
    resource_type: request.resourceType(),
    query: redactQuery(rawUrl, redactionKey),
    body: redactBody(postData, headers["content-type"], redactionKey),
  };
  return record;
}

function stripQuery(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return String(value).split("?")[0];
  }
}

function redactQuery(value, redactionKey) {
  try {
    const url = new URL(value);
    return [...url.searchParams.entries()]
      .map(([name, content]) => ({ name, value_hmac: keyedDigest(`query:${name}\0${content}`, redactionKey) }))
      .sort((left, right) => left.name.localeCompare(right.name) || left.value_hmac.localeCompare(right.value_hmac));
  } catch {
    return [];
  }
}

function redactBody(value, contentType, redactionKey) {
  if (value === null || value === undefined) return null;
  const body = String(value);
  const mediaType = String(contentType || "").split(";", 1)[0].trim().toLowerCase() || null;
  let jsonKeys = [];
  if (mediaType === "application/json") {
    try {
      const parsed = JSON.parse(body);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) jsonKeys = Object.keys(parsed).sort();
    } catch {
      jsonKeys = [];
    }
  }
  return {
    media_type: mediaType,
    length: Buffer.byteLength(body),
    json_keys: jsonKeys,
    value_hmac: keyedDigest(`body\0${body}`, redactionKey),
  };
}

function redactArguments(value, redactionKey) {
  const input = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    keys: Object.keys(input).sort(),
    value_hmac: keyedDigest(`arguments\0${canonicalJson(input)}`, redactionKey),
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function redactConsole(value) {
  return String(value).replace(/(?:bearer|token|password|secret)\s*[:=]\s*\S+/gi, "[redacted]").slice(0, 1_000);
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function keyedDigest(value, key) {
  return createHmac("sha256", key).update(String(value)).digest("base64url");
}

function isPrivateAddress(address) {
  const normalized = normalizeHostname(address);
  if (isIP(normalized) === 4) {
    const [a, b] = normalized.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0);
  }
  if (isIP(normalized) === 6) {
    const words = parseIpv6Words(normalized);
    if (!words) return true;
    const allZero = words.every((word) => word === 0);
    const loopback = words.slice(0, 7).every((word) => word === 0) && words[7] === 1;
    if (allZero || loopback) return true;
    const embeddedV4 = (words.slice(0, 5).every((word) => word === 0) && (words[5] === 0 || words[5] === 0xffff)) ||
      (words.slice(0, 4).every((word) => word === 0) && words[4] === 0xffff && words[5] === 0);
    if (embeddedV4) {
      const ipv4 = `${words[6] >> 8}.${words[6] & 0xff}.${words[7] >> 8}.${words[7] & 0xff}`;
      return isPrivateAddress(ipv4);
    }
    const first = words[0];
    if ((first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00) return true;
    if ((first & 0xffc0) === 0xfec0) return true;
    if (ipv6MatchesPrefix(words, "64:ff9b::", 96) || ipv6MatchesPrefix(words, "64:ff9b:1::", 48)) return true;
    if (ipv6MatchesPrefix(words, "100::", 64)) return true;
    if (ipv6MatchesPrefix(words, "2001::", 32) || ipv6MatchesPrefix(words, "2002::", 16)) return true;
    if (ipv6MatchesPrefix(words, "2001:2::", 48) || ipv6MatchesPrefix(words, "2001:10::", 28) || ipv6MatchesPrefix(words, "2001:20::", 28)) return true;
    if (words[0] === 0x2001 && words[1] === 0x0db8) return true;
    if (words[0] === 0x3ffe || ipv6MatchesPrefix(words, "3fff::", 20) || words[0] === 0x5f00) return true;
    return false;
  }
  return true;
}

function ipv6MatchesPrefix(words, prefix, prefixLength) {
  const expected = parseIpv6Words(prefix);
  if (!expected) return false;
  const completeWords = Math.floor(prefixLength / 16);
  for (let index = 0; index < completeWords; index += 1) {
    if (words[index] !== expected[index]) return false;
  }
  const remainingBits = prefixLength % 16;
  if (!remainingBits) return true;
  const mask = (0xffff << (16 - remainingBits)) & 0xffff;
  return (words[completeWords] & mask) === (expected[completeWords] & mask);
}

function normalizeHostname(value) {
  return String(value).trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function parseIpv6Words(address) {
  let source = String(address);
  const ipv4Match = source.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (ipv4Match) {
    const octets = ipv4Match[1].split(".").map(Number);
    if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) return null;
    source = `${source.slice(0, -ipv4Match[1].length)}${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const halves = source.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const raw = [...left, ...Array(missing).fill("0"), ...right];
  if (raw.length !== 8 || raw.some((word) => !/^[0-9a-f]{1,4}$/i.test(word))) return null;
  return raw.map((word) => Number.parseInt(word, 16));
}
