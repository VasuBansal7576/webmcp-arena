import { clamp, nowIso, readText, sha256 } from "./util.js";
import { loadMcpManifest } from "./mcp.js";
import { loadAgentSkills } from "./skills.js";

const DEFAULT_UA = "AgentContractOS/0.1 (+https://agentcontract.dev)";

export async function scanUrl(input, options = {}) {
  const startedAt = nowIso();
  const url = new URL(input);
  const home = await fetchText(url, options);
  const html = home.text;
  const robots = await optionalFetch(new URL("/robots.txt", url), options);
  const sitemap = await optionalFetch(new URL("/sitemap.xml", url), options);
  const llms = await optionalFetch(new URL("/llms.txt", url), options);
  const openapi = options.openapi ? await fetchOpenApi(options.openapi, options) : null;
  const mcp = options.mcp ? await loadMcpManifest(options.mcp, options) : null;
  const agentContract = await loadAgentContract(url, options);
  const a2a = await loadA2aCard(url, options);
  const agentSkillsRequired = Boolean(options.agentSkills);
  const agentSkills = await loadAgentSkills(options.agentSkills || new URL("/.agent/agent-skills/index.json", url).href, options);
  const page = analyzeHtml(html, url, home.headers);
  const links = await checkLinks(page.links, url, options);
  const cpiRisks = page.critical_elements.filter((item) => item.structural_risk);

  const checks = [
    check("robots_txt", robots.ok, robots.ok ? "robots.txt found" : "robots.txt missing or unreachable", "medium"),
    check("sitemap", sitemap.ok, sitemap.ok ? "sitemap.xml found" : "sitemap.xml missing or unreachable", "medium"),
    check("llms_txt", llms.ok, llms.ok ? "llms.txt found" : "llms.txt missing", "high"),
    check("json_ld", page.hasJsonLd, page.hasJsonLd ? "JSON-LD found" : "No JSON-LD/schema.org block found", "medium"),
    check(
      "js_only_content",
      !page.looksJsOnly,
      page.looksJsOnly ? "Page has low readable HTML and relies on scripts" : "Readable HTML present",
      "critical",
      { metrics: { dom_tokens: page.dom_tokens, script_count: page.scriptCount, text_length: page.textLength } },
    ),
    check("cookie_modal", !page.hasCookieBlocker, page.hasCookieBlocker ? "Cookie/consent blocker text detected" : "No obvious cookie blocker text detected", "medium"),
    check(
      "content_position_index",
      cpiRisks.length === 0,
      cpiRisks.length ? `${cpiRisks.length} critical elements sit in the transformer middle-context risk zone` : "Critical elements are not in the middle-context risk zone",
      "medium",
      { elements: page.critical_elements },
    ),
    check(
      "ipi_risk",
      page.ipi_risks.length === 0,
      page.ipi_risks.length ? `${page.ipi_risks.length} indirect prompt-injection patterns detected` : "No indirect prompt-injection patterns detected",
      page.ipi_risks.some((item) => item.severity === "critical") ? "critical" : page.ipi_risks.length ? "high" : "low",
      { findings: page.ipi_risks },
    ),
    check("slider_switch_interactions", !page.hasSliderSwitchRisk, page.hasSliderSwitchRisk ? "Slider/switch controls detected; verify keyboard and ARIA behavior for agents" : "No obvious slider/switch controls detected", "low"),
    check("datagrid_filtering", !page.hasDatagridRisk, page.hasDatagridRisk ? "Datagrid or filterable table detected; verify filtering is represented in accessible controls" : "No obvious datagrid filtering surface detected", "low"),
    check("ab_test_variants", !page.hasAbVariantRisk, page.hasAbVariantRisk ? "A/B or experiment variant markers detected; run missions against stable variants" : "No obvious A/B variant markers detected", "low"),
    check("webmcp_registration", page.hasWebMcp, page.hasWebMcp ? "WebMCP tool registration markers detected" : "No WebMCP tool registration markers detected", "info"),
    check("broken_links", links.broken.length === 0, links.broken.length ? `${links.broken.length} sampled links failed` : "Sampled links reachable", "high"),
    ...agentAuthChecks(agentContract),
    ...a2aChecks(a2a),
    ...openApiChecks(openapi),
    ...mcpChecks(mcp),
    ...agentSkillsChecks(agentSkills, agentSkillsRequired),
  ];

  const score = scoreChecks(checks);
  const awi = awiScores(checks, page, agentSkills);
  return {
    generated_at: startedAt,
    source: { type: "website", url: url.href, content_hash: sha256(html) },
    auth_profile: options.auth?.audit || null,
    page,
    robots: pickFetch(robots),
    sitemap: pickFetch(sitemap),
    llms: pickFetch(llms),
    openapi,
    mcp,
    agent_contract: agentContract,
    a2a,
    agent_skills: agentSkills,
    links,
    checks,
    readiness: {
      score,
      awi,
      level: score >= 85 ? "gold" : score >= 70 ? "silver" : score >= 50 ? "bronze" : "blocked",
      critical_gaps: checks.filter((item) => !item.pass && item.severity === "critical").map((item) => item.message),
    },
  };
}

async function fetchText(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 15000);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": options.userAgent || DEFAULT_UA, accept: "text/html,application/json,text/plain,*/*", ...(options.auth?.headers || {}) },
    });
    const text = await response.text();
    return { ok: response.ok, url: response.url, status: response.status, contentType: response.headers.get("content-type") || "", headers: Object.fromEntries(response.headers.entries()), text };
  } finally {
    clearTimeout(timeout);
  }
}

async function optionalFetch(url, options) {
  try {
    return await fetchText(url, options);
  } catch (error) {
    return { ok: false, url: url.href, status: 0, contentType: "", headers: {}, text: "", error: error.message };
  }
}

async function fetchOpenApi(input, options) {
  const result = await fetchInput(input, options);
  if (!result.ok) return { ok: false, url: input, error: `OpenAPI fetch failed with ${result.status}` };
  try {
    const spec = JSON.parse(result.text);
    return analyzeOpenApi(spec, input);
  } catch {
    return { ok: false, url: input, error: "Only JSON OpenAPI specs are supported in v1. YAML support needs a real parser dependency." };
  }
}

async function loadAgentContract(baseUrl, options) {
  const source = new URL("/.agent/contract.json", baseUrl);
  const result = await optionalFetch(source, options);
  if (!result.ok) return { discovered: false, source: source.href, status: result.status, error: result.error || `contract.json fetch failed with ${result.status}` };
  try {
    const json = JSON.parse(result.text);
    const agentAuth = json?.agent_auth && typeof json.agent_auth === "object" ? json.agent_auth : null;
    return { discovered: true, source: result.url, status: result.status, content_hash: sha256(result.text), agent_auth: agentAuth };
  } catch (error) {
    return { discovered: true, source: result.url, status: result.status, error: `contract.json is not valid JSON: ${error.message}` };
  }
}

async function loadA2aCard(baseUrl, options) {
  const source = new URL("/.well-known/agent.json", baseUrl);
  const result = await optionalFetch(source, options);
  if (!result.ok) return { discovered: false, source: source.href, status: result.status, valid: false, errors: [result.error || `agent.json fetch failed with ${result.status}`] };
  try {
    const json = JSON.parse(result.text);
    const endpoint = agentEndpoint(json, baseUrl);
    const capabilities = Array.isArray(json.capabilities) ? json.capabilities : Array.isArray(json.skills) ? json.skills : [];
    const errors = [];
    if (!capabilities.length) errors.push("no capabilities declared");
    if (!endpoint) errors.push("no endpoint declared");
    let endpointStatus = null;
    let endpointReachable = false;
    if (endpoint) {
      const endpointResult = await optionalFetch(endpoint, options);
      endpointStatus = endpointResult.status;
      endpointReachable = endpointResult.status > 0 && endpointResult.status < 500;
      if (!endpointReachable) errors.push("declared endpoint is unreachable");
    }
    return {
      discovered: true,
      source: result.url,
      status: result.status,
      valid: errors.length === 0,
      content_hash: sha256(result.text),
      capability_count: capabilities.length,
      endpoint: endpoint?.href || "",
      endpoint_status: endpointStatus,
      endpoint_reachable: endpointReachable,
      errors,
    };
  } catch (error) {
    return { discovered: true, source: result.url, status: result.status, valid: false, errors: [`agent.json is not valid JSON: ${error.message}`] };
  }
}

function agentEndpoint(card, baseUrl) {
  const raw = card?.endpoint || card?.url || card?.serviceEndpoint || card?.transport?.url;
  if (!raw) return null;
  try {
    return new URL(String(raw), baseUrl);
  } catch {
    return null;
  }
}

async function fetchInput(input, options) {
  if (/^https?:\/\//i.test(input)) return fetchText(input, options);
  try {
    return { ok: true, url: input, status: 200, contentType: "application/json", headers: {}, text: await readText(input) };
  } catch (error) {
    return { ok: false, url: input, status: 0, contentType: "", headers: {}, text: "", error: error.message };
  }
}

export function analyzeHtml(html, url = new URL("https://example.invalid"), headers = {}) {
  // ponytail: regex extraction is enough for static checks; use parse5 when DOM mutation fidelity matters.
  const withoutScripts = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
  const bodyText = decodeEntities(withoutScripts.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
  const contentHash = sha256(html);
  const scriptCount = (html.match(/<script\b/gi) || []).length;
  const lowerHtml = html.toLowerCase();
  const headerWebMcp = Object.entries(headers).some(([key, value]) => key.toLowerCase() === "webmcp-enabled" && /^(1|true|yes)$/i.test(String(value)));
  const webmcpTools = [...html.matchAll(/\btool-name=["']([^"']+)["']/gi), ...html.matchAll(/\bname:\s*["']([^"']+)["']/gi)].map((match) => match[1].toLowerCase());
  const criticalElements = criticalElementPositions(bodyText, contentHash);
  const links = [...html.matchAll(/href=["']([^"'#]+)["']/gi)]
    .map((match) => {
      try {
        return new URL(match[1], url).href;
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  return {
    title: html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || "",
    textLength: bodyText.length,
    dom_tokens: estimateTokens(bodyText),
    scriptCount,
    hasJsonLd: /<script[^>]+type=["']application\/ld\+json["']/i.test(html),
    hasCookieBlocker: /\b(cookie|consent|gdpr|privacy preferences)\b/i.test(bodyText) && /\b(accept|reject|manage)\b/i.test(bodyText),
    critical_elements: criticalElements,
    ipi_risks: ipiRisks(html, contentHash),
    hasSliderSwitchRisk: /(?:role|type)=["'](?:slider|switch|range)["']|aria-valuenow|class=["'][^"']*(?:slider|switch|toggle)|data-(?:slider|switch|toggle)/i.test(html),
    hasDatagridRisk: /\brole=["']grid["']|class=["'][^"']*(?:data-grid|datagrid|ag-grid|filterable)|data-grid\b/i.test(html) || (/<table\b/i.test(html) && /\b(filter|sort)\b/i.test(bodyText)),
    hasAbVariantRisk: /\b(?:optimizely|launchdarkly|statsig|growthbook|split\.io|data-experiment|data-variant|ab-test|a\/b test|experiment-id)\b/i.test(lowerHtml),
    hasWebMcp: headerWebMcp || /\b(?:navigator|document)\.modelContext\b|\.registerTool\s*\(|@mcp-b\/global|\btool-(?:name|description)=["']/i.test(html),
    webmcp_components: webMcpCoverage(bodyText, webmcpTools),
    looksJsOnly: bodyText.length < 300 && scriptCount > 3,
    links: [...new Set(links)].slice(0, 100),
    sampleText: bodyText.slice(0, 500),
  };
}

async function checkLinks(links, baseUrl, options) {
  const sameOrigin = links.filter((link) => {
    try {
      return new URL(link).origin === baseUrl.origin;
    } catch {
      return false;
    }
  }).slice(0, options.linkLimit ?? 12);

  const results = [];
  for (const link of sameOrigin) {
    try {
      const result = await fetchText(link, { ...options, timeoutMs: Math.min(options.timeoutMs ?? 15000, 8000) });
      results.push({ url: link, status: result.status, ok: result.status < 400 });
    } catch (error) {
      results.push({ url: link, status: 0, ok: false, error: error.message });
    }
  }
  return { checked: results.length, broken: results.filter((item) => !item.ok), results };
}

function analyzeOpenApi(spec, url) {
  const operations = Object.values(spec.paths || {}).flatMap((pathItem) => Object.values(pathItem || {}).filter((value) => value && typeof value === "object"));
  const withDescriptions = operations.filter((operation) => operation.summary || operation.description).length;
  const withExamples = operations.filter((operation) => JSON.stringify(operation).includes('"example"') || JSON.stringify(operation).includes('"examples"')).length;
  const hasErrorResponses = operations.some((operation) => Object.keys(operation.responses || {}).some((status) => /^[45]/.test(status)));
  return {
    ok: true,
    url,
    title: spec.info?.title || "",
    version: spec.info?.version || "",
    path_count: Object.keys(spec.paths || {}).length,
    operation_count: operations.length,
    described_operation_rate: operations.length ? withDescriptions / operations.length : 0,
    example_rate: operations.length ? withExamples / operations.length : 0,
    has_error_responses: hasErrorResponses,
    has_security: Boolean(spec.security || spec.components?.securitySchemes),
  };
}

function openApiChecks(openapi) {
  if (!openapi) return [];
  if (!openapi.ok) return [check("openapi_parse", false, openapi.error, "high")];
  return [
    check("openapi_descriptions", openapi.described_operation_rate >= 0.8, `${Math.round(openapi.described_operation_rate * 100)}% of operations have descriptions`, "medium"),
    check("openapi_examples", openapi.example_rate >= 0.5, `${Math.round(openapi.example_rate * 100)}% of operations have examples`, "high"),
    check("openapi_error_docs", openapi.has_error_responses, openapi.has_error_responses ? "Error responses documented" : "No 4xx/5xx responses documented", "high"),
    check("openapi_auth_docs", openapi.has_security, openapi.has_security ? "Security schemes documented" : "No security scheme documented", "medium"),
  ];
}

function mcpChecks(mcp) {
  if (!mcp) return [];
  if (!mcp.discovered) return [check("mcp_discovery", false, mcp.error || "MCP manifest missing or unreachable", "high")];
  return [
    check("mcp_discovery", true, `MCP manifest discovered with ${mcp.tool_count} tools`, "medium"),
    check(
      "mcp_spec_version",
      mcp.spec_version_compliant,
      mcp.spec_version ? `MCP spec version ${mcp.spec_version}` : "MCP spec version missing",
      "medium",
    ),
    check(
      "mcp_dangerous_tools",
      mcp.unapproved_dangerous_tools.length === 0,
      mcp.unapproved_dangerous_tools.length
        ? `${mcp.unapproved_dangerous_tools.length} dangerous MCP tools lack explicit human approval`
        : "No unapproved dangerous MCP tools detected",
      "critical",
    ),
  ];
}

function agentSkillsChecks(agentSkills, required) {
  if (!required && !agentSkills.discovered) return [];
  return [
    check(
      "agent_skills_discovery",
      agentSkills.discovered,
      agentSkills.discovered ? `Agent skills index discovered with ${agentSkills.skill_count} skills` : agentSkills.error || "Agent skills index missing",
      required ? "high" : "low",
    ),
  ];
}

function agentAuthChecks(agentContract) {
  const declared = Boolean(agentContract?.agent_auth);
  const message = declared
    ? "Agent identity declaration found in .agent/contract.json"
    : agentContract?.error?.startsWith("contract.json is not valid JSON")
      ? agentContract.error
      : "No agent_auth block declared in .agent/contract.json";
  return [
    check(
      "agent_auth_undeclared",
      declared,
      message,
      declared ? "low" : "info",
      { source: agentContract?.source || "", discovered: Boolean(agentContract?.discovered) },
    ),
  ];
}

function a2aChecks(a2a) {
  if (!a2a?.discovered) {
    return [check("a2a_card_absent", false, "/.well-known/agent.json missing or unreachable", "info", { source: a2a?.source || "" })];
  }
  if (!a2a.valid) {
    return [check("a2a_card_invalid", false, a2a.errors?.join("; ") || "/.well-known/agent.json is invalid", "medium", { source: a2a.source, errors: a2a.errors || [] })];
  }
  return [check("a2a_card_valid", true, `A2A Agent Card valid with ${a2a.capability_count} capabilities`, "low", { source: a2a.source, endpoint: a2a.endpoint })];
}

function check(id, pass, message, severity = "medium", details = {}) {
  return {
    id,
    pass: Boolean(pass),
    severity,
    message,
    taxonomy: TAXONOMY[id] || "AgentContract::GeneralReadiness",
    dimension: DIMENSION[id] || "discoverability",
    framing: FRAMING[id] || "",
    ...details,
  };
}

function scoreChecks(checks) {
  const weight = { critical: 30, high: 15, medium: 8, low: 3, info: 0 };
  const lost = checks.filter((item) => !item.pass).reduce((sum, item) => sum + (weight[item.severity] ?? 5), 0);
  return clamp(100 - lost, 0, 100);
}

function estimateTokens(text) {
  return Math.ceil((text || "").length / 4);
}

function awiScores(checks, page, agentSkills) {
  const failed = new Set(checks.filter((item) => !item.pass).map((item) => item.id));
  const axes = {
    safety: axis(20, failed.has("mcp_dangerous_tools") ? 12 : 0, failed.has("cookie_modal") ? 4 : 0),
    efficiency: axis(20, failed.has("js_only_content") ? 12 : 0, page.dom_tokens > 5000 ? 4 : 0),
    standardization: axis(20, failed.has("llms_txt") ? 8 : 0, failed.has("mcp_spec_version") ? 4 : 0, page.hasWebMcp ? 0 : 2),
    discoverability: axis(20, failed.has("sitemap") ? 5 : 0, failed.has("json_ld") ? 5 : 0, agentSkills.discovered ? 0 : 3, failed.has("a2a_card_absent") || failed.has("a2a_card_invalid") ? 2 : 0),
    observability: 20,
    policy_compliance: axis(20, failed.has("robots_txt") ? 5 : 0, failed.has("mcp_dangerous_tools") ? 10 : 0, failed.has("agent_auth_undeclared") ? 2 : 0),
  };
  return { total: Object.values(axes).reduce((sum, value) => sum + value, 0), max: 120, axes };
}

function axis(max, ...losses) {
  return clamp(max - losses.reduce((sum, value) => sum + value, 0), 0, max);
}

function webMcpCoverage(text, toolNames) {
  const components = ["checkout", "contact", "pricing", "signup", "api key"];
  const detected = components.filter((item) => new RegExp(item.replace(" ", "[ -]?"), "i").test(text));
  const annotated = detected.filter((item) => toolNames.some((tool) => tool.includes(item.replace(" ", "_")) || tool.includes(item.replace(" ", "")) || tool.includes(item)));
  const score = detected.length ? annotated.length / detected.length : null;
  const unannotated = detected.filter((item) => !annotated.includes(item));
  return {
    detected,
    annotated,
    unannotated,
    score,
    coverage: detected.length ? { annotated: annotated.length, unannotated: unannotated.length, total: detected.length } : null,
    estimated_completion_rate_ceiling: score === null ? null : {
      current: Math.round((61.7 + (86.3 - 61.7) * score) * 10) / 10,
      all_annotated: 86.3,
      baseline_unannotated: 61.7,
      source: "CI4A arXiv:2601.14790",
    },
  };
}

function criticalElementPositions(text, contentHash) {
  const tokens = estimateTokens(text);
  if (!tokens) return [];
  return [
    ["pricing", /\b(pricing|plans?|enterprise|startup|\$\d+)/i],
    ["api_quickstart", /\b(api quickstart|quickstart|GET \/|POST \/|curl\b)/i],
    ["cta", /\b(get started|start trial|book demo|contact sales|sign up|signup)\b/i],
    ["contact_form", /\b(contact|sales|email|message)\b/i],
    ["mcp_endpoint", /\b(mcp|model context protocol|\.well-known\/mcp)\b/i],
    ["checkout", /\b(checkout|cart|payment|subscribe)\b/i],
  ].flatMap(([id, pattern]) => {
    const match = pattern.exec(text);
    if (!match) return [];
    const cpi = estimateTokens(text.slice(0, match.index)) / tokens;
    return [{ id, cpi: Math.round(cpi * 1000) / 1000, structural_risk: cpi > 0.3 && cpi < 0.7, content_hash: `sha256:${sha256(match[0])}`, page_content_hash: `sha256:${contentHash}` }];
  });
}

function ipiRisks(html, contentHash) {
  const rules = [
    { severity: "high", pattern: /aria-label=["'][^"']{0,80}(ignore|disregard|instead|override|new instruction)[^"']*["']/i },
    { severity: "high", pattern: /style=["'][^"']*(?:opacity:\s*0|display:\s*none)[^"']*["'][^>]*>[^<]*(you must|your task is now|ignore previous)/i },
    { severity: "medium", pattern: /role=["']note["'][^>]*>[^<]*(click|send|transfer|ignore|do not)/i },
    { severity: "medium", pattern: /<span[^>]*class=["'][^"']*(?:sr-only|visually-hidden|hidden)[^"']*["'][^>]*>[^<]*(ignore|instead|new goal)/i },
    { severity: "critical", pattern: /(send|exfiltrate|post).{0,80}(token|cookie|session|credential)/i },
  ];
  return rules.flatMap((rule) => {
    const match = rule.pattern.exec(html);
    if (!match) return [];
    const snippet = match[0].replace(/\s+/g, " ").slice(0, 220);
    return [{ severity: rule.severity, snippet, content_hash: `sha256:${sha256(snippet)}`, page_content_hash: `sha256:${contentHash}` }];
  });
}

const TAXONOMY = {
  js_only_content: "AWI::DOMComplexity",
  content_position_index: "LostInTheMiddle::ContentPositionIndex",
  ipi_risk: "WebAgentSecurity::IndirectPromptInjection",
  cookie_modal: "BrowserArena::PopUpBannerRemoval",
  slider_switch_interactions: "BrowserArena::DynamicUIControl",
  datagrid_filtering: "BrowserArena::DynamicUIControl",
  ab_test_variants: "BrowserArena::VariantInstability",
  broken_links: "BrowserArena::DirectNavigationBlocked",
  mcp_dangerous_tools: "MCP::ToolRugPullRisk",
  mcp_discovery: "MCP::Discovery",
  mcp_spec_version: "MCP::SpecVersion",
  webmcp_registration: "WebMCP::ToolRegistration",
  agent_auth_undeclared: "AgentIdentity::Declaration",
  a2a_card_absent: "A2A::AgentCard",
  a2a_card_invalid: "A2A::AgentCard",
  a2a_card_valid: "A2A::AgentCard",
};

const DIMENSION = {
  ipi_risk: "safety",
  cookie_modal: "safety",
  mcp_dangerous_tools: "safety",
  content_position_index: "efficiency",
  js_only_content: "efficiency",
  webmcp_registration: "standardization",
  mcp_discovery: "standardization",
  mcp_spec_version: "policy_compliance",
  agent_auth_undeclared: "policy_compliance",
  a2a_card_absent: "discoverability",
  a2a_card_invalid: "discoverability",
  a2a_card_valid: "discoverability",
  openapi_descriptions: "standardization",
  openapi_examples: "standardization",
  openapi_error_docs: "standardization",
  openapi_auth_docs: "policy_compliance",
  robots_txt: "discoverability",
  sitemap: "discoverability",
  llms_txt: "standardization",
  json_ld: "discoverability",
  agent_skills_discovery: "discoverability",
  broken_links: "discoverability",
};

const FRAMING = {
  js_only_content: "Research framing: DOM-heavy or JS-only pages increase agent navigation cost before task work begins.",
  content_position_index: "Research framing: middle-positioned critical content is more likely to be missed by long-context transformer attention.",
  ipi_risk: "Research framing: hidden or accessibility-only imperative instructions can hijack web agents through the page representation they consume.",
  cookie_modal: "Research framing: pop-up and consent banners are a recurring real-world browser-agent failure mode.",
  slider_switch_interactions: "Research framing: dynamic controls often need explicit accessible state for reliable agent use.",
  datagrid_filtering: "Research framing: filterable grids hide state unless controls are browser-readable.",
  ab_test_variants: "Research framing: unstable variants make mission replay less trustworthy.",
  broken_links: "Research framing: direct navigation failures block agents before task reasoning starts.",
  mcp_dangerous_tools: "Research framing: MCP tools with side effects need explicit human-approval boundaries.",
  agent_auth_undeclared: "Research framing: payment and account agents need declared identity and consent boundaries before checkout-like workflows.",
  a2a_card_absent: "Research framing: A2A Agent Cards make delegated agent endpoints discoverable without manual orchestration setup.",
  a2a_card_invalid: "Research framing: invalid Agent Cards break machine-to-machine delegation even when a human docs page exists.",
};

function pickFetch(result) {
  return { ok: result.ok, url: result.url, status: result.status, contentType: result.contentType, bytes: result.text?.length || 0, error: result.error };
}

function decodeEntities(value) {
  return value.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}
