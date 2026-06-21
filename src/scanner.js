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
  const agentSkillsRequired = Boolean(options.agentSkills);
  const agentSkills = await loadAgentSkills(options.agentSkills || new URL("/.agent/agent-skills/index.json", url).href, options);
  const page = analyzeHtml(html, url);
  const links = await checkLinks(page.links, url, options);

  const checks = [
    check("robots_txt", robots.ok, robots.ok ? "robots.txt found" : "robots.txt missing or unreachable", "medium"),
    check("sitemap", sitemap.ok, sitemap.ok ? "sitemap.xml found" : "sitemap.xml missing or unreachable", "medium"),
    check("llms_txt", llms.ok, llms.ok ? "llms.txt found" : "llms.txt missing", "high"),
    check("json_ld", page.hasJsonLd, page.hasJsonLd ? "JSON-LD found" : "No JSON-LD/schema.org block found", "medium"),
    check("js_only_content", !page.looksJsOnly, page.looksJsOnly ? "Page has low readable HTML and relies on scripts" : "Readable HTML present", "critical"),
    check("cookie_modal", !page.hasCookieBlocker, page.hasCookieBlocker ? "Cookie/consent blocker text detected" : "No obvious cookie blocker text detected", "medium"),
    check("broken_links", links.broken.length === 0, links.broken.length ? `${links.broken.length} sampled links failed` : "Sampled links reachable", "high"),
    ...openApiChecks(openapi),
    ...mcpChecks(mcp),
    ...agentSkillsChecks(agentSkills, agentSkillsRequired),
  ];

  const score = scoreChecks(checks);
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
    agent_skills: agentSkills,
    links,
    checks,
    readiness: {
      score,
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
    return { ok: response.ok, url: response.url, status: response.status, contentType: response.headers.get("content-type") || "", text };
  } finally {
    clearTimeout(timeout);
  }
}

async function optionalFetch(url, options) {
  try {
    return await fetchText(url, options);
  } catch (error) {
    return { ok: false, url: url.href, status: 0, contentType: "", text: "", error: error.message };
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

async function fetchInput(input, options) {
  if (/^https?:\/\//i.test(input)) return fetchText(input, options);
  try {
    return { ok: true, url: input, status: 200, contentType: "application/json", text: await readText(input) };
  } catch (error) {
    return { ok: false, url: input, status: 0, contentType: "", text: "", error: error.message };
  }
}

export function analyzeHtml(html, url = new URL("https://example.invalid")) {
  // ponytail: regex extraction is enough for static checks; use parse5 when DOM mutation fidelity matters.
  const withoutScripts = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
  const bodyText = decodeEntities(withoutScripts.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
  const scriptCount = (html.match(/<script\b/gi) || []).length;
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
    scriptCount,
    hasJsonLd: /<script[^>]+type=["']application\/ld\+json["']/i.test(html),
    hasCookieBlocker: /\b(cookie|consent|gdpr|privacy preferences)\b/i.test(bodyText) && /\b(accept|reject|manage)\b/i.test(bodyText),
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

function check(id, pass, message, severity = "medium") {
  return { id, pass: Boolean(pass), severity, message };
}

function scoreChecks(checks) {
  const weight = { critical: 30, high: 15, medium: 8, low: 3 };
  const lost = checks.filter((item) => !item.pass).reduce((sum, item) => sum + (weight[item.severity] || 5), 0);
  return clamp(100 - lost, 0, 100);
}

function pickFetch(result) {
  return { ok: result.ok, url: result.url, status: result.status, contentType: result.contentType, bytes: result.text?.length || 0, error: result.error };
}

function decodeEntities(value) {
  return value.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}
