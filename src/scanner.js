import { clamp, nowIso, readText, sha256 } from "./util.js";
import { loadMcpManifest } from "./mcp.js";
import { loadAgentSkills } from "./skills.js";
import { fetchTextSafely } from "./safe-fetch.js";

const MAX_EXTERNAL_WEBMCP_SCRIPTS = 6;
const MAX_EXTERNAL_WEBMCP_SCRIPT_BYTES = 256 * 1024;
const MAX_EXTERNAL_WEBMCP_TOTAL_BYTES = 512 * 1024;
const MAX_EXTERNAL_WEBMCP_REDIRECTS = 2;
const MAX_EXTERNAL_WEBMCP_TIMEOUT_MS = 5_000;
const JAVASCRIPT_CONTENT_TYPES = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
]);

export async function scanUrl(input, options = {}) {
  const startedAt = nowIso();
  const url = new URL(input);
  const scopedOptions = { ...options, authOrigin: url.origin };
  const home = await fetchText(url, scopedOptions);
  const html = home.text;
  const effectiveUrl = new URL(home.url);
  const robots = await optionalFetch(new URL("/robots.txt", effectiveUrl), scopedOptions);
  const sitemap = await optionalFetch(new URL("/sitemap.xml", effectiveUrl), scopedOptions);
  const llms = await optionalFetch(new URL("/llms.txt", effectiveUrl), scopedOptions);
  const openapi = options.openapi ? await fetchOpenApi(options.openapi, scopedOptions) : null;
  const mcp = options.mcp ? await loadMcpManifest(options.mcp, scopedOptions) : null;
  const agentContract = await loadAgentContract(effectiveUrl, scopedOptions);
  const a2a = await loadA2aCard(effectiveUrl, scopedOptions);
  const agentSkillsRequired = Boolean(options.agentSkills);
  const agentSkills = await loadAgentSkills(options.agentSkills || new URL("/.agent/agent-skills/index.json", effectiveUrl).href, scopedOptions);
  const page = analyzeHtml(html, effectiveUrl, home.headers, {
    redactSnippets: Boolean(options.auth),
  });
  const externalScriptInspection = home.ok && /^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/i.test(home.contentType || "")
    ? await inspectExternalWebMcpScripts(html, effectiveUrl, scopedOptions)
    : emptyExternalScriptInspection();
  applyExternalWebMcpInspection(page, externalScriptInspection);
  const targetDocumentValid = validTargetDocument(home, page, html);
  const links = await checkLinks(page.links, effectiveUrl, scopedOptions);
  const cpiRisks = page.critical_elements.filter((item) => item.structural_risk);
  const robotsValid = validRobots(robots);
  const sitemapValid = validSitemap(sitemap);
  const llmsValid = validLlms(llms);

  const checks = [
    check("target_reachable", home.ok, home.ok ? `Homepage returned HTTP ${home.status}` : `Homepage returned HTTP ${home.status}`, "critical"),
    check(
      "target_document_valid",
      targetDocumentValid,
      targetDocumentValid
        ? "Homepage is a meaningful HTML document"
        : `Homepage is not a meaningful HTML document (${home.contentType || "content type missing"})`,
      "critical",
      { content_type: home.contentType, text_length: page.textLength, script_count: page.scriptCount },
    ),
    check("robots_txt", robotsValid, robotsValid ? "robots.txt found and parsed" : "robots.txt missing, unreachable, or invalid", "medium"),
    check("sitemap", sitemapValid, sitemapValid ? "sitemap.xml found and parsed" : "sitemap.xml missing, unreachable, or invalid", "medium"),
    check("llms_txt", llmsValid, llmsValid ? "llms.txt found and parsed" : "llms.txt missing or invalid", "high"),
    check("json_ld", page.hasJsonLd, page.hasJsonLd ? "JSON-LD found" : "No JSON-LD/schema.org block found", "medium"),
    check(
      "js_only_content",
      page.hasReadableHtml && !page.looksJsOnly,
      page.looksJsOnly
        ? "Page has low readable HTML and relies on scripts"
        : page.hasReadableHtml ? "Readable HTML present" : "No meaningful readable HTML is present",
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
    check("webmcp_registration", page.hasWebMcp, page.hasWebMcp ? "Static hint of WebMCP registration detected; runtime inspection is still required" : "No WebMCP marker was found in fetched source; runtime state remains unknown", "info"),
    check("broken_links", links.broken.length === 0, links.broken.length ? `${links.broken.length} sampled links failed` : "Sampled links reachable", "high"),
    ...agentAuthChecks(agentContract),
    ...a2aChecks(a2a),
    ...openApiChecks(openapi),
    ...mcpChecks(mcp),
    ...agentSkillsChecks(agentSkills, agentSkillsRequired),
  ];

  const score = targetDocumentValid ? scoreChecks(checks) : 0;
  const awi = awiScores(checks, page, agentSkills);
  const report = {
    generated_at: startedAt,
    kind: "arena.webmcp_preflight",
    version: 1,
    source: {
      type: "website",
      requested_url: url.href,
      effective_url: effectiveUrl.href,
      url: effectiveUrl.href,
      status: home.status,
      content_type: home.contentType,
      content_hash: sha256(html),
    },
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
    webmcp_preflight: {
      scope: "static_source_hint_only",
      candidate_count: page.webmcp_candidates.length,
      candidates: page.webmcp_candidates,
      external_scripts_uninspected: page.webmcp_evidence.external_scripts_uninspected,
      external_script_inspection: externalScriptInspection.summary,
      runtime_discovered: false,
      behavior_verified: false,
      score: null,
    },
    readiness: {
      scope: "generic_agent_web_preflight",
      score,
      awi,
      level: score >= 85 ? "gold" : score >= 70 ? "silver" : score >= 50 ? "bronze" : "blocked",
      critical_gaps: checks.filter((item) => !item.pass && item.severity === "critical").map((item) => item.message),
    },
  };
  return options.auth ? redactAuthenticatedReport(report) : report;
}

async function fetchText(url, options = {}) {
  return fetchTextSafely(url, options);
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
      const endpointResult = await optionalFetch(endpoint, { ...options, auth: null });
      endpointStatus = endpointResult.status;
      endpointReachable = endpointResult.ok === true;
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

export function analyzeHtml(html, url = new URL("https://example.invalid"), headers = {}, options = {}) {
  // ponytail: regex extraction is enough for static checks; use parse5 when DOM mutation fidelity matters.
  const withoutScripts = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "");
  const bodyText = decodeEntities(withoutScripts.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim());
  const contentHash = sha256(html);
  const scriptMatches = [...String(html).matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  const scriptCount = scriptMatches.length;
  const externalScriptCount = scriptMatches.filter((match) => /(?:^|\s)src\s*=/i.test(match[1])).length;
  const executableScriptCount = scriptMatches.filter((match) => isJavaScriptType(match[1]) &&
    (/(?:^|\s)src\s*=/i.test(match[1]) || match[2].trim().length >= 10)).length;
  const lowerHtml = html.toLowerCase();
  const headerWebMcp = Object.entries(headers).some(([key, value]) => key.toLowerCase() === "webmcp-enabled" && /^(1|true|yes)$/i.test(String(value)));
  const webmcpCandidates = detectWebMcpCandidates(html);
  const webmcpTools = webmcpCandidates.map((candidate) => candidate.tool_name).filter(Boolean);
  const criticalElements = criticalElementPositions(bodyText, contentHash);
  const documentBaseUrl = effectiveDocumentBaseUrl(html, url);
  const links = [...html.matchAll(/href=["']([^"'#]+)["']/gi)]
    .map((match) => {
      try {
        return new URL(match[1], documentBaseUrl).href;
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  return {
    title: options.redactSnippets === true ? null : html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || "",
    textLength: bodyText.length,
    dom_tokens: estimateTokens(bodyText),
    scriptCount,
    hasJsonLd: /<script[^>]+type=["']application\/ld\+json["']/i.test(html),
    hasCookieBlocker: /\b(cookie|consent|gdpr|privacy preferences)\b/i.test(bodyText) && /\b(accept|reject|manage)\b/i.test(bodyText),
    critical_elements: criticalElements,
    ipi_risks: ipiRisks(html, contentHash, options.redactSnippets === true),
    hasSliderSwitchRisk: /(?:role|type)=["'](?:slider|switch|range)["']|aria-valuenow|class=["'][^"']*(?:slider|switch|toggle)|data-(?:slider|switch|toggle)/i.test(html),
    hasDatagridRisk: /\brole=["']grid["']|class=["'][^"']*(?:data-grid|datagrid|ag-grid|filterable)|data-grid\b/i.test(html) || (/<table\b/i.test(html) && /\b(filter|sort)\b/i.test(bodyText)),
    hasAbVariantRisk: /\b(?:optimizely|launchdarkly|statsig|growthbook|split\.io|data-experiment|data-variant|ab-test|a\/b test|experiment-id)\b/i.test(lowerHtml),
    hasWebMcp: headerWebMcp || webmcpCandidates.length > 0,
    webmcp_evidence: {
      level: headerWebMcp || webmcpCandidates.length > 0 ? "static_marker" : "none_in_fetched_source",
      runtime_discovered: false,
      behavior_verified: false,
      external_scripts_uninspected: externalScriptCount,
    },
    webmcp_candidates: webmcpCandidates,
    webmcp_component_keyword_heuristic: webMcpCoverage(bodyText, webmcpTools),
    hasReadableHtml: bodyText.length >= 20,
    executableScriptCount,
    looksJsOnly: bodyText.length < 300 && executableScriptCount > 0,
    links: [...new Set(links)].slice(0, 100),
    sampleText: options.redactSnippets === true ? null : bodyText.slice(0, 500),
  };
}

function detectWebMcpCandidates(html) {
  const sourceHtml = String(html);
  const activeHtml = activeHtmlMarkup(sourceHtml, { includeScripts: true });
  const scripts = [...activeHtml.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)]
    .filter((match) => isJavaScriptType(match[1]))
    .map((match) => tokenizeJavaScript(match[2].replace(/<!--[\s\S]*?-->/g, "")));
  const candidates = [];
  for (const tokens of scripts) {
    candidates.push(...imperativeCandidates(tokens, "document", "current"));
  }
  for (const tokens of scripts) {
    candidates.push(...imperativeCandidates(tokens, "navigator", "legacy"));
  }
  const declarativeHtml = activeHtmlMarkup(sourceHtml);
  const tags = [...declarativeHtml.matchAll(/<[a-z][^>]*>/gi)].map((match) => match[0]);
  for (const tag of tags) {
    const value = htmlAttributeValue(tag, "toolname");
    if (value) candidates.push({ kind: "declarative", syntax: "explainer", tool_name: value.toLowerCase() });
  }
  for (const tag of tags) {
    const value = htmlAttributeValue(tag, "tool-name");
    if (value) candidates.push({ kind: "declarative", syntax: "nonstandard", tool_name: value.toLowerCase() });
  }
  return [...new Map(candidates.map((candidate) => [JSON.stringify(candidate), candidate])).values()];
}

async function inspectExternalWebMcpScripts(html, pageUrl, options) {
  const sources = externalJavaScriptSources(html, pageUrl);
  const candidates = [];
  const summary = emptyExternalScriptInspection().summary;
  summary.references = sources.length;
  let downloadedBytes = 0;

  for (const source of sources) {
    if (!source.url || !new Set(["http:", "https:"]).has(source.url.protocol) ||
        source.url.origin !== pageUrl.origin || source.url.username || source.url.password) {
      summary.skipped_cross_origin += 1;
      continue;
    }
    summary.same_origin += 1;
    if (summary.attempted >= MAX_EXTERNAL_WEBMCP_SCRIPTS) {
      summary.skipped_limit += 1;
      continue;
    }
    const remainingBytes = MAX_EXTERNAL_WEBMCP_TOTAL_BYTES - downloadedBytes;
    if (remainingBytes < 1) {
      summary.failures.byte_limit += 1;
      continue;
    }
    summary.attempted += 1;

    let response;
    try {
      response = await fetchText(source.url, {
        ...options,
        accept: "text/javascript,application/javascript,application/ecmascript,text/ecmascript",
        maxBytes: Math.min(MAX_EXTERNAL_WEBMCP_SCRIPT_BYTES, remainingBytes),
        maxRedirects: MAX_EXTERNAL_WEBMCP_REDIRECTS,
        sameOriginRedirectsOnly: true,
        timeoutMs: Math.min(options.timeoutMs ?? MAX_EXTERNAL_WEBMCP_TIMEOUT_MS, MAX_EXTERNAL_WEBMCP_TIMEOUT_MS),
      });
    } catch (error) {
      summary.failures[externalScriptFailure(error)] += 1;
      continue;
    }
    if (!response.ok) {
      summary.failures.other += 1;
      continue;
    }
    const bytes = Buffer.byteLength(response.text);
    downloadedBytes += bytes;
    if (!isJavaScriptContentType(response.contentType)) {
      summary.rejected_content_type += 1;
      continue;
    }

    summary.inspected += 1;
    const found = detectImperativeCandidates(response.text).map((candidate) => ({
      ...candidate,
      source: "external_script",
      source_url: source.url.href,
    }));
    candidates.push(...found);
    summary.candidates_found += found.length;
  }

  return { candidates, summary };
}

function emptyExternalScriptInspection() {
  return {
    candidates: [],
    summary: {
      references: 0,
      same_origin: 0,
      attempted: 0,
      inspected: 0,
      candidates_found: 0,
      skipped_cross_origin: 0,
      skipped_limit: 0,
      rejected_content_type: 0,
      failures: {
        byte_limit: 0,
        redirect_limit: 0,
        redirect_origin: 0,
        timeout: 0,
        other: 0,
      },
    },
  };
}

function applyExternalWebMcpInspection(page, inspection) {
  if (inspection.candidates.length) {
    page.webmcp_candidates = [...new Map(
      [...page.webmcp_candidates, ...inspection.candidates]
        .map((candidate) => [JSON.stringify(candidate), candidate]),
    ).values()];
  }
  page.hasWebMcp = page.hasWebMcp || inspection.candidates.length > 0;
  page.webmcp_evidence.level = page.hasWebMcp ? "static_marker" : "none_in_fetched_source";
  page.webmcp_evidence.external_scripts_uninspected = inspection.summary.references - inspection.summary.inspected;
}

function externalJavaScriptSources(html, pageUrl) {
  const sourceHtml = activeHtmlMarkup(html, { includeScripts: true });
  const documentBaseUrl = effectiveDocumentBaseUrl(sourceHtml, pageUrl);
  const scriptSources = [...sourceHtml.matchAll(/<script\b([^>]*)>[\s\S]*?<\/script>/gi)]
    .filter((match) => isJavaScriptType(match[1]))
    .map((match) => htmlAttributeValue(match[1], "src"))
    .filter(Boolean);
  const modulePreloads = [...sourceHtml.matchAll(/<link\b([^>]*)>/gi)]
    .filter((match) => String(htmlAttributeValue(match[1], "rel") || "").toLowerCase().split(/\s+/).includes("modulepreload"))
    .map((match) => htmlAttributeValue(match[1], "href"))
    .filter(Boolean);
  const seen = new Set();
  return [...scriptSources, ...modulePreloads].flatMap((rawSource) => {
    try {
      const url = new URL(decodeEntities(rawSource), documentBaseUrl);
      url.hash = "";
      if (seen.has(url.href)) return [];
      seen.add(url.href);
      return [{ url }];
    } catch {
      return [{ url: null }];
    }
  });
}

function effectiveDocumentBaseUrl(html, pageUrl) {
  const baseTag = activeHtmlMarkup(html).match(/<base\b([^>]*)>/i);
  const rawHref = baseTag ? htmlAttributeValue(baseTag[1], "href") : null;
  if (!rawHref) return pageUrl;
  try {
    const candidate = new URL(decodeEntities(rawHref), pageUrl);
    return new Set(["http:", "https:"]).has(candidate.protocol) ? candidate : pageUrl;
  } catch {
    return pageUrl;
  }
}

function activeHtmlMarkup(html, { includeScripts = false } = {}) {
  let source = String(html)
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(style|textarea|template|noscript|xmp)\b[^>]*>[\s\S]*?<\/\1>/gi, "");
  if (!includeScripts) source = source.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
  return source;
}

function detectImperativeCandidates(source) {
  const tokens = tokenizeJavaScript(String(source));
  return [
    ...imperativeCandidates(tokens, "document", "current"),
    ...imperativeCandidates(tokens, "navigator", "legacy"),
  ];
}

function isJavaScriptContentType(value) {
  const essence = String(value).split(";", 1)[0].trim().toLowerCase();
  return JAVASCRIPT_CONTENT_TYPES.has(essence);
}

function externalScriptFailure(error) {
  const message = `${error?.message || ""} ${error?.cause?.message || ""}`.toLowerCase();
  if (/byte limit/.test(message)) return "byte_limit";
  if (/redirect limit/.test(message)) return "redirect_limit";
  if (/leaves the requested origin/.test(message)) return "redirect_origin";
  if (/timed out|aborted/.test(message)) return "timeout";
  return "other";
}

function htmlAttributeValue(tag, name) {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = String(tag).match(new RegExp(`(?:^|\\s)${escapedName}\\s*=\\s*(?:"([^"]+)"|'([^']+)'|([^\\s"'=<>\u0060]+))`, "i"));
  return match?.[1] || match?.[2] || match?.[3] || null;
}

function imperativeCandidates(tokens, owner, syntax) {
  const aliases = new Set();
  const functionAliases = new Set();
  const stringBindings = new Map();
  const toolBindings = new Map();
  const found = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.type === "identifier" && tokens[index + 1]?.value === "=" &&
        matchesMember(tokens, index + 2, owner, "modelContext") !== -1) {
      aliases.add(tokens[index].value);
    }
    if (tokens[index]?.value !== "{") continue;
    const close = findFlatClosingBrace(tokens, index);
    if (close === -1 || tokens[close + 1]?.value !== "=") continue;
    if (tokens[close + 2]?.type === "identifier" && tokens[close + 2].value === owner) {
      const alias = destructuredAlias(tokens, index, close, "modelContext");
      if (alias) aliases.add(alias);
    }
    if (matchesMember(tokens, close + 2, owner, "modelContext") !== -1) {
      const alias = destructuredAlias(tokens, index, close, "registerTool");
      if (alias) functionAliases.add(alias);
    }
  }
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index]?.type === "identifier" && tokens[index + 1]?.value === "=") {
      if (tokens[index + 2]?.type === "string") {
        stringBindings.set(tokens[index].value, tokens[index + 2].value);
      } else if (tokens[index + 2]?.value === "{") {
        const boundName = objectStringProperty(tokens, index + 2, "name", stringBindings);
        if (boundName) toolBindings.set(tokens[index].value, boundName);
      }
    }
    let cursor = matchesMember(tokens, index, owner, "modelContext", "registerTool");
    if (cursor === -1 && tokens[index]?.type === "identifier" && aliases.has(tokens[index].value)) {
      cursor = matchesMember(tokens, index, tokens[index].value, "registerTool");
    }
    if (cursor === -1 && tokens[index]?.type === "identifier" && functionAliases.has(tokens[index].value)) {
      cursor = index + 1;
    }
    if (cursor === -1 || tokens[cursor]?.value !== "(") continue;
    const argument = tokens[cursor + 1];
    const name = argument?.value === "{"
      ? objectStringProperty(tokens, cursor + 1, "name", stringBindings)
      : argument?.type === "identifier" ? toolBindings.get(argument.value) : null;
    found.push({
      kind: "imperative",
      syntax,
      tool_name: name ? name.toLowerCase() : null,
    });
  }
  return found;
}

function matchesMember(tokens, start, owner, ...members) {
  if (tokens[start]?.type !== "identifier" || tokens[start].value !== owner) return -1;
  let cursor = start + 1;
  for (const member of members) {
    cursor = memberAccess(tokens, cursor, member);
    if (cursor === -1) return -1;
  }
  return cursor;
}

function memberAccess(tokens, start, member) {
  if (new Set([".", "?."]).has(tokens[start]?.value) &&
      new Set(["identifier", "string"]).has(tokens[start + 1]?.type) && tokens[start + 1].value === member) {
    return start + 2;
  }
  const bracket = tokens[start]?.value === "?." ? start + 1 : start;
  if (tokens[bracket]?.value === "[" && tokens[bracket + 1]?.type === "string" &&
      tokens[bracket + 1].value === member && tokens[bracket + 2]?.value === "]") {
    return bracket + 3;
  }
  return -1;
}

function findFlatClosingBrace(tokens, start) {
  let depth = 0;
  for (let index = start; index < tokens.length && index < start + 100; index += 1) {
    if (tokens[index].value === "{") depth += 1;
    else if (tokens[index].value === "}" && --depth === 0) return index;
  }
  return -1;
}

function destructuredAlias(tokens, start, end, property) {
  for (let index = start + 1; index < end; index += 1) {
    if (tokens[index]?.type !== "identifier" || tokens[index].value !== property) continue;
    if (tokens[index + 1]?.value === ":" && tokens[index + 2]?.type === "identifier") return tokens[index + 2].value;
    return property;
  }
  return null;
}

function objectStringProperty(tokens, start, property, stringBindings = new Map()) {
  let depth = 0;
  for (let index = start; index < tokens.length && index < start + 2_000; index += 1) {
    const token = tokens[index];
    if (token.value === "{") depth += 1;
    else if (token.value === "}") {
      depth -= 1;
      if (depth === 0) return null;
    } else if (depth === 1 && (token.type === "identifier" || token.type === "string") && token.value === property &&
               tokens[index + 1]?.value === ":") {
      if (tokens[index + 2]?.type === "string") return tokens[index + 2].value;
      if (tokens[index + 2]?.type === "identifier") return stringBindings.get(tokens[index + 2].value) || null;
    } else if (depth === 1 && token.value === "[" && tokens[index + 1]?.type === "string" &&
               tokens[index + 1].value === property && tokens[index + 2]?.value === "]" &&
               tokens[index + 3]?.value === ":" && tokens[index + 4]?.type === "string") {
      return tokens[index + 4].value;
    }
  }
  return null;
}

function isJavaScriptType(attributes) {
  const match = String(attributes).match(/(?:^|\s)type\s*=\s*(["'])([^"']+)\1/i);
  if (!match) return true;
  const type = match[2].trim().toLowerCase().split(";")[0];
  return type === "module" || /^(?:text|application)\/(?:java|ecma)script$/.test(type);
}

function tokenizeJavaScript(source) {
  const tokens = [];
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && source[index + 1] === "/") {
      index = source.indexOf("\n", index + 2);
      if (index === -1) break;
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      const end = source.indexOf("*/", index + 2);
      index = end === -1 ? source.length : end + 2;
      continue;
    }
    if (char === "/" && isRegexLiteralStart(tokens)) {
      const end = skipRegexLiteral(source, index);
      if (end !== -1) {
        index = end;
        continue;
      }
    }
    if (char === "\"" || char === "'") {
      const string = readJavaScriptString(source, index, char);
      tokens.push({ type: "string", value: string.value });
      index = string.end;
      continue;
    }
    if (char === "`") {
      const template = readTemplateLiteral(source, index + 1);
      if (template.expressions.length === 0) tokens.push({ type: "string", value: template.value });
      else {
        for (const expression of template.expressions) tokens.push(...tokenizeJavaScript(expression));
      }
      index = template.end;
      continue;
    }
    if (/[A-Za-z_$]/.test(char)) {
      let end = index + 1;
      while (end < source.length && /[A-Za-z0-9_$]/.test(source[end])) end += 1;
      tokens.push({ type: "identifier", value: source.slice(index, end) });
      index = end;
      continue;
    }
    if (char === "?" && source[index + 1] === ".") {
      tokens.push({ type: "punctuation", value: "?." });
      index += 2;
      continue;
    }
    tokens.push({ type: "punctuation", value: char });
    index += 1;
  }
  return tokens;
}

function isRegexLiteralStart(tokens) {
  const previous = tokens.at(-1);
  if (!previous) return true;
  if (previous.type === "identifier") {
    return new Set(["await", "case", "delete", "do", "else", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield"]).has(previous.value);
  }
  if (previous.value === ")" && closesControlFlowHeader(tokens)) return true;
  if (previous.value === "}" && closesStatementBlock(tokens)) return true;
  return new Set(["(", "[", "{", ",", ":", ";", "=", "!", "?", "&", "|", "+", "-", "*", "%", "^", "~", "<", ">"]).has(previous.value);
}

function closesControlFlowHeader(tokens) {
  const open = matchingOpeningToken(tokens, tokens.length - 1, "(", ")");
  return open > 0 && tokens[open - 1]?.type === "identifier" &&
    new Set(["catch", "for", "if", "switch", "while", "with"]).has(tokens[open - 1].value);
}

function closesStatementBlock(tokens) {
  const open = matchingOpeningToken(tokens, tokens.length - 1, "{", "}");
  if (open === 0) return true;
  const before = tokens[open - 1];
  if (before?.value === ")") return true;
  if (before?.value === ">" && tokens[open - 2]?.value === "=") return true;
  return before?.type === "identifier" && new Set(["do", "else", "finally", "try"]).has(before.value);
}

function matchingOpeningToken(tokens, closeIndex, openValue, closeValue) {
  let depth = 0;
  for (let index = closeIndex; index >= 0; index -= 1) {
    if (tokens[index]?.value === closeValue) depth += 1;
    else if (tokens[index]?.value === openValue && --depth === 0) return index;
  }
  return -1;
}

function skipRegexLiteral(source, start) {
  let index = start + 1;
  let inCharacterClass = false;
  while (index < source.length) {
    const char = source[index];
    if (char === "\n" || char === "\r") return -1;
    if (char === "\\") {
      index += 2;
      continue;
    }
    if (char === "[") inCharacterClass = true;
    else if (char === "]") inCharacterClass = false;
    else if (char === "/" && !inCharacterClass) {
      index += 1;
      while (index < source.length && /[A-Za-z]/.test(source[index])) index += 1;
      return index;
    }
    index += 1;
  }
  return -1;
}

function readJavaScriptString(source, start, quote) {
  let value = "";
  let index = start + 1;
  while (index < source.length) {
    const char = source[index];
    if (char === quote) return { value, end: index + 1 };
    if (char === "\\") {
      const next = source[index + 1];
      const escapes = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\v", "0": "\0" };
      value += Object.hasOwn(escapes, next) ? escapes[next] : next || "";
      index += 2;
      continue;
    }
    value += char;
    index += 1;
  }
  return { value, end: source.length };
}

function readTemplateLiteral(source, start) {
  const expressions = [];
  let value = "";
  let index = start;
  while (index < source.length) {
    if (source[index] === "\\") {
      value += source[index + 1] || "";
      index += 2;
    } else if (source[index] === "`") return { end: index + 1, expressions, value };
    else if (source[index] === "$" && source[index + 1] === "{") {
      const expressionStart = index + 2;
      let cursor = expressionStart;
      let depth = 1;
      while (cursor < source.length && depth > 0) {
        const char = source[cursor];
        if (char === "\"" || char === "'") cursor = readJavaScriptString(source, cursor, char).end;
        else if (char === "`") cursor = readTemplateLiteral(source, cursor + 1).end;
        else if (char === "/" && source[cursor + 1] === "/") {
          const end = source.indexOf("\n", cursor + 2);
          cursor = end === -1 ? source.length : end;
        } else if (char === "/" && source[cursor + 1] === "*") {
          const end = source.indexOf("*/", cursor + 2);
          cursor = end === -1 ? source.length : end + 2;
        } else {
          if (char === "{") depth += 1;
          else if (char === "}") depth -= 1;
          cursor += 1;
        }
      }
      if (depth === 0) expressions.push(source.slice(expressionStart, cursor - 1));
      index = cursor;
    } else {
      value += source[index];
      index += 1;
    }
  }
  return { end: source.length, expressions, value };
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

function validRobots(result) {
  return result.ok && /^\s*user-agent\s*:/im.test(result.text || "");
}

function validTargetDocument(home, page, html) {
  if (!home.ok || !/^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/i.test(home.contentType || "")) return false;
  const hasHtmlStructure = /<!doctype\s+html\b|<html\b|<body\b|<main\b/i.test(String(html));
  const hasMeaningfulSurface = page.hasReadableHtml || page.executableScriptCount > 0;
  return hasHtmlStructure && hasMeaningfulSurface;
}

function validSitemap(result) {
  if (!result.ok) return false;
  const text = String(result.text || "").trim();
  return /^<\?xml\b[^>]*>\s*/i.test(text) && /<(?:urlset|sitemapindex)\b/i.test(text);
}

function validLlms(result) {
  if (!result.ok) return false;
  const text = String(result.text || "").trim();
  return text.length >= 16 && /^#{1,6}\s+\S+/m.test(text);
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
  const invalidTarget = failed.has("target_reachable") || failed.has("target_document_valid");
  const ipiCheck = checks.find((item) => item.id === "ipi_risk");
  const ipiLoss = ipiCheck?.pass === false ? (ipiCheck.severity === "critical" ? 16 : 10) : 0;
  const axes = {
    safety: invalidTarget ? 0 : axis(20, failed.has("mcp_dangerous_tools") ? 12 : 0, failed.has("cookie_modal") ? 4 : 0, ipiLoss),
    efficiency: invalidTarget ? 0 : axis(20, failed.has("js_only_content") ? 12 : 0, page.dom_tokens > 5000 ? 4 : 0),
    standardization: invalidTarget ? 0 : axis(20, failed.has("llms_txt") ? 8 : 0, failed.has("mcp_spec_version") ? 4 : 0, page.hasWebMcp ? 0 : 2),
    discoverability: invalidTarget ? 0 : axis(20, failed.has("sitemap") ? 5 : 0, failed.has("json_ld") ? 5 : 0, agentSkills.discovered ? 0 : 3, failed.has("a2a_card_absent") || failed.has("a2a_card_invalid") ? 2 : 0),
    observability: null,
    policy_compliance: invalidTarget ? 0 : axis(20, failed.has("robots_txt") ? 5 : 0, failed.has("mcp_dangerous_tools") ? 10 : 0, failed.has("agent_auth_undeclared") ? 2 : 0),
  };
  return {
    total: Object.values(axes).filter(Number.isFinite).reduce((sum, value) => sum + value, 0),
    max: 100,
    axes,
    not_scored: ["observability"],
  };
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
    method: "keyword_heuristic",
    detected,
    annotated,
    unannotated,
    score,
    coverage: detected.length ? { annotated: annotated.length, unannotated: unannotated.length, total: detected.length } : null,
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

function ipiRisks(html, contentHash, redactSnippets = false) {
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
    return [{
      severity: rule.severity,
      ...(redactSnippets ? {} : { snippet }),
      content_hash: `sha256:${sha256(snippet)}`,
      page_content_hash: `sha256:${contentHash}`,
    }];
  });
}

const TAXONOMY = {
  target_reachable: "Arena::StaticPreflight::Transport",
  target_document_valid: "Arena::StaticPreflight::Document",
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
  target_reachable: "discoverability",
  target_document_valid: "discoverability",
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
  return { ok: result.ok, url: result.url, status: result.status, contentType: result.contentType, bytes: Buffer.byteLength(result.text || ""), error: result.error };
}

function redactAuthenticatedReport(value) {
  if (Array.isArray(value)) return value.map(redactAuthenticatedReport);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, redactAuthenticatedReport(child)]));
  }
  if (typeof value !== "string") return value;
  try {
    const url = new URL(value);
    if (!new Set(["http:", "https:"]).has(url.protocol)) return value;
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.href;
  } catch {
    return value;
  }
}

function decodeEntities(value) {
  return value.replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}
