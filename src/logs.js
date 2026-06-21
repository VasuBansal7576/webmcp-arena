import { nowIso } from "./util.js";

export const BOT_PATTERNS = [
  ["claudebot", /claudebot|anthropic-ai/i],
  ["gptbot", /\bgptbot\b/i],
  ["chatgpt-user", /chatgpt-user/i],
  ["oai-searchbot", /oai-searchbot/i],
  ["perplexitybot", /perplexitybot/i],
  ["google-extended", /google-extended/i],
];

export function identifyBot(userAgent = "") {
  return BOT_PATTERNS.find(([, pattern]) => pattern.test(userAgent))?.[0] || null;
}

export function parseLogLine(line) {
  if (!line || line.startsWith("#")) return null;

  const cloudfront = line.includes("\t") ? parseCloudFront(line) : null;
  if (cloudfront) return cloudfront;

  const match = line.match(/^(\S+) \S+ \S+ \[([^\]]+)] "([A-Z]+) ([^" ]+)(?: HTTP\/[\d.]+)?" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/);
  if (!match) return null;

  return {
    source: "nginx",
    ip: match[1],
    timestamp: match[2],
    method: match[3],
    path: safePath(match[4]),
    status: Number(match[5]),
    bytes: match[6] === "-" ? 0 : Number(match[6]),
    referer: match[7],
    userAgent: match[8],
  };
}

function parseCloudFront(line) {
  const parts = line.split("\t");
  if (parts.length < 11) return null;
  const [date, time, , bytes, ip, method, host, uri, status, referer, ua] = parts;
  return {
    source: "cloudfront",
    ip,
    timestamp: `${date}T${time}Z`,
    method,
    host,
    path: safePath(uri),
    status: Number(status),
    bytes: Number(bytes) || 0,
    referer,
    userAgent: decodeURIComponentSafe(ua || ""),
  };
}

function safePath(value) {
  try {
    return new URL(value, "https://example.invalid").pathname || "/";
  } catch {
    return "/";
  }
}

function decodeURIComponentSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function analyzeLogs(text, options = {}) {
  // ponytail: byte-size is the only log-safe empty-HTML proxy; use response-body samples if customers can share them.
  const emptyHtmlBytes = options.emptyHtmlBytes ?? 800;
  const parsed = text.split(/\r?\n/).map(parseLogLine).filter(Boolean);
  const agentRows = parsed.map((row) => ({ ...row, bot: identifyBot(row.userAgent) })).filter((row) => row.bot);
  const bots = {};
  const pages = {};

  for (const row of agentRows) {
    const bot = bots[row.bot] ??= freshCounter();
    const page = pages[row.path] ??= freshCounter();
    addRow(bot, row, emptyHtmlBytes);
    addRow(page, row, emptyHtmlBytes);
    page.bots[row.bot] = (page.bots[row.bot] || 0) + 1;
  }

  const pageFindings = Object.entries(pages)
    .map(([path, stats]) => ({ path, ...rates(stats) }))
    .sort((a, b) => b.agentRequests - a.agentRequests);

  const findings = pageFindings.flatMap((page) => {
    const out = [];
    if (page.emptyHtmlRate >= 0.5 && page.okResponses >= 3) {
      out.push(finding("empty_html_to_agents", "critical", `${page.path} returned tiny 2xx bodies to agents ${Math.round(page.emptyHtmlRate * 100)}% of the time.`));
    }
    if (page.authWallRate >= 0.2) {
      out.push(finding("agent_auth_wall", "high", `${page.path} returned 401/403 to agents ${Math.round(page.authWallRate * 100)}% of the time.`));
    }
    if (page.rateLimitRate >= 0.1) {
      out.push(finding("agent_rate_limited", "high", `${page.path} returned 429 to agents ${Math.round(page.rateLimitRate * 100)}% of the time.`));
    }
    return out;
  });

  return {
    generated_at: nowIso(),
    total_requests: parsed.length,
    total_agent_requests: agentRows.length,
    bots: Object.fromEntries(Object.entries(bots).map(([bot, stats]) => [bot, rates(stats)])),
    pages: pageFindings,
    findings,
  };
}

function freshCounter() {
  return {
    agentRequests: 0,
    okResponses: 0,
    emptyHtmlResponses: 0,
    authWallHits: 0,
    rateLimitHits: 0,
    errorHits: 0,
    bots: {},
    statuses: {},
  };
}

function addRow(counter, row, emptyHtmlBytes) {
  counter.agentRequests += 1;
  counter.statuses[row.status] = (counter.statuses[row.status] || 0) + 1;
  if (row.status >= 200 && row.status < 300) counter.okResponses += 1;
  if (row.status >= 200 && row.status < 300 && row.bytes > 0 && row.bytes <= emptyHtmlBytes) counter.emptyHtmlResponses += 1;
  if (row.status === 401 || row.status === 403) counter.authWallHits += 1;
  if (row.status === 429) counter.rateLimitHits += 1;
  if (row.status >= 500) counter.errorHits += 1;
}

function rates(counter) {
  return {
    ...counter,
    emptyHtmlRate: ratio(counter.emptyHtmlResponses, counter.okResponses),
    authWallRate: ratio(counter.authWallHits, counter.agentRequests),
    rateLimitRate: ratio(counter.rateLimitHits, counter.agentRequests),
    errorRate: ratio(counter.errorHits, counter.agentRequests),
  };
}

function ratio(value, total) {
  return total ? value / total : 0;
}

function finding(id, severity, message) {
  return { id, severity, message };
}
