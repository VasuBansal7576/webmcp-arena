export function buildDriftScore(registry, { agentId, siteType = "global", threshold = 0.8, blockThreshold = 0.5 } = {}) {
  if (!agentId) throw new Error("drift score requires agentId");
  const agent = registry.agents?.[agentId] || null;
  const segment = scoreSegment(registry, agentId, siteType);
  const score = siteType === "global" ? agent?.conformance_score ?? null : segment.conformance_score;
  return {
    version: "1.0.0",
    layer: "agent_session_membrane.layer3",
    agent_id: agentId,
    site_type: siteType,
    conformance_score: score,
    drift_score: score === null ? null : round(1 - score),
    threshold,
    block_threshold: blockThreshold,
    decision: decision(score, threshold, blockThreshold),
    sample: siteType === "global" ? agent?.total_actions || 0 : segment.total_actions,
    interpretation_boundary: "Probabilistic behavioral aggregate from local ABR input, not proof of future behavior.",
  };
}

export function wafRule({ provider = "nginx", endpoint, threshold = 0.8, blockThreshold = 0.5 } = {}) {
  if (!endpoint) throw new Error("waf rule requires endpoint");
  if (provider === "cloudflare") return cloudflareRule(endpoint, threshold, blockThreshold);
  if (provider === "fastly") return fastlyRule(endpoint, threshold, blockThreshold);
  return nginxRule(endpoint, threshold, blockThreshold);
}

function decision(score, threshold, blockThreshold) {
  if (score === null || score === undefined) return "monitor";
  if (score < blockThreshold) return "block";
  if (score < threshold) return "rate_limit";
  return "allow";
}

function scoreSegment(registry, agentId, siteType) {
  const events = Object.values(registry.sessions || {})
    .flatMap((session) => session.events || [])
    .filter((event) => event.agent_id === agentId && (siteType === "global" || event.site_type === siteType) && event.conformance?.status !== "unknown");
  const totalWeight = events.reduce((sum, event) => sum + (event.conformance?.weight || 0), 0);
  const conformingWeight = events.filter((event) => event.conformance?.status === "passed").reduce((sum, event) => sum + (event.conformance?.weight || 0), 0);
  return {
    total_actions: events.length,
    conformance_score: totalWeight ? round(conformingWeight / totalWeight) : null,
  };
}

function nginxRule(endpoint, threshold, blockThreshold) {
  return `# Agent Contract drift-score check
# Endpoint should return 204 allow, 429 rate_limit, or 403 block.
# threshold=${threshold} block_threshold=${blockThreshold}
location / {
  auth_request /_agent_contract_drift;
}

location = /_agent_contract_drift {
  internal;
  proxy_pass ${endpoint};
  proxy_set_header X-Agent-User-Agent $http_user_agent;
  proxy_set_header X-Agent-Path $request_uri;
}
`;
}

function cloudflareRule(endpoint, threshold, blockThreshold) {
  return `export default {
  async fetch(request) {
    const score = await fetch(${JSON.stringify(endpoint)}, {
      headers: {
        "x-agent-user-agent": request.headers.get("user-agent") || "",
        "x-agent-path": new URL(request.url).pathname,
        "x-agent-threshold": ${JSON.stringify(String(threshold))},
        "x-agent-block-threshold": ${JSON.stringify(String(blockThreshold))}
      }
    }).then((res) => res.json());
    if (score.decision === "block") return new Response("blocked", { status: 403 });
    if (score.decision === "rate_limit") return new Response("rate limited", { status: 429 });
    return fetch(request);
  }
};`;
}

function fastlyRule(endpoint, threshold, blockThreshold) {
  return `# Agent Contract drift-score check
# endpoint=${endpoint} threshold=${threshold} block_threshold=${blockThreshold}
# Wire this endpoint as a backend named agent_contract_drift.
if (req.http.User-Agent) {
  set req.http.X-Agent-User-Agent = req.http.User-Agent;
  set req.http.X-Agent-Path = req.url;
}
`;
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}
