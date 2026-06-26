import { nowIso, sha256 } from "./util.js";

const WEIGHT = { critical: 5, high: 3, medium: 2, low: 1, info: 1 };

export function emptyRegistry() {
  return {
    version: "1.0.0",
    layer: "agent_session_membrane.layer2",
    generated_at: nowIso(),
    sessions: {},
    agents: {},
  };
}

export function ingestBehavioralEvents(registry, input, declarations = {}) {
  const next = normalizeRegistry(registry);
  for (const event of normalizeEvents(input, declarations)) {
    const session = next.sessions[event.session_id] || {
      session_id: event.session_id,
      site_id: event.site_id,
      agent_id: event.agent_id,
      started_at: event.timestamp,
      events: [],
    };
    session.events.push(event);
    session.ended_at = event.timestamp;
    next.sessions[event.session_id] = session;
  }
  next.generated_at = nowIso();
  next.agents = scoreAgents(next);
  return next;
}

export function registrySummary(registry, agentId) {
  const current = normalizeRegistry(registry);
  if (agentId) return current.agents[agentId] || { agent_id: agentId, conformance_score: null, total_actions: 0 };
  return {
    generated_at: nowIso(),
    agents: Object.values(current.agents).sort((a, b) => String(a.agent_id).localeCompare(String(b.agent_id))),
  };
}

function normalizeRegistry(registry) {
  return { ...emptyRegistry(), ...(registry || {}), sessions: registry?.sessions || {}, agents: registry?.agents || {} };
}

function normalizeEvents(input, declarations) {
  const events = Array.isArray(input) ? input : input?.events || input?.records || [];
  return events.map((event) => normalizeEvent(event, declarations));
}

function normalizeEvent(event, declarations) {
  const agentId = String(event.agent_id || event.agent || event.user_agent || "unknown_agent");
  const siteId = String(event.site_id || event.site || host(event.url) || "unknown_site");
  const timestamp = event.timestamp || event.observed_at || nowIso();
  const actionType = String(event.action_type || event.type || "request");
  const sessionId = String(event.session_id || sha256(`${siteId}\n${agentId}\n${event.url || ""}\n${timestamp}`).slice(0, 16));
  const conformance = conformanceFor(event, declarationFor(declarations, agentId), actionType);
  return {
    id: event.id || sha256(JSON.stringify({ event, sessionId })).slice(0, 16),
    session_id: sessionId,
    site_id: siteId,
    agent_id: agentId,
    url: event.url || "",
    site_type: event.site_type || event.segment || "global",
    action_type: actionType,
    action: event.action || event.region || actionType,
    severity: event.severity || "info",
    timestamp,
    conformance,
  };
}

function conformanceFor(event, declaration, actionType) {
  if (String(event.type || "").startsWith("runtime_")) {
    return { status: "unknown", weight: 0, reason: "runtime_deviation_is_not_agent_intent" };
  }
  if (event.conforms === false || event.allowed === false || event.policy_violation) return failed(event, "observed_policy_violation");
  if (declaration?.forbidden_paths?.some((path) => event.url && new URL(event.url).pathname.startsWith(path))) return failed(event, "forbidden_path");
  if (declaration?.allowed_actions?.length && !declaration.allowed_actions.includes(actionType)) return failed(event, "undeclared_action");
  return { status: "passed", weight: weight(event), reason: "matched_declaration" };
}

function failed(event, reason) {
  return { status: "failed", weight: weight(event), reason };
}

function weight(event) {
  return WEIGHT[event.severity] || 1;
}

function declarationFor(declarations, agentId) {
  return declarations?.agents?.[agentId] || declarations?.[agentId] || declarations || {};
}

function scoreAgents(registry) {
  const totals = {};
  for (const session of Object.values(registry.sessions)) {
    for (const event of session.events) {
      const bucket = totals[event.agent_id] || { agent_id: event.agent_id, conforming_weight: 0, total_weight: 0, conforming_actions: 0, total_actions: 0, unknown_actions: 0 };
      if (event.conformance.status === "unknown") bucket.unknown_actions += 1;
      else {
        bucket.total_weight += event.conformance.weight;
        bucket.total_actions += 1;
        if (event.conformance.status === "passed") {
          bucket.conforming_weight += event.conformance.weight;
          bucket.conforming_actions += 1;
        }
      }
      totals[event.agent_id] = bucket;
    }
  }
  return Object.fromEntries(Object.entries(totals).map(([agentId, item]) => [agentId, {
    ...item,
    conformance_score: item.total_weight ? round(item.conforming_weight / item.total_weight) : null,
  }]));
}

function host(value) {
  try {
    return new URL(value).host;
  } catch {
    return "";
  }
}

function round(value) {
  return Math.round(value * 1000) / 1000;
}
