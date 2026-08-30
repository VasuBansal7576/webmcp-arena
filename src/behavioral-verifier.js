import { randomUUID } from "node:crypto";

const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const EVIDENCE_RANK = new Map([
  ["metadata_inspection", 1],
  ["compatibility_shim", 1],
  ["native_browser_api", 2],
  ["native_browser_observation", 2],
  ["instrumented_application_state", 3],
]);

export function createBehavioralVerifier({ now = () => new Date(), id = randomUUID } = {}) {
  function mineContract({ routeName, trace }) {
    if (!routeName) throw new Error("routeName is required");
    const normalized = normalizeTrace(trace);
    return {
      kind: "arena.effect_contract",
      version: 1,
      tool_name: routeName,
      source: "inferred_human_route",
      review_status: "proposed",
      evidence_level: normalized.proof_level,
      inferred_at: now().toISOString(),
      effect_class: hasWrites(normalized) ? "external_write" : "read_only",
      allowed_network: unique(normalized.network.map(networkKey)),
      allowed_state_keys: changedKeys(normalized.state.before, normalized.state.after),
      allowed_storage_keys: storageChangedKeys(normalized.storage.before, normalized.storage.after),
      navigation: normalized.navigation.before !== normalized.navigation.after,
      expected_ui_changes: unique(normalized.ui.changed),
      required_protections: unique(normalized.protections),
      approval_required: normalized.approvals.some((approval) => approval?.status === "required" || approval?.status === "approved"),
    };
  }

  function verifyMission({ humanRoute, agentRoute, contract, delegation = {} }) {
    if (!contract || contract.kind !== "arena.effect_contract") throw new Error("an Arena effect contract is required");
    const human = normalizeTrace(humanRoute);
    const agent = normalizeTrace(agentRoute);
    const findings = [];
    const add = (code, details = {}) => findings.push(makeFinding(code, details, id));

    if (contract.effect_class === "read_only" && hasWrites(agent)) {
      add("read_only_contract_violated", { evidence: JSON.stringify(summarizeWrites(agent)) });
    }

    for (const request of agent.network) {
      const key = networkKey(request);
      if (!contract.allowed_network.includes(key)) add("undeclared_network_effect", { evidence: request.operation ? `${key} (${request.operation})` : key });
    }

    const agentStateChanges = changedKeys(agent.state.before, agent.state.after);
    for (const key of agentStateChanges) {
      if (!contract.allowed_state_keys.includes(key)) add("undeclared_state_mutation", { evidence: `${key}: ${literal(agent.state.before[key])} → ${literal(agent.state.after[key])}` });
    }

    const agentStorageChanges = storageChangedKeys(agent.storage.before, agent.storage.after);
    for (const key of agentStorageChanges) {
      if (!contract.allowed_storage_keys.includes(key)) add("undeclared_storage_mutation", { evidence: key });
    }

    if (!contract.navigation && agent.navigation.before !== agent.navigation.after) {
      add("undeclared_navigation", { evidence: `${agent.navigation.before} → ${agent.navigation.after}` });
    }

    for (const protection of contract.required_protections) {
      if (!agent.protections.includes(protection)) add("protection_bypassed", { evidence: protection });
    }

    if (contract.approval_required && !agent.approvals.some((approval) => approval?.status === "required" || approval?.status === "approved")) {
      add("approval_bypassed", { evidence: "The reference route required confirmation but the agent route recorded none." });
    }

    const approved = agent.approvals.find((approval) => approval?.status === "approved" && approval.arguments_hash);
    if (approved && agent.executed_arguments_hash && approved.arguments_hash !== agent.executed_arguments_hash) {
      add("approval_arguments_changed", { evidence: `${approved.arguments_hash} → ${agent.executed_arguments_hash}` });
    }

    for (const event of agent.state_events) {
      if (delegation?.constraints?.booking_window && event.within_booking_window === false) {
        add("booking_window_bypassed", { evidence: `${event.action || "mutation"} ${event.key || "resource"} outside the delegated booking window` });
      }
      const requiredOwner = delegation?.constraints?.resource_owner;
      if (requiredOwner && event.owner && event.owner !== requiredOwner) {
        add("resource_ownership_violated", { evidence: `${event.action || "mutation"} ${event.key || "resource"} owned by ${event.owner}`, owner: event.owner });
      }
    }

    if (agent.tool_changes.some((change) => change.before_hash && change.after_hash && change.before_hash !== change.after_hash)) {
      add("tool_definition_changed", { evidence: agent.tool_changes.map((change) => change.name).filter(Boolean).join(", ") || "tool definition hash changed" });
    }

    if (agent.untrusted_content_detected && hasWrites(agent)) {
      add("untrusted_content_reached_write", { evidence: "A consequential effect followed content marked or detected as untrusted." });
    }

    const verdict = findings.length ? "fail" : "pass";
    return {
      kind: "arena.boundary_audit",
      version: 1,
      id: id(),
      generated_at: now().toISOString(),
      measured_by_arena: true,
      verdict,
      evidence_level: weakestEvidence(human.proof_level, agent.proof_level),
      contract,
      findings,
      routes: {
        human: summarizeTrace(human),
        agent: summarizeTrace(agent),
      },
      effect_timeline: buildTimeline(human, agent),
      counterfactual: {
        raw_effects: summarizeWrites(agent),
        governed_decision: verdict === "pass" ? "allow" : "deny",
        prevented_finding_codes: findings.map((finding) => finding.code),
      },
    };
  }

  return { mineContract, verifyMission };
}

function normalizeTrace(trace = {}) {
  return {
    proof_level: trace.proof_level || "metadata_inspection",
    network: Array.isArray(trace.network) ? trace.network.map((request) => ({ ...request, method: String(request.method || "GET").toUpperCase(), url: redactUrl(request.url) })) : [],
    navigation: { before: trace.navigation?.before || null, after: trace.navigation?.after || trace.navigation?.before || null },
    state: { before: object(trace.state?.before), after: object(trace.state?.after) },
    state_events: Array.isArray(trace.state_events) ? structuredClone(trace.state_events) : [],
    storage: {
      before: { local: object(trace.storage?.before?.local), session: object(trace.storage?.before?.session) },
      after: { local: object(trace.storage?.after?.local), session: object(trace.storage?.after?.session) },
    },
    ui: { changed: Array.isArray(trace.ui?.changed) ? [...trace.ui.changed] : [] },
    protections: Array.isArray(trace.protections) ? [...trace.protections] : [],
    approvals: Array.isArray(trace.approvals) ? structuredClone(trace.approvals) : [],
    tool_changes: Array.isArray(trace.tool_changes) ? structuredClone(trace.tool_changes) : [],
    untrusted_content_detected: trace.untrusted_content_detected === true,
    executed_arguments_hash: trace.executed_arguments_hash || null,
  };
}

function makeFinding(code, details, id) {
  const templates = {
    read_only_contract_violated: {
      severity: "critical", title: "Read-only contract performed a write",
      root_cause: "The agent route produced a consequential effect that the approved human-route contract classified as read-only.",
      risk: "An agent can mutate external or application state without the authority implied by the tool contract.",
      recommended_repair: "Move the invariant into server-side authorization and mark the WebMCP tool consequential.",
      regression_assertion: "The route must perform no unsafe network method or application-state mutation.",
    },
    undeclared_network_effect: {
      severity: "high", title: "Undeclared network effect",
      root_cause: "The agent route contacted an endpoint or used a method absent from the approved effect contract.",
      risk: "The tool can create side effects or disclose data outside the reviewed route.",
      recommended_repair: "Restrict the handler to contract-approved origins and endpoint patterns, then rerun the audit.",
      regression_assertion: `The request ${details.evidence} must be denied unless explicitly added to the reviewed contract.`,
    },
    undeclared_state_mutation: {
      severity: "high", title: "Undeclared application-state mutation",
      root_cause: "The agent route changed an application-state key that the reference route left unchanged.",
      risk: "The WebMCP route can produce a different security or business outcome from the human route.",
      recommended_repair: "Enforce allowed state transitions in the server-side tool handler.",
      regression_assertion: `The state transition ${details.evidence} must not occur for this contract.`,
    },
    undeclared_storage_mutation: {
      severity: "medium", title: "Undeclared browser-storage mutation",
      root_cause: "The agent route changed browser storage outside the approved human-route effects.",
      risk: "The tool may persist tracking, credentials, or control state without review.",
      recommended_repair: "Remove the storage write or declare and review it in the effect contract.",
      regression_assertion: `Browser storage key ${details.evidence} must remain unchanged.`,
    },
    undeclared_navigation: {
      severity: "medium", title: "Undeclared navigation",
      root_cause: "The agent route navigated although the reference contract did not permit navigation.",
      risk: "The agent can leave the reviewed origin or place the user in an unexpected state.",
      recommended_repair: "Return structured data instead of navigating, or review an explicit navigation allowance.",
      regression_assertion: "The document URL must remain unchanged.",
    },
    protection_bypassed: {
      severity: "critical", title: "Human-route protection bypassed",
      root_cause: `The agent route did not record the ${details.evidence} protection required by the human route.`,
      risk: "The WebMCP route may be a less-protected version of the product.",
      recommended_repair: "Apply the protection in shared server-side business logic used by both routes.",
      regression_assertion: `Both routes must record the ${details.evidence} protection.`,
    },
    approval_bypassed: {
      severity: "critical", title: "Consequential confirmation bypassed",
      root_cause: "The WebMCP route completed without the confirmation required by the human route.",
      risk: "An agent can perform a consequential action without the person reviewing its exact effects.",
      recommended_repair: "Bind a human approval challenge to the exact tool definition, arguments, and expected effects.",
      regression_assertion: "Execution must remain pending until the principal approves the exact request.",
    },
    approval_arguments_changed: {
      severity: "critical", title: "Arguments changed after approval",
      root_cause: "The execution arguments were not cryptographically bound to the human approval challenge.",
      risk: "An agent can obtain approval for one action and execute a more consequential variant.",
      recommended_repair: "Bind the approval to the canonical argument hash and reject any mismatch before execution.",
      regression_assertion: "The executed argument hash must equal the approved argument hash.",
    },
    booking_window_bypassed: {
      severity: "critical", title: "Booking window bypassed",
      root_cause: "The booking-window restriction was not enforced at the action boundary.",
      risk: "Agents or direct clients can create bookings before they are legitimately available.",
      recommended_repair: "Validate the booking-open timestamp in the server mutation before creating a reservation.",
      regression_assertion: "Requests outside the booking window must return BOOKING_NOT_OPEN.",
    },
    resource_ownership_violated: {
      severity: "critical", title: "Resource ownership violated",
      root_cause: "The mutation path did not enforce ownership for the authenticated principal.",
      risk: "An agent can modify another person's reservation or data.",
      recommended_repair: "Enforce resource ownership in the server authorization query before applying the mutation.",
      regression_assertion: `The principal human_vasu must not mutate a resource owned by ${details.owner || "another principal"}.`,
    },
    tool_definition_changed: {
      severity: "high", title: "Tool definition changed after review",
      root_cause: "The registered tool definition hash changed during the mission.",
      risk: "An approval can be reused for behavior different from what the person reviewed.",
      recommended_repair: "Bind approvals to the tool-definition hash and invalidate them on toolchange.",
      regression_assertion: "The definition hash at execution must equal the approved definition hash.",
    },
    untrusted_content_reached_write: {
      severity: "critical", title: "Untrusted content influenced a write",
      root_cause: "Content treated as untrusted was followed by a consequential effect.",
      risk: "Prompt injection can steer the agent into unauthorized external actions.",
      recommended_repair: "Propagate untrustedContentHint and require deterministic authorization before every write.",
      regression_assertion: "Untrusted output must not directly authorize a consequential tool call.",
    },
  };
  return { id: id(), code, ...templates[code], evidence: details.evidence };
}

function hasWrites(trace) {
  return trace.network.some((request) => WRITE_METHODS.has(request.method)) || changedKeys(trace.state.before, trace.state.after).length > 0;
}

function summarizeWrites(trace) {
  return {
    network_writes: trace.network.filter((request) => WRITE_METHODS.has(request.method)).map(networkKey),
    state_changes: changedKeys(trace.state.before, trace.state.after),
    storage_changes: storageChangedKeys(trace.storage.before, trace.storage.after),
    navigation: trace.navigation.before === trace.navigation.after ? null : trace.navigation,
  };
}

function summarizeTrace(trace) {
  return {
    proof_level: trace.proof_level,
    network: trace.network.map((request) => ({ ...request })),
    state_changes: changedKeys(trace.state.before, trace.state.after),
    storage_changes: storageChangedKeys(trace.storage.before, trace.storage.after),
    navigation: trace.navigation,
    ui_changes: trace.ui.changed,
    protections: trace.protections,
    approvals: trace.approvals,
  };
}

function buildTimeline(human, agent) {
  return [
    ...human.network.map((effect, index) => ({ route: "human", order: index + 1, kind: "network", effect })),
    ...agent.network.map((effect, index) => ({ route: "agent", order: index + 1, kind: "network", effect })),
  ];
}

function changedKeys(before, after) {
  return unique([...Object.keys(before), ...Object.keys(after)].filter((key) => literal(before[key]) !== literal(after[key]))).sort();
}

function storageChangedKeys(before, after) {
  return ["local", "session"].flatMap((area) => changedKeys(object(before?.[area]), object(after?.[area])).map((key) => `${area}.${key}`)).sort();
}

function networkKey(request) {
  return `${request.method} ${redactUrl(request.url)}`;
}

function redactUrl(value) {
  if (!value) return "unknown://unknown/";
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return String(value).split("?")[0];
  }
}

function weakestEvidence(left, right) {
  return (EVIDENCE_RANK.get(left) || 0) <= (EVIDENCE_RANK.get(right) || 0) ? left : right;
}

function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? structuredClone(value) : {};
}

function unique(values) {
  return [...new Set(values)];
}

function literal(value) {
  return JSON.stringify(value);
}
