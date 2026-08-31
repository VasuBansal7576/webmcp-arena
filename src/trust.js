import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

import { openSecret, sealSecret } from "./secret-envelope.js";

export function createTrustGateway({ secret, tools = [], requireVerifiedAgents = false, stateStore = null, proof = null, now = () => new Date(), monotonic = () => performance.now(), id = randomUUID } = {}) {
  if (!secret || String(secret).length < 16) throw new Error("trust gateway requires a signing secret of at least 16 characters");
  const catalog = new Map(tools.map((tool) => [tool.name, tool]));
  const storedState = stateStore?.load?.();
  const restored = normalizeState(storedState, secret);
  const approvals = new Map(Object.entries(restored.approvals));
  const idempotency = new Map(Object.entries(restored.idempotency));
  const revoked = new Map(Object.entries(restored.revoked));
  const budgets = new Map(Object.entries(restored.budgets));
  const approvalBindings = new Map();
  const inFlight = new Map();
  const timeline = restored.timeline;
  const receipts = restored.receipts;
  let stateUnavailable = restored.unavailable === true;

  function issuePassport(input) {
    return withStateLock(() => {
      refreshState();
      return issuePassportUnlocked(input);
    });
  }

  function issuePassportUnlocked({ principalId, agentId, agentIdentity = null, scopes = [], ttlSeconds = 900, maxAmount = null }) {
    if (stateUnavailable) throw new Error("trust state integrity verification failed");
    if (!principalId) throw new Error("principalId is required");
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) throw new Error("ttlSeconds must be a finite positive number");
    if (maxAmount !== null && (!Number.isFinite(maxAmount) || maxAmount < 0)) throw new Error("maxAmount must be a finite non-negative number or null");
    if (requireVerifiedAgents && agentIdentity?.verified !== true) throw new Error("verified agent identity is required");
    if (agentIdentity?.verified && agentId && agentId !== agentIdentity.agent_id) throw new Error("declared agentId does not match the verified identity");
    const effectiveAgentId = agentIdentity?.verified ? agentIdentity.agent_id : agentId;
    if (!effectiveAgentId) throw new Error("agentId is required");
    const issuedAt = now().toISOString();
    const payload = {
      kind: "arena.delegation",
      version: 1,
      id: id(),
      principal_id: principalId,
      agent_id: effectiveAgentId,
      agent_identity: agentIdentity?.verified ? {
        verified: true,
        issuer: agentIdentity.issuer,
        subject: agentIdentity.subject,
        token_id: agentIdentity.token_id,
        algorithm: agentIdentity.algorithm,
      } : { verified: false, issuer: "arena-local", subject: effectiveAgentId, token_id: null, algorithm: "HS256" },
      scopes: [...new Set(scopes)],
      max_amount: maxAmount,
      issued_at: issuedAt,
      expires_at: new Date(Date.parse(issuedAt) + ttlSeconds * 1000).toISOString(),
    };
    const passport = { token: signToken(payload, secret), delegation: payload };
    record("passport_issued", { delegation_id: payload.id, principal_id: principalId, agent_id: effectiveAgentId, identity_verified: payload.agent_identity.verified, identity_issuer: payload.agent_identity.issuer, scopes: payload.scopes });
    persist();
    return passport;
  }

  function requestToolExecution(input) {
    return withStateLock(() => {
      refreshState();
      if (sweepExpiredApprovals()) persist();
      return requestToolExecutionUnlocked(input);
    });
  }

  async function requestToolExecutionUnlocked({ passport, agentId, toolName, arguments: args = {}, idempotencyKey }) {
    if (stateUnavailable) return { status: "denied", reason: "trust_state_integrity_failure" };
    const delegation = verifyToken(passport, secret);
    if (!delegation || delegation.kind !== "arena.delegation") return reject("invalid_passport", { agent_id: agentId, tool_name: toolName });
    if (revoked.has(delegation.id)) return reject("delegation_revoked", { delegation_id: delegation.id, agent_id: agentId, tool_name: toolName });
    if (Date.parse(delegation.expires_at) <= now().getTime()) return reject("expired_passport", { agent_id: agentId, tool_name: toolName });
    if (delegation.agent_id !== agentId) return reject("agent_identity_mismatch", { agent_id: agentId, tool_name: toolName });
    const tool = catalog.get(toolName);
    if (!tool) return reject("unknown_tool", { agent_id: agentId, tool_name: toolName });
    if (!delegation.scopes.includes(tool.scope)) return reject("scope_not_delegated", { agent_id: agentId, tool_name: toolName });
    const toolBinding = captureToolBinding(tool, secret);
    let capturedArguments;
    try {
      capturedArguments = structuredClone(args || {});
    } catch {
      return reject("invalid_arguments", { agent_id: agentId, tool_name: toolName, validation_error: "arguments must be structured-cloneable" });
    }
    const idempotencyRecordKey = idempotencyKey ? `${delegation.id}:${idempotencyKey}` : null;
    const requestHash = signature(stableJson({ toolName, arguments: capturedArguments }), secret);
    const active = idempotencyRecordKey ? inFlight.get(idempotencyRecordKey) : null;
    if (active && active.requestHash !== requestHash) return reject("idempotency_conflict", { agent_id: agentId, tool_name: toolName });
    if (active) return structuredClone(await active.promise);
    const existing = idempotencyRecordKey ? idempotency.get(idempotencyRecordKey) : null;
    if (existing && existing.requestHash !== requestHash) return reject("idempotency_conflict", { agent_id: agentId, tool_name: toolName });
    if (existing) return structuredClone(existing.response);
    const validationError = toolBinding.validate ? toolBinding.validate(capturedArguments) : null;
    if (validationError) return reject("invalid_arguments", { agent_id: agentId, tool_name: toolName, validation_failed: true });
    const amount = toolBinding.amount ? Number(toolBinding.amount(capturedArguments)) : null;
    const reservationId = idempotencyRecordKey || `execution:${id()}`;
    const budgetDecision = reserveBudget(delegation, reservationId, amount);
    if (!budgetDecision.allowed) return reject(budgetDecision.reason, { agent_id: agentId, tool_name: toolName, amount, max_amount: delegation.max_amount });
    if (tool.requiresApproval) {
      const approval = {
        id: id(),
        status: "pending",
        principal_id: delegation.principal_id,
        agent_id: agentId,
        tool_name: toolName,
        arguments: capturedArguments,
        delegation,
        idempotency_key: idempotencyKey || null,
        idempotency_record_key: idempotencyRecordKey,
        budget_reservation_id: reservationId,
        request_hash: requestHash,
        tool_context_id: toolBinding.contextId,
        tool_context_hash: toolBinding.contextHash,
        requested_at: now().toISOString(),
      };
      approvals.set(approval.id, approval);
      approvalBindings.set(approval.id, toolBinding);
      const response = { status: "approval_required", approval: publicApproval(approval) };
      rememberIdempotency(idempotencyRecordKey, requestHash, response);
      record("approval_required", { approval_id: approval.id, agent_id: agentId, tool_name: toolName, arguments: structuredClone(capturedArguments) });
      persist();
      return response;
    }
    commitBudget(delegation.id, reservationId);
    rememberIdempotency(idempotencyRecordKey, requestHash, { status: "execution_in_progress" });
    persist();
    const execution = Promise.resolve().then(async () => {
      const started = monotonic();
      const result = await toolBinding.execute(structuredClone(capturedArguments));
      const durationMs = duration(started, monotonic());
      return withStateLock(() => {
        refreshState();
        const response = executed({ delegation, agentId, toolName, args: capturedArguments, idempotencyKey, result, durationMs });
        rememberIdempotency(idempotencyRecordKey, requestHash, response);
        record("executed", { receipt_id: response.receipt.id, agent_id: agentId, tool_name: toolName, arguments: structuredClone(capturedArguments), duration_ms: durationMs });
        persist();
        return response;
      });
    });
    if (idempotencyRecordKey) inFlight.set(idempotencyRecordKey, { requestHash, promise: execution });
    try {
      return structuredClone(await execution);
    } catch (error) {
      withStateLock(() => {
        refreshState();
        rememberIdempotency(idempotencyRecordKey, requestHash, { status: "denied", reason: "execution_outcome_unknown" });
        record("execution_outcome_unknown", { agent_id: agentId, tool_name: toolName, failure_class: "tool_execution_failed" });
        persist();
      });
      throw error;
    } finally {
      if (idempotencyRecordKey) inFlight.delete(idempotencyRecordKey);
    }
  }

  function resolveApproval(input) {
    return withStateLock(() => {
      refreshState();
      return resolveApprovalUnlocked(input);
    });
  }

  async function resolveApprovalUnlocked({ approvalId, principalId, decision }) {
    if (stateUnavailable) return { status: "denied", reason: "trust_state_integrity_failure" };
    const approval = approvals.get(approvalId);
    if (!approval) return reject("approval_not_found", { approval_id: approvalId, principal_id: principalId });
    if (approval.status !== "pending") return reject("approval_already_resolved", { approval_id: approvalId, principal_id: principalId });
    if (approval.principal_id !== principalId) return reject("principal_identity_mismatch", { approval_id: approvalId, principal_id: principalId });
    if (Date.parse(approval.delegation.expires_at) <= now().getTime()) {
      approval.status = "denied";
      approval.resolved_at = now().toISOString();
      releaseBudget(approval.delegation.id, approval.budget_reservation_id);
      approvalBindings.delete(approval.id);
      const response = reject("expired_passport", { approval_id: approvalId, principal_id: principalId, tool_name: approval.tool_name });
      rememberIdempotency(approval.idempotency_record_key, approval.request_hash, response);
      persist();
      return response;
    }
    if (revoked.has(approval.delegation.id)) {
      approval.status = "denied";
      approval.resolved_at = now().toISOString();
      releaseBudget(approval.delegation.id, approval.budget_reservation_id);
      approvalBindings.delete(approval.id);
      const response = reject("delegation_revoked", { approval_id: approvalId, principal_id: principalId, tool_name: approval.tool_name });
      rememberIdempotency(approval.idempotency_record_key, approval.request_hash, response);
      persist();
      return response;
    }
    if (decision !== "approved") {
      approval.status = "denied";
      approval.resolved_at = now().toISOString();
      record("denied", { approval_id: approval.id, principal_id: principalId, tool_name: approval.tool_name });
      releaseBudget(approval.delegation.id, approval.budget_reservation_id);
      approvalBindings.delete(approval.id);
      const response = { status: "denied", reason: "human_denied", approval: publicApproval(approval) };
      rememberIdempotency(approval.idempotency_record_key, approval.request_hash, response);
      persist();
      return response;
    }
    const toolBinding = approvalBindings.get(approval.id);
    if (!toolBinding || toolBinding.contextHash !== approval.tool_context_hash) {
      approval.status = "denied";
      approval.resolved_at = now().toISOString();
      releaseBudget(approval.delegation.id, approval.budget_reservation_id);
      approvalBindings.delete(approval.id);
      const response = reject("approval_context_unavailable", { approval_id: approvalId, principal_id: principalId, tool_name: approval.tool_name });
      rememberIdempotency(approval.idempotency_record_key, approval.request_hash, response);
      persist();
      return response;
    }
    approval.status = "approved";
    approval.resolved_at = now().toISOString();
    record("approved", { approval_id: approval.id, principal_id: principalId, tool_name: approval.tool_name });
    commitBudget(approval.delegation.id, approval.budget_reservation_id);
    approvalBindings.delete(approval.id);
    persist();
    const started = monotonic();
    let result;
    try {
      result = await Promise.resolve().then(() => toolBinding.execute(structuredClone(approval.arguments)));
    } catch (error) {
      withStateLock(() => {
        refreshState();
        rememberIdempotency(approval.idempotency_record_key, approval.request_hash, { status: "denied", reason: "execution_outcome_unknown" });
        record("execution_outcome_unknown", { approval_id: approval.id, agent_id: approval.agent_id, tool_name: approval.tool_name, failure_class: "tool_execution_failed" });
        persist();
      });
      throw error;
    }
    const durationMs = duration(started, monotonic());
    return withStateLock(() => {
      refreshState();
      const response = executed({
        delegation: approval.delegation,
        agentId: approval.agent_id,
        toolName: approval.tool_name,
        args: approval.arguments,
        idempotencyKey: approval.idempotency_key,
        result,
        approvalId: approval.id,
        durationMs,
      });
      const currentApproval = approvals.get(approval.id);
      if (currentApproval) currentApproval.receipt = response.receipt;
      rememberIdempotency(approval.idempotency_record_key, approval.request_hash, response);
      record("executed", { receipt_id: response.receipt.id, approval_id: approval.id, agent_id: approval.agent_id, tool_name: approval.tool_name, arguments: structuredClone(approval.arguments), duration_ms: durationMs });
      persist();
      return response;
    });
  }

  function executed({ delegation, agentId, toolName, args, idempotencyKey, result, approvalId = null, durationMs = 0 }) {
    const receiptPayload = {
      kind: "arena.execution_receipt",
      version: 1,
      id: id(),
      delegation_id: delegation.id,
      principal_id: delegation.principal_id,
      agent_id: agentId,
      tool_name: toolName,
      idempotency_key: idempotencyKey || null,
      approval_id: approvalId,
      status: "executed",
      executed_at: now().toISOString(),
      duration_ms: durationMs,
      arguments: redactSensitive(args),
      result: redactSensitive(result),
      arguments_commitment: signature(stableJson(args), secret),
      result_commitment: signature(stableJson(result), secret),
    };
    const receipt = proof ? proof.issue(receiptPayload) : signReceipt(receiptPayload, secret);
    receipts.push(structuredClone(receipt));
    return { status: "executed", result: structuredClone(result), receipt: structuredClone(receipt) };
  }

  function record(status, details) {
    timeline.push({ id: id(), status, at: now().toISOString(), ...redactSensitive(details) });
  }

  function revokePassport(input) {
    return withStateLock(() => {
      refreshState();
      return revokePassportUnlocked(input);
    });
  }

  function revokePassportUnlocked({ passport, principalId, reason = "user_revoked" }) {
    if (stateUnavailable) return { status: "denied", reason: "trust_state_integrity_failure" };
    const delegation = verifyToken(passport, secret);
    if (!delegation || delegation.kind !== "arena.delegation") return reject("invalid_passport", { principal_id: principalId });
    if (delegation.principal_id !== principalId) return reject("principal_identity_mismatch", { delegation_id: delegation.id, principal_id: principalId });
    if (revoked.has(delegation.id)) return { status: "revoked", revocation: structuredClone(revoked.get(delegation.id)) };
    const revocation = { delegation_id: delegation.id, principal_id: principalId, reason, revoked_at: now().toISOString() };
    revoked.set(delegation.id, revocation);
    for (const approval of approvals.values()) {
      if (approval.delegation.id === delegation.id && approval.status === "pending") {
        approval.status = "denied";
        approval.resolved_at = revocation.revoked_at;
        releaseBudget(approval.delegation.id, approval.budget_reservation_id);
        approvalBindings.delete(approval.id);
        if (approval.idempotency_record_key) {
          rememberIdempotency(approval.idempotency_record_key, approval.request_hash, { status: "denied", reason: "delegation_revoked" });
        }
      }
    }
    record("delegation_revoked", revocation);
    persist();
    return { status: "revoked", revocation };
  }

  function reject(reason, details = {}) {
    record("denied", { reason, ...details });
    persist();
    return { status: "denied", reason };
  }

  function withStateLock(callback) {
    return stateStore?.withLock ? stateStore.withLock(callback) : callback();
  }

  function refreshState() {
    if (!stateStore?.load) return;
    const latest = normalizeState(stateStore.load(), secret);
    stateUnavailable = latest.unavailable === true;
    replaceMap(approvals, latest.approvals);
    replaceMap(idempotency, latest.idempotency);
    replaceMap(revoked, latest.revoked);
    replaceMap(budgets, latest.budgets);
    timeline.splice(0, timeline.length, ...latest.timeline);
    receipts.splice(0, receipts.length, ...latest.receipts);
    for (const [approvalId, binding] of approvalBindings) {
      const approval = approvals.get(approvalId);
      if (!approval || approval.status !== "pending" || approval.tool_context_hash !== binding.contextHash) approvalBindings.delete(approvalId);
    }
  }

  function sweepExpiredApprovals() {
    let changed = false;
    for (const approval of approvals.values()) {
      if (approval.status !== "pending" || Date.parse(approval.delegation?.expires_at) > now().getTime()) continue;
      approval.status = "denied";
      approval.denial_reason = "expired_passport";
      approval.resolved_at = now().toISOString();
      releaseBudget(approval.delegation.id, approval.budget_reservation_id);
      approvalBindings.delete(approval.id);
      rememberIdempotency(approval.idempotency_record_key, approval.request_hash, { status: "denied", reason: "expired_passport" });
      record("approval_expired", { approval_id: approval.id, agent_id: approval.agent_id, tool_name: approval.tool_name });
      changed = true;
    }
    return changed;
  }

  function persist() {
    if (stateUnavailable) throw new Error("refusing to overwrite trust state after an integrity failure");
    const payload = {
      version: 4,
      approvals: Object.fromEntries([...approvals].map(([key, approval]) => [key, sealApproval(approval, secret)])),
      idempotency: Object.fromEntries([...idempotency].map(([key, record]) => [key, sealIdempotency(record, secret)])),
      revoked: Object.fromEntries(revoked),
      budgets: Object.fromEntries(budgets),
      timeline,
      receipts,
    };
    stateStore?.save?.({ ...payload, integrity: signature(stableJson(payload), secret) });
  }

  function rememberIdempotency(key, requestHash, response) {
    if (!key) return;
    idempotency.set(key, { requestHash, response: structuredClone(response) });
  }

  function reserveBudget(delegation, reservationId, amount) {
    if (amount === null || delegation.max_amount === null) return { allowed: true };
    if (!Number.isFinite(amount) || amount < 0) return { allowed: false, reason: "invalid_arguments" };
    const budget = budgets.get(delegation.id) || { committed: 0, reservations: {} };
    if (budget.unavailable === true) return { allowed: false, reason: "delegation_budget_state_unavailable" };
    const reserved = Object.values(budget.reservations).reduce((total, value) => total + Number(value || 0), 0);
    if (budget.committed + reserved + amount > Number(delegation.max_amount)) return { allowed: false, reason: "amount_exceeds_delegation" };
    budget.reservations[reservationId] = amount;
    budgets.set(delegation.id, budget);
    return { allowed: true };
  }

  function commitBudget(delegationId, reservationId) {
    const budget = budgets.get(delegationId);
    if (!budget || !(reservationId in budget.reservations)) return;
    budget.committed += Number(budget.reservations[reservationId]);
    delete budget.reservations[reservationId];
  }

  function releaseBudget(delegationId, reservationId) {
    const budget = budgets.get(delegationId);
    if (!budget || !reservationId) return;
    delete budget.reservations[reservationId];
  }

  if (storedState && storedState.version !== 4) {
    withStateLock(() => {
      refreshState();
      persist();
    });
  }

  return {
    issuePassport,
    requestToolExecution,
    resolveApproval,
    submit: requestToolExecution,
    resolve: resolveApproval,
    revoke: revokePassport,
    getSnapshot: () => withStateLock(() => {
      refreshState();
      if (!stateUnavailable && sweepExpiredApprovals()) persist();
      return {
        integrity_status: stateUnavailable ? "failed" : "verified",
        timeline: structuredClone(timeline),
        approvals: [...approvals.values()].map(publicApproval),
        receipts: structuredClone(receipts),
        revocations: [...revoked.values()].map((value) => structuredClone(value)),
      };
    }),
    getTools: () => [...catalog.values()].map(({
      execute: _execute,
      amount: _amount,
      validate: _validate,
      ...tool
    }) => ({ ...tool })),
    verifyReceipt: (receipt) => proof ? proof.verify(receipt) : Boolean(verifyReceipt(receipt, secret)),
  };
}

function replaceMap(target, entries) {
  target.clear();
  for (const [key, value] of Object.entries(entries)) target.set(key, value);
}

function publicApproval(approval) {
  const {
    delegation: _delegation,
    idempotency_record_key: _idempotencyRecordKey,
    budget_reservation_id: _budgetReservationId,
    request_hash: _requestHash,
    tool_context_id: _toolContextId,
    tool_context_hash: _toolContextHash,
    ...safe
  } = approval;
  return redactSensitive(safe);
}

function captureToolBinding(tool, secret) {
  const context = {};
  for (const [key, value] of Object.entries(tool)) {
    context[key] = typeof value === "function" ? value : structuredClone(value);
  }
  const definition = {};
  for (const [key, value] of Object.entries(context)) {
    if (typeof value !== "function") definition[key] = value;
  }
  const callable = (name) => typeof context[name] === "function" ? context[name].bind(context) : null;
  return {
    execute: callable("execute"),
    amount: callable("amount"),
    validate: callable("validate"),
    contextId: typeof context.approvalContextId === "string" && context.approvalContextId.trim() ? context.approvalContextId : null,
    contextHash: signature(stableJson({
      definition,
      execute: functionSource(context.execute),
      amount: functionSource(context.amount),
      validate: functionSource(context.validate),
    }), secret),
  };
}

function functionSource(value) {
  return typeof value === "function" ? Function.prototype.toString.call(value) : null;
}

function normalizeState(value, secret) {
  const empty = { approvals: {}, idempotency: {}, revoked: {}, budgets: {}, timeline: [], receipts: [], unavailable: false };
  if (!value) return empty;
  if (![1, 2, 3, 4].includes(value.version)) return { ...empty, unavailable: true };
  if (value.version === 4) {
    const { integrity, ...payload } = value;
    if (!integrity || !safeEqual(integrity, signature(stableJson(payload), secret))) return { ...empty, unavailable: true };
  }
  const approvals = value.version === 4
    ? openRecordMap(value.approvals, (record) => openSealedRecord(record, secret))
    : value.approvals && typeof value.approvals === "object" ? structuredClone(value.approvals) : {};
  const idempotency = value.version === 4
    ? openRecordMap(value.idempotency, (record) => openSealedRecord(record, secret))
    : value.idempotency && typeof value.idempotency === "object" ? structuredClone(value.idempotency) : {};
  const receipts = Array.isArray(value.receipts) ? value.receipts.map((receipt) => redactSensitive(receipt)) : [];
  const budgets = value.version >= 3 ? normalizeBudgets(value.budgets) : {};
  if (value.version < 3) {
    for (const receipt of receipts) {
      if (receipt?.delegation_id) budgets[receipt.delegation_id] = { committed: 0, reservations: {}, unavailable: true };
    }
    for (const approval of Object.values(approvals)) {
      if (approval?.delegation?.id) budgets[approval.delegation.id] = { committed: 0, reservations: {}, unavailable: true };
    }
  }
  return {
    approvals,
    idempotency,
    revoked: value.revoked && typeof value.revoked === "object" ? structuredClone(value.revoked) : {},
    budgets,
    timeline: Array.isArray(value.timeline) ? value.timeline.map((event) => redactSensitive(event)) : [],
    receipts,
    unavailable: false,
  };
}

function sealApproval(approval, secret) {
  return { status: approval.status, sealed: sealJson(approval, secret) };
}

function sealIdempotency(record, secret) {
  return { status: record?.response?.status || "unknown", sealed: sealJson(record, secret) };
}

function openRecordMap(value, opener) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const opened = {};
  for (const [key, record] of Object.entries(value)) {
    try {
      const result = opener(record);
      if (result && typeof result === "object") opened[key] = result;
    } catch {
      // A corrupted or incorrectly keyed protected record is omitted and therefore cannot authorize an effect.
    }
  }
  return opened;
}

function openSealedRecord(record, secret) {
  if (!record?.sealed) throw new Error("protected state record is missing its envelope");
  return openJson(record.sealed, secret);
}

function sealJson(value, secret) {
  return sealSecret(value, secret, "arena.trust.state.v1");
}

function openJson(envelope, secret) {
  return openSecret(envelope, secret, "arena.trust.state.v1");
}

function redactSensitive(value, parentSensitive = false) {
  if (parentSensitive) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((item) => redactSensitive(item));
  if (!value || typeof value !== "object") return structuredClone(value);
  const redacted = {};
  for (const [key, item] of Object.entries(value)) {
    const sensitive = /(?:authorization|cookie|credential|password|passphrase|secret|token|api[_-]?key|private[_-]?key|card|cvv|cvc|pin)/i.test(key);
    redacted[key] = redactSensitive(item, sensitive);
  }
  return redacted;
}

function normalizeBudgets(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const normalized = {};
  for (const [delegationId, candidate] of Object.entries(value)) {
    if (candidate?.unavailable === true) {
      normalized[delegationId] = { committed: 0, reservations: {}, unavailable: true };
      continue;
    }
    const reservations = candidate?.reservations;
    const committed = candidate?.committed;
    const validReservations = reservations && typeof reservations === "object" && !Array.isArray(reservations) &&
      Object.values(reservations).every((amount) => Number.isFinite(amount) && amount >= 0);
    if (!Number.isFinite(committed) || committed < 0 || !validReservations) {
      normalized[delegationId] = { committed: 0, reservations: {}, unavailable: true };
      continue;
    }
    normalized[delegationId] = { committed, reservations: structuredClone(reservations) };
  }
  return normalized;
}

function signToken(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${signature(encoded, secret)}`;
}

function verifyToken(token, secret) {
  if (typeof token !== "string") return null;
  const [encoded, supplied, extra] = token.split(".");
  if (!encoded || !supplied || extra || !safeEqual(supplied, signature(encoded, secret))) return null;
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function signReceipt(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return { ...payload, signature: signature(encoded, secret) };
}

function verifyReceipt(receipt, secret) {
  if (!receipt || typeof receipt !== "object" || !receipt.signature) return false;
  const { signature: supplied, ...payload } = receipt;
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return safeEqual(supplied, signature(encoded, secret));
}

function signature(value, secret) {
  return createHmac("sha256", secret).update(value).digest("base64url");
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function duration(started, ended) {
  return Math.max(0, Math.round((Number(ended) - Number(started)) * 1000) / 1000);
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && timingSafeEqual(a, b);
}
