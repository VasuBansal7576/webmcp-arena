import { randomUUID } from "node:crypto";

const DEFAULT_REPOSITORY_KEY = "measured_audits";

export function createMeasuredAuditService({
  presets,
  prepare,
  run,
  repository,
  clock = () => new Date(),
  id = randomUUID,
  onApprovalRequired,
  repositoryKey = DEFAULT_REPOSITORY_KEY,
} = {}) {
  if (!presets || typeof presets !== "object" || Array.isArray(presets)) throw new Error("measured audit presets are required");
  if (typeof prepare !== "function" || typeof run !== "function") throw new Error("measured audit prepare and run dependencies are required");
  if (!repository?.read || !repository?.write) throw new Error("measured audit repository must implement read and write");
  if (typeof clock !== "function" || typeof id !== "function") throw new Error("measured audit clock and id dependencies must be functions");
  if (typeof onApprovalRequired !== "function") throw new Error("measured audit human approval callback is required");
  const presetCatalog = structuredClone(presets);
  const preparations = new Map();
  const executions = new Map();
  recoverTransientAudits();

  async function start(input) {
    rejectUnsupportedFields(input, ["presetId", "idempotencyKey", "actor"], "start");
    const presetId = input?.presetId;
    const preset = presetCatalog[presetId];
    if (!preset) throw new Error("unknown measured audit preset");
    const actor = validateActor(input.actor);
    const idempotencyKey = validateIdempotencyKey(input.idempotencyKey);
    const idempotencyScope = `${actor.type}:${actor.id}:${idempotencyKey}`;
    const claim = withLock(repository, () => {
      const records = repository.read(repositoryKey, []);
      const existing = records.find((record) => record.idempotencyScope === idempotencyScope);
      if (existing) {
        if (existing.presetId !== presetId) throw new Error("measured audit idempotency conflict");
        return { created: false, record: existing };
      }
      const createdAt = nowIso(clock);
      const record = {
        id: String(id()),
        presetId,
        idempotencyKey,
        idempotencyScope,
        starter: actor,
        state: "preparing",
        createdAt,
        updatedAt: createdAt,
        review: null,
        execution: null,
        approval: null,
        result: null,
        error: null,
        history: [{ state: "preparing", at: createdAt }],
      };
      records.push(record);
      repository.write(repositoryKey, records);
      return { created: true, record };
    });
    if (!claim.created) {
      const active = preparations.get(claim.record.id);
      return active ? active : publicAudit(claim.record);
    }
    const preparation = completePreparation(claim.record, preset);
    preparations.set(claim.record.id, preparation);
    let prepared;
    try {
      prepared = await preparation;
    } finally {
      preparations.delete(claim.record.id);
    }
    return prepared;
  }

  async function completePreparation(record, preset) {
    let prepared;
    try {
      prepared = await prepare({ auditId: record.id, presetId: record.presetId, preset: structuredClone(preset) });
    } catch {
      return publicAudit(transition(record.id, "failed", { error: { code: "preparation_failed" } }));
    }
    const awaiting = transition(record.id, "awaiting_approval", {
      review: structuredClone(prepared.review),
      execution: structuredClone(prepared.execution),
      expiresAt: prepared.expiresAt || null,
    });
    const current = expirePendingAudit(record.id);
    if (current.state === "awaiting_approval") {
      onApprovalRequired({ audit: publicAudit(current), decide: (decision) => decideHuman(record.id, decision) });
    }
    return publicAudit(current);
  }

  async function poll(input) {
    rejectUnsupportedFields(input, ["auditId", "actor"], "poll");
    validateActor(input?.actor);
    return publicAudit(expirePendingAudit(input?.auditId));
  }

  async function decideHuman(auditId, decision) {
    rejectUnsupportedFields(decision, ["decision", "humanId"], "human decision");
    if (!new Set(["approve", "deny"]).has(decision?.decision) || typeof decision.humanId !== "string" || !decision.humanId) {
      throw new Error("human decision requires approve or deny and a humanId");
    }
    expirePendingAudit(auditId);
    const decisionAt = nowIso(clock);
    const claim = withLock(repository, () => {
      const records = repository.read(repositoryKey, []);
      const index = records.findIndex((record) => record.id === auditId);
      if (index < 0) throw new Error("unknown measured audit");
      if (records[index].state !== "awaiting_approval") return { execute: false, record: records[index] };
      if (decision.decision === "deny") {
        const denied = {
          ...records[index],
          state: "failed",
          updatedAt: decisionAt,
          approval: { status: "denied", humanId: decision.humanId, deniedAt: decisionAt },
          error: { code: "approval_denied" },
          history: [...records[index].history, { state: "failed", at: decisionAt }],
        };
        records[index] = denied;
        repository.write(repositoryKey, records);
        return { execute: false, record: denied };
      }
      const running = {
        ...records[index],
        state: "running",
        updatedAt: decisionAt,
        approval: { status: "approved", humanId: decision.humanId, approvedAt: decisionAt },
        history: [...records[index].history, { state: "running", at: decisionAt }],
      };
      records[index] = running;
      repository.write(repositoryKey, records);
      return { execute: true, record: running };
    });
    if (!claim.execute) {
      const active = executions.get(auditId);
      return active ? active : publicAudit(claim.record);
    }
    const execution = executeAudit(claim.record);
    executions.set(auditId, execution);
    try {
      return await execution;
    } finally {
      executions.delete(auditId);
    }
  }

  async function executeAudit(running) {
    const auditId = running.id;
    let outcomePromise;
    try {
      outcomePromise = Promise.resolve(run({
        auditId,
        presetId: running.presetId,
        preset: structuredClone(presetCatalog[running.presetId]),
        execution: structuredClone(running.execution),
        approval: structuredClone(running.approval),
      }));
    } catch {
      return publicAudit(transition(auditId, "outcome_unknown", { error: { code: "execution_outcome_unknown" } }));
    }
    transition(auditId, "waiting_for_effects");
    let result;
    try {
      result = await outcomePromise;
    } catch {
      return publicAudit(transition(auditId, "outcome_unknown", { error: { code: "execution_outcome_unknown" } }));
    }
    if (result?.verdict === "inconclusive") {
      return publicAudit(transition(auditId, "inconclusive", { result: structuredClone(result) }));
    }
    if (new Set(["pass", "fail"]).has(result?.verdict)) {
      return publicAudit(transition(auditId, "completed", { result: structuredClone(result) }));
    }
    return publicAudit(transition(auditId, "outcome_unknown", {
      result: null,
      error: { code: "execution_result_invalid" },
    }));
  }

  function transition(auditId, state, changes = {}) {
    return withLock(repository, () => {
      const records = repository.read(repositoryKey, []);
      const index = records.findIndex((record) => record.id === auditId);
      if (index < 0) throw new Error("unknown measured audit");
      const at = nowIso(clock);
      records[index] = {
        ...records[index],
        ...structuredClone(changes),
        state,
        updatedAt: at,
        history: [...records[index].history, { state, at }],
      };
      repository.write(repositoryKey, records);
      return structuredClone(records[index]);
    });
  }

  function requireRecord(auditId) {
    const record = repository.read(repositoryKey, []).find((candidate) => candidate.id === auditId);
    if (!record) throw new Error("unknown measured audit");
    return record;
  }

  function expirePendingAudit(auditId) {
    return withLock(repository, () => {
      const records = repository.read(repositoryKey, []);
      const index = records.findIndex((record) => record.id === auditId);
      if (index < 0) throw new Error("unknown measured audit");
      const record = records[index];
      if (record.state !== "awaiting_approval" || !record.expiresAt || Date.parse(record.expiresAt) > Date.parse(nowIso(clock))) {
        return record;
      }
      const at = nowIso(clock);
      records[index] = {
        ...record,
        state: "expired",
        updatedAt: at,
        error: { code: "approval_expired" },
        history: [...record.history, { state: "expired", at }],
      };
      repository.write(repositoryKey, records);
      return records[index];
    });
  }

  function recoverTransientAudits() {
    withLock(repository, () => {
      const records = repository.read(repositoryKey, []);
      const at = nowIso(clock);
      let changed = false;
      const recovered = records.map((record) => {
        let state;
        let code;
        if (new Set(["preparing", "awaiting_approval"]).has(record.state)) {
          state = "expired";
          code = "service_restarted_before_approval";
        } else if (new Set(["running", "waiting_for_effects"]).has(record.state)) {
          state = "outcome_unknown";
          code = "service_restarted_after_execution_started";
        } else {
          return record;
        }
        changed = true;
        return {
          ...record,
          state,
          updatedAt: at,
          error: { code },
          history: [...record.history, { state, at }],
        };
      });
      if (changed) repository.write(repositoryKey, recovered);
    });
  }

  return Object.freeze({ start, poll });
}

function publicAudit(record) {
  const { execution: _execution, idempotencyKey: _idempotencyKey, idempotencyScope: _idempotencyScope, ...visible } = structuredClone(record);
  return visible;
}

function validateIdempotencyKey(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 200) throw new Error("measured audit idempotencyKey is required");
  return value;
}

function validateActor(actor) {
  rejectUnsupportedFields(actor, ["type", "id"], "actor");
  if (!actor || !new Set(["agent", "human"]).has(actor.type) || typeof actor.id !== "string" || !actor.id) {
    throw new Error("audit actor must identify an agent or human");
  }
  return { type: actor.type, id: actor.id };
}

function rejectUnsupportedFields(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length) throw new Error(`unsupported ${label} field: ${unexpected.join(", ")}`);
}

function nowIso(clock) {
  const value = clock();
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) throw new Error("measured audit clock returned an invalid date");
  return value.toISOString();
}

function withLock(repository, callback) {
  return repository.withWriteLock ? repository.withWriteLock(callback) : callback();
}
