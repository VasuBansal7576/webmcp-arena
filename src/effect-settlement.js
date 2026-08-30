const SAFE_SCOPE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function createEffectSettlementObserver({ scheduler, pollIntervalMs = 25, timeoutMs = 1_000 } = {}) {
  if (!scheduler || typeof scheduler.now !== "function" || typeof scheduler.sleep !== "function") {
    throw new Error("effect settlement observer requires a scheduler with now and sleep");
  }
  validateDuration(pollIntervalMs, "pollIntervalMs", { minimum: 1 });
  validateDuration(timeoutMs, "timeoutMs", { minimum: 1 });

  async function observe({ logicalScopeId, read } = {}) {
    const scope = safeScope(logicalScopeId);
    if (typeof read !== "function") throw new Error("effect settlement observer requires a read function");
    const startedAt = validClock(scheduler.now());
    const deadline = startedAt + timeoutMs;

    while (true) {
      const snapshot = validateSnapshot(await read());
      if (snapshot.pendingEffects === 0) {
        return terminalRecord(scope, "settled", "terminal_watermark", snapshot);
      }
      const current = validClock(scheduler.now());
      if (current >= deadline) {
        return terminalRecord(scope, "inconclusive", "timeout", snapshot);
      }
      await scheduler.sleep(Math.min(pollIntervalMs, deadline - current));
    }
  }

  return Object.freeze({ observe });
}

export function createDeterministicScheduler({ startMs = 0 } = {}) {
  validateDuration(startMs, "startMs", { minimum: 0 });
  let clock = startMs;
  let nextId = 0;
  const tasks = [];

  function schedule(delayMs, task, { scopeId = "global" } = {}) {
    validateDuration(delayMs, "delayMs", { minimum: 0 });
    if (typeof task !== "function") throw new Error("scheduled task must be a function");
    const scope = safeScope(scopeId);
    const record = { id: ++nextId, dueAt: clock + delayMs, scopeId: scope, task };
    tasks.push(record);
    return record.id;
  }

  async function sleep(durationMs) {
    validateDuration(durationMs, "sleep duration", { minimum: 0 });
    const target = clock + durationMs;
    while (true) {
      const next = tasks
        .filter(({ dueAt }) => dueAt <= target)
        .sort((left, right) => left.dueAt - right.dueAt || left.id - right.id)[0];
      if (!next) break;
      tasks.splice(tasks.indexOf(next), 1);
      clock = next.dueAt;
      await next.task();
    }
    clock = target;
  }

  function cancelScope(scopeId) {
    const scope = safeScope(scopeId);
    let cancelled = 0;
    for (let index = tasks.length - 1; index >= 0; index -= 1) {
      if (tasks[index].scopeId === scope) {
        tasks.splice(index, 1);
        cancelled += 1;
      }
    }
    return cancelled;
  }

  function pendingCount(scopeId = null) {
    if (scopeId === null) return tasks.length;
    const scope = safeScope(scopeId);
    return tasks.filter((task) => task.scopeId === scope).length;
  }

  return Object.freeze({
    now: () => clock,
    schedule,
    sleep,
    cancelScope,
    pendingCount,
  });
}

function terminalRecord(logicalScopeId, status, reason, snapshot) {
  return Object.freeze({
    kind: "effect_settlement",
    version: 1,
    logicalScopeId,
    complete: status === "settled",
    status,
    reason,
    observedThrough: snapshot.watermark,
    pendingEffects: snapshot.pendingEffects,
  });
}

function validateSnapshot(value) {
  if (!isPlainObject(value) || !Number.isSafeInteger(value.watermark) || value.watermark < 0 ||
      !Number.isSafeInteger(value.pendingEffects) || value.pendingEffects < 0) {
    throw new Error("effect settlement read must return non-negative integer watermark and pendingEffects");
  }
  return { watermark: value.watermark, pendingEffects: value.pendingEffects };
}

function validateDuration(value, label, { minimum }) {
  if (!Number.isSafeInteger(value) || value < minimum || value > 24 * 60 * 60 * 1_000) {
    throw new Error(`${label} must be an integer between ${minimum} and 86400000 milliseconds`);
  }
}

function validClock(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("effect settlement scheduler returned an invalid clock");
  return value;
}

function safeScope(value) {
  const result = String(value || "");
  if (!SAFE_SCOPE.test(result)) throw new Error("effect settlement logical scope identifier is invalid");
  return result;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
