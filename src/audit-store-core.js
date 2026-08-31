const EXECUTION_LEASE_MS = 30_000;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const NONCE = /^[A-Za-z0-9_-]{16,128}$/;
const EXECUTION_STATES = new Set(["running", "waiting_for_effects"]);

export function createAuditStore(getDb) {
  if (typeof getDb !== "function") throw new TypeError("an audit database provider is required");

  async function insertAudit(record, idempotencyKey) {
    const db = await getDb();
    const createdAt = Date.parse(String(record.createdAt));
    const updatedAt = Date.parse(String(record.updatedAt));
    const approvalExpiresAt = Date.parse(String(record.approvalExpiresAt));
    const retentionUntil = validatedRetentionUntil(record);
    await db.prepare("INSERT INTO audits (id, idempotency_key, version, state, created_at, updated_at, expires_at, retention_until, lease_id, lease_expires_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)")
      .bind(record.id, idempotencyKey, record.version, record.state, createdAt, updatedAt, approvalExpiresAt, retentionUntil, JSON.stringify(record)).run();
  }

  async function loadAudit(id) {
    const row = await loadAuditRow(await getDb(), id);
    return row ? parseRecord(row.payload) : null;
  }

  async function loadAuditByIdempotencyKey(idempotencyKey) {
    const db = await getDb();
    const row = await db.prepare("SELECT payload FROM audits WHERE idempotency_key = ?").bind(idempotencyKey).first();
    return row ? parseRecord(row.payload) : null;
  }

  async function claimApproval({ id, now, proof }) {
    const db = await getDb();
    const row = await loadAuditRow(db, id);
    if (!row) return claimResult("missing");

    const record = parseRecord(row.payload);
    record.state = row.state;
    if (row.state === "completed") return claimResult("completed", record);
    if (row.state === "failed") return claimResult("conflict", record);

    if (row.state === "awaiting_approval" && row.expires_at <= now) {
      const failed = await markFailedIfCurrent(db, row, now, "approval_window_expired");
      return claimResult("expired", failed || await loadAudit(id));
    }

    if (EXECUTION_STATES.has(row.state)) {
      if (row.lease_expires_at !== null && row.lease_expires_at > now) {
        return claimResult("conflict", record);
      }
      const failed = await markFailedIfCurrent(db, row, now, "execution_lease_expired");
      return failed
        ? claimResult("failed", failed)
        : claimResult("conflict", await loadAudit(id));
    }

    if (row.state !== "awaiting_approval" || !isApprovalProof(proof)) {
      return claimResult("invalid", record);
    }

    const privateApproval = record.privateApproval;
    const review = record.review;
    if (!isPrivateApproval(privateApproval) || !isReviewBinding(review)) {
      return claimResult("invalid", record);
    }

    const leaseId = crypto.randomUUID();
    const leaseExpiresAt = now + EXECUTION_LEASE_MS;
    const updatedAt = new Date(now).toISOString();
    const approvedRecord = structuredClone(record);
    approvedRecord.state = "running";
    approvedRecord.updatedAt = updatedAt;
    approvedRecord.approval = {
      status: "approved",
      method: "one_time_interface_session_capability",
      nonceId: privateApproval.nonceId,
      approvedAt: updatedAt,
      expiresAt: record.approvalExpiresAt,
      sessionCommitment: privateApproval.sessionHash,
      reviewerClaim: "same_origin_interface_session_controller",
      assuranceClaim: "session_capability_verified_human_presence_not_attested",
      reviewedContractHash: review.contractHash,
      reviewedTargetHash: review.targetHash,
      reviewedReleaseHash: review.releaseHash,
      reviewedAgentHash: review.agentHash,
      reviewedPrincipalHash: review.principalHash,
      reviewedToolDefinitionHash: review.toolDefinitionHash,
      reviewedToolHash: review.toolHash,
      reviewedArgumentsHash: review.argumentsHash,
    };
    approvedRecord.history = [...record.history, { state: "running", at: updatedAt }];

    const result = await db.prepare(`UPDATE audits
      SET state = 'running', updated_at = ?, lease_id = ?, lease_expires_at = ?, payload = ?
      WHERE id = ? AND state = 'awaiting_approval' AND expires_at > ? AND updated_at = ?
        AND json_extract(payload, '$.privateApproval.capabilityHash') = ?
        AND json_extract(payload, '$.privateApproval.sessionHash') = ?
        AND json_extract(payload, '$.privateApproval.nonceId') = ?
        AND json_extract(payload, '$.review.contractHash') = ?
        AND json_extract(payload, '$.review.targetHash') = ?
        AND json_extract(payload, '$.review.releaseHash') = ?
        AND json_extract(payload, '$.review.agentHash') = ?
        AND json_extract(payload, '$.review.principalHash') = ?
        AND json_extract(payload, '$.review.toolDefinitionHash') = ?
        AND json_extract(payload, '$.review.toolHash') = ?
        AND json_extract(payload, '$.review.argumentsHash') = ?`)
      .bind(
        now,
        leaseId,
        leaseExpiresAt,
        JSON.stringify(approvedRecord),
        id,
        now,
        row.updated_at,
        proof.capabilityHash,
        proof.sessionHash,
        privateApproval.nonceId,
        review.contractHash,
        review.targetHash,
        review.releaseHash,
        review.agentHash,
        review.principalHash,
        review.toolDefinitionHash,
        review.toolHash,
        review.argumentsHash,
      ).run();

    if (changed(result)) return claimResult("claimed", approvedRecord, leaseId);

    const current = await loadAuditRow(db, id);
    if (!current) return claimResult("missing");
    const currentRecord = parseRecord(current.payload);
    if (current.state === "completed") return claimResult("completed", currentRecord);
    if (current.state === "awaiting_approval" && !proofMatches(currentRecord.privateApproval, proof)) {
      return claimResult("invalid", currentRecord);
    }
    return claimResult("conflict", currentRecord);
  }

  async function rotateApprovalCapability(record, privateApproval, now) {
    const previous = record?.privateApproval;
    if (record?.state !== "awaiting_approval" ||
        !isPrivateApproval(previous) ||
        !isPrivateApproval(privateApproval) ||
        previous.sessionHash !== privateApproval.sessionHash ||
        Date.parse(String(record.approvalExpiresAt)) <= now) return false;

    const db = await getDb();
    const previousUpdatedAt = Date.parse(String(record.updatedAt));
    const next = structuredClone(record);
    next.privateApproval = structuredClone(privateApproval);
    next.updatedAt = new Date(now).toISOString();
    const result = await db.prepare(`UPDATE audits SET updated_at = ?, payload = ?
      WHERE id = ? AND state = 'awaiting_approval' AND updated_at = ? AND expires_at > ?
        AND json_extract(payload, '$.privateApproval.capabilityHash') = ?
        AND json_extract(payload, '$.privateApproval.sessionHash') = ?
        AND json_extract(payload, '$.privateApproval.nonceId') = ?`)
      .bind(
        now,
        JSON.stringify(next),
        record.id,
        previousUpdatedAt,
        now,
        previous.capabilityHash,
        previous.sessionHash,
        previous.nonceId,
      ).run();
    if (!changed(result)) return false;
    Object.assign(record, next);
    return true;
  }

  async function saveAudit(record, { expectedState, leaseId, releaseLease = false }) {
    const db = await getDb();
    const updatedAt = Date.parse(String(record.updatedAt));
    const retentionUntil = validatedRetentionUntil(record);
    if (!Number.isFinite(updatedAt)) throw new TypeError("audit update timestamp must be valid");
    const leaseExpiresAt = releaseLease ? null : Date.now() + EXECUTION_LEASE_MS;
    const result = await db.prepare("UPDATE audits SET state = ?, updated_at = ?, retention_until = ?, lease_id = ?, lease_expires_at = ?, payload = ? WHERE id = ? AND state = ? AND lease_id = ?")
      .bind(record.state, updatedAt, retentionUntil, releaseLease ? null : leaseId, leaseExpiresAt, JSON.stringify(record), record.id, expectedState, leaseId).run();
    if (!changed(result)) throw new Error("audit execution lease was lost");
  }

  async function pruneExpiredAudits(now, limit = 50) {
    const db = await getDb();
    const candidates = await db.prepare(`SELECT id, state, updated_at, expires_at, lease_id, lease_expires_at, payload
      FROM audits
      WHERE (state = 'awaiting_approval' AND expires_at <= ?)
         OR (state IN ('running', 'waiting_for_effects') AND (lease_expires_at IS NULL OR lease_expires_at <= ?))
      ORDER BY updated_at LIMIT ?`).bind(now, now, limit).all();

    let failed = 0;
    for (const row of candidates.results || []) {
      const reason = row.state === "awaiting_approval" ? "approval_window_expired" : "execution_lease_expired";
      if (await markFailedIfCurrent(db, row, now, reason)) failed += 1;
    }

    const deletion = await db.prepare("DELETE FROM audits WHERE id IN (SELECT id FROM audits WHERE retention_until < ? AND state IN ('completed', 'failed') ORDER BY retention_until LIMIT ?)")
      .bind(now, limit).run();
    return { failed, pruned: Number(deletion?.meta?.changes || 0) };
  }

  async function consumeAuditStartLimit({ bucketKey, now, limit, windowMs }) {
    if (!/^audit-start:v1:[A-Za-z0-9_-]{16,128}$/.test(bucketKey || "")) {
      throw new TypeError("an audit start limit bucket commitment is required");
    }
    if (!Number.isInteger(now) || !Number.isInteger(limit) || limit < 1 || limit > 1_000 ||
        !Number.isInteger(windowMs) || windowMs < 1_000 || windowMs > 3_600_000) {
      throw new TypeError("audit start limit timing is invalid");
    }

    const db = await getDb();
    const nextResetAt = now + windowMs;
    const result = await db.prepare(`INSERT INTO audit_start_limits (bucket_key, request_count, reset_at)
      VALUES (?, 1, ?)
      ON CONFLICT(bucket_key) DO UPDATE SET
        request_count = CASE
          WHEN audit_start_limits.reset_at <= ? THEN 1
          ELSE audit_start_limits.request_count + 1
        END,
        reset_at = CASE
          WHEN audit_start_limits.reset_at <= ? THEN excluded.reset_at
          ELSE audit_start_limits.reset_at
        END
      WHERE audit_start_limits.reset_at <= ?
         OR audit_start_limits.request_count < ?`)
      .bind(bucketKey, nextResetAt, now, now, now, limit).run();
    const row = await db.prepare("SELECT reset_at FROM audit_start_limits WHERE bucket_key = ?")
      .bind(bucketKey).first();
    if (!row || !Number.isInteger(Number(row.reset_at))) {
      throw new Error("audit start limit storage did not return a reset boundary");
    }
    return { allowed: changed(result), resetAt: Number(row.reset_at) };
  }

  async function pruneExpiredAuditStartLimits(now, limit = 100) {
    if (!Number.isInteger(now) || !Number.isInteger(limit) || limit < 1 || limit > 1_000) {
      throw new TypeError("audit start limit cleanup timing is invalid");
    }
    const db = await getDb();
    const deletion = await db.prepare(`DELETE FROM audit_start_limits
      WHERE bucket_key IN (
        SELECT bucket_key FROM audit_start_limits WHERE reset_at <= ? ORDER BY reset_at LIMIT ?
      )`).bind(now, limit).run();
    return Number(deletion?.meta?.changes || 0);
  }

  return Object.freeze({
    claimApproval,
    consumeAuditStartLimit,
    insertAudit,
    loadAudit,
    loadAuditByIdempotencyKey,
    pruneExpiredAudits,
    pruneExpiredAuditStartLimits,
    rotateApprovalCapability,
    saveAudit,
  });
}

async function loadAuditRow(db, id) {
  return db.prepare("SELECT id, state, updated_at, expires_at, retention_until, lease_id, lease_expires_at, payload FROM audits WHERE id = ?")
    .bind(id).first();
}

async function markFailedIfCurrent(db, row, now, reason) {
  const record = parseRecord(row.payload);
  const updatedAt = new Date(now).toISOString();
  record.state = "failed";
  record.updatedAt = updatedAt;
  record.failure = { code: reason, at: updatedAt, retrySafe: false };
  record.history = [...record.history, { state: "failed", at: updatedAt, reason }];

  const leaseGuard = row.state === "awaiting_approval"
    ? "expires_at <= ?"
    : "lease_id IS ? AND (lease_expires_at IS NULL OR lease_expires_at <= ?)";
  const guardValues = row.state === "awaiting_approval" ? [now] : [row.lease_id, now];
  const result = await db.prepare(`UPDATE audits
    SET state = 'failed', updated_at = ?, lease_id = NULL, lease_expires_at = NULL, payload = ?
    WHERE id = ? AND state = ? AND updated_at = ? AND ${leaseGuard}`)
    .bind(now, JSON.stringify(record), row.id, row.state, row.updated_at, ...guardValues).run();
  return changed(result) ? record : null;
}

function parseRecord(payload) {
  return JSON.parse(String(payload));
}

function validatedRetentionUntil(record) {
  const approvalValue = record?.approvalExpiresAt;
  const retentionValue = record?.retentionUntil;
  const approvalExpiresAt = Date.parse(String(approvalValue));
  const retentionUntil = Date.parse(String(retentionValue));
  if (!Number.isFinite(approvalExpiresAt) || !Number.isFinite(retentionUntil) || retentionUntil <= approvalExpiresAt) {
    throw new TypeError("audit retention must outlive its approval window");
  }
  if (new Date(approvalExpiresAt).toISOString() !== approvalValue ||
      new Date(retentionUntil).toISOString() !== retentionValue) {
    throw new TypeError("audit retention requires canonical approval and cleanup timestamps");
  }
  return retentionUntil;
}

function claimResult(status, record = null, leaseId = null) {
  return { status, record, leaseId };
}

function changed(result) {
  return Number(result?.meta?.changes || 0) === 1;
}

function isApprovalProof(value) {
  return value && DIGEST.test(value.capabilityHash || "") && DIGEST.test(value.sessionHash || "");
}

function isPrivateApproval(value) {
  return isApprovalProof(value) && NONCE.test(value.nonceId || "");
}

function isReviewBinding(value) {
  return value && [
    value.contractHash,
    value.targetHash,
    value.releaseHash,
    value.agentHash,
    value.principalHash,
    value.toolDefinitionHash,
    value.toolHash,
    value.argumentsHash,
  ]
    .every((digest) => DIGEST.test(digest || ""));
}

function proofMatches(privateApproval, proof) {
  return isPrivateApproval(privateApproval) && isApprovalProof(proof) &&
    privateApproval.capabilityHash === proof.capabilityHash &&
    privateApproval.sessionHash === proof.sessionHash;
}
