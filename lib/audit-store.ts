import { getAuditDb } from "@/db";

const EXECUTION_LEASE_MS = 30_000;

export async function insertAudit(record: Record<string, any>, idempotencyKey: string) {
  const db = await getAuditDb();
  const createdAt = Date.parse(String(record.createdAt));
  const updatedAt = Date.parse(String(record.updatedAt));
  const expiresAt = Date.parse(String(record.expiresAt));
  await db.prepare("INSERT INTO audits (id, idempotency_key, version, state, created_at, updated_at, expires_at, lease_id, lease_expires_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)")
    .bind(record.id, idempotencyKey, record.version, record.state, createdAt, updatedAt, expiresAt, JSON.stringify(record)).run();
}

export async function loadAudit(id: string) {
  const db = await getAuditDb();
  const row = await db.prepare("SELECT payload FROM audits WHERE id = ?").bind(id).first<{ payload: string }>();
  return row ? JSON.parse(row.payload) : null;
}

export async function loadAuditByIdempotencyKey(idempotencyKey: string) {
  const db = await getAuditDb();
  const row = await db.prepare("SELECT payload FROM audits WHERE idempotency_key = ?").bind(idempotencyKey).first<{ payload: string }>();
  return row ? JSON.parse(row.payload) : null;
}

export async function claimApproval(id: string, now: number) {
  const db = await getAuditDb();
  const record = await loadAudit(id);
  if (!record) return { status: "missing" as const, record: null, leaseId: null };
  if (record.state === "completed") return { status: "completed" as const, record, leaseId: null };
  if (Date.parse(record.expiresAt) <= now) return { status: "expired" as const, record, leaseId: null };

  const leaseId = crypto.randomUUID();
  const leaseExpiresAt = now + EXECUTION_LEASE_MS;
  if (record.state === "awaiting_approval") {
    record.state = "running";
    record.updatedAt = new Date(now).toISOString();
    record.approval = {
      status: "approved",
      method: "one_time_interface_session_capability",
      nonceId: record.privateApproval.nonceId,
      approvedAt: record.updatedAt,
      reviewedContractHash: record.review.contractHash,
      reviewedTargetHash: record.review.targetHash,
      reviewedToolHash: record.review.toolHash,
      reviewedArgumentsHash: record.review.argumentsHash,
    };
    record.history = [...record.history, { state: "running", at: record.updatedAt }];
    const result = await db.prepare("UPDATE audits SET state = 'running', updated_at = ?, lease_id = ?, lease_expires_at = ?, payload = ? WHERE id = ? AND state = 'awaiting_approval' AND expires_at > ?")
      .bind(now, leaseId, leaseExpiresAt, JSON.stringify(record), id, now).run();
    return Number(result.meta.changes || 0) === 1
      ? { status: "claimed" as const, record, leaseId }
      : { status: "conflict" as const, record: await loadAudit(id), leaseId: null };
  }

  if (new Set(["running", "waiting_for_effects"]).has(record.state)) {
    const row = await db.prepare("SELECT lease_expires_at, updated_at FROM audits WHERE id = ?").bind(id).first<{ lease_expires_at: number | null; updated_at: number }>();
    if (!row || Number(row.lease_expires_at || 0) > now) {
      return { status: "conflict" as const, record, leaseId: null };
    }
    record.state = "running";
    record.updatedAt = new Date(now).toISOString();
    record.history = [...record.history, { state: "running", at: record.updatedAt, recovery: true }];
    const result = await db.prepare("UPDATE audits SET state = 'running', updated_at = ?, lease_id = ?, lease_expires_at = ?, payload = ? WHERE id = ? AND updated_at = ? AND lease_expires_at <= ?")
      .bind(now, leaseId, leaseExpiresAt, JSON.stringify(record), id, row.updated_at, now).run();
    return Number(result.meta.changes || 0) === 1
      ? { status: "reclaimed" as const, record, leaseId }
      : { status: "conflict" as const, record: await loadAudit(id), leaseId: null };
  }

  return { status: "conflict" as const, record, leaseId: null };
}

export async function rotateApprovalCapability(record: Record<string, any>, privateApproval: Record<string, string>, now: number) {
  if (record.state !== "awaiting_approval" || record.privateApproval?.sessionHash !== privateApproval.sessionHash) return false;
  const db = await getAuditDb();
  const previousUpdatedAt = Date.parse(String(record.updatedAt));
  record.privateApproval = structuredClone(privateApproval);
  record.updatedAt = new Date(now).toISOString();
  const result = await db.prepare("UPDATE audits SET updated_at = ?, payload = ? WHERE id = ? AND state = 'awaiting_approval' AND updated_at = ?")
    .bind(now, JSON.stringify(record), record.id, previousUpdatedAt).run();
  return Number(result.meta.changes || 0) === 1;
}

export async function saveAudit(record: Record<string, any>, { expectedState, leaseId, releaseLease = false }: { expectedState: string; leaseId: string; releaseLease?: boolean }) {
  const db = await getAuditDb();
  const updatedAt = Date.parse(String(record.updatedAt));
  const leaseExpiresAt = releaseLease ? null : Date.now() + EXECUTION_LEASE_MS;
  const result = await db.prepare("UPDATE audits SET state = ?, updated_at = ?, lease_id = ?, lease_expires_at = ?, payload = ? WHERE id = ? AND state = ? AND lease_id = ?")
    .bind(record.state, updatedAt, releaseLease ? null : leaseId, leaseExpiresAt, JSON.stringify(record), record.id, expectedState, leaseId).run();
  if (Number(result.meta.changes || 0) !== 1) throw new Error("audit execution lease was lost");
}

export async function pruneExpiredAudits(now: number, limit = 50) {
  const db = await getAuditDb();
  await db.prepare("DELETE FROM audits WHERE id IN (SELECT id FROM audits WHERE expires_at < ? AND state IN ('awaiting_approval', 'completed', 'failed') ORDER BY expires_at LIMIT ?)")
    .bind(now, limit).run();
}
