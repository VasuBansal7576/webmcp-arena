import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { createAuditStore } from "../src/audit-store-core.js";
import { admitAuditStart } from "../src/audit-capability.js";
import { completeHostedAudit, createHostedAudit } from "../src/hosted-audit.js";
import { createWebMcpInvocationReceipt } from "../src/webmcp-invocation.js";

const NOW = Date.parse("2026-08-30T12:00:00.000Z");
const HASHES = Object.freeze({
  capabilityHash: "C".repeat(43),
  sessionHash: "S".repeat(43),
  contractHash: "K".repeat(43),
  targetHash: "T".repeat(43),
  toolHash: "W".repeat(43),
  argumentsHash: "A".repeat(43),
  releaseHash: "R".repeat(43),
  agentHash: "G".repeat(43),
  principalHash: "P".repeat(43),
  toolDefinitionHash: "D".repeat(43),
});

test("a rotated capability cannot claim the new nonce, even when timestamps collide", async (t) => {
  const { store } = testStore(t);
  const original = auditRecord({ id: auditId(1) });
  await store.insertAudit(original, "rotation-test");
  const rotated = {
    capabilityHash: "N".repeat(43),
    sessionHash: HASHES.sessionHash,
    nonceId: "rotated_nonce_0002",
  };

  assert.equal(await store.rotateApprovalCapability(original, rotated, NOW), true);
  const staleClaim = await store.claimApproval({
    id: original.id,
    now: NOW + 1,
    proof: { capabilityHash: HASHES.capabilityHash, sessionHash: HASHES.sessionHash },
  });
  assert.equal(staleClaim.status, "invalid");
  assert.equal((await store.loadAudit(original.id)).state, "awaiting_approval");

  const currentClaim = await store.claimApproval({
    id: original.id,
    now: NOW + 2,
    proof: { capabilityHash: rotated.capabilityHash, sessionHash: rotated.sessionHash },
  });
  assert.equal(currentClaim.status, "claimed");
  assert.equal(currentClaim.record.approval.nonceId, rotated.nonceId);
  assert.equal(currentClaim.record.approval.sessionCommitment, HASHES.sessionHash);
  assert.equal(currentClaim.record.approval.reviewerClaim, "same_origin_interface_session_controller");
  assert.equal(currentClaim.record.approval.assuranceClaim, "session_capability_verified_human_presence_not_attested");
  assert.equal(currentClaim.record.approval.expiresAt, original.approvalExpiresAt);
  assert.equal(currentClaim.record.approval.reviewedReleaseHash, HASHES.releaseHash);
  assert.equal(currentClaim.record.approval.reviewedAgentHash, HASHES.agentHash);
  assert.equal(currentClaim.record.approval.reviewedPrincipalHash, HASHES.principalHash);
  assert.equal(currentClaim.record.approval.reviewedToolDefinitionHash, HASHES.toolDefinitionHash);
});

test("only one concurrent request can consume an approval capability", async (t) => {
  const { store } = testStore(t);
  const record = auditRecord({ id: auditId(2) });
  await store.insertAudit(record, "concurrency-test");
  const proof = { capabilityHash: HASHES.capabilityHash, sessionHash: HASHES.sessionHash };

  const claims = await Promise.all([
    store.claimApproval({ id: record.id, now: NOW + 1, proof }),
    store.claimApproval({ id: record.id, now: NOW + 1, proof }),
  ]);

  assert.deepEqual(claims.map(({ status }) => status).sort(), ["claimed", "conflict"]);
  assert.equal((await store.loadAudit(record.id)).history.filter(({ state }) => state === "awaiting_webmcp_invocation").length, 1);
});

test("only the exact session-bound callback lease can claim an approved invocation", async (t) => {
  const { store } = testStore(t);
  const record = auditRecord({ id: auditId(20) });
  record.review.toolName = "preview_checkout";
  await store.insertAudit(record, "callback-claim-test");
  const approval = await store.claimApproval({
    id: record.id,
    now: NOW + 1,
    proof: { capabilityHash: HASHES.capabilityHash, sessionHash: HASHES.sessionHash },
  });
  assert.equal(approval.status, "claimed");
  const receipt = await createWebMcpInvocationReceipt({
    auditId: record.id,
    review: approval.record.review,
    approval: approval.record.approval,
    pageOrigin: "https://arena.example",
    invocationLease: approval.leaseId,
    invokedAt: new Date(NOW + 2).toISOString(),
  });

  const wrongLease = await store.claimInvocation({
    id: record.id,
    now: NOW + 2,
    leaseId: "ffffffff-ffff-4fff-8fff-ffffffffffff",
    sessionHash: HASHES.sessionHash,
    receipt,
  });
  assert.equal(wrongLease.status, "invalid");
  const wrongSession = await store.claimInvocation({
    id: record.id,
    now: NOW + 2,
    leaseId: approval.leaseId,
    sessionHash: "X".repeat(43),
    receipt,
  });
  assert.equal(wrongSession.status, "invalid");

  const claims = await Promise.all([
    store.claimInvocation({ id: record.id, now: NOW + 3, leaseId: approval.leaseId, sessionHash: HASHES.sessionHash, receipt }),
    store.claimInvocation({ id: record.id, now: NOW + 3, leaseId: approval.leaseId, sessionHash: HASHES.sessionHash, receipt }),
  ]);
  assert.deepEqual(claims.map(({ status }) => status).sort(), ["claimed", "conflict"]);
  const claimed = claims.find(({ status }) => status === "claimed");
  assert.equal(claimed.record.state, "waiting_for_effects");
  assert.deepEqual(claimed.record.invocation, receipt);
  assert.equal((await store.loadAudit(record.id)).history.at(-1).state, "waiting_for_effects");
});

test("the database claim binds the browser session as well as the capability", async (t) => {
  const { store } = testStore(t);
  const record = auditRecord({ id: auditId(3) });
  await store.insertAudit(record, "session-test");

  const claim = await store.claimApproval({
    id: record.id,
    now: NOW + 1,
    proof: { capabilityHash: HASHES.capabilityHash, sessionHash: "X".repeat(43) },
  });

  assert.equal(claim.status, "invalid");
  assert.equal((await store.loadAudit(record.id)).state, "awaiting_approval");
});

test("expired execution leases fail closed and are never reclaimed by approval", async (t) => {
  const { store, db } = testStore(t);
  const record = auditRecord({ id: auditId(4), state: "running" });
  await store.insertAudit(record, "stale-claim-test");
  await setLease(db, record.id, "running", "stale-lease", NOW - 1);

  const claim = await store.claimApproval({
    id: record.id,
    now: NOW,
    proof: { capabilityHash: HASHES.capabilityHash, sessionHash: HASHES.sessionHash },
  });

  assert.equal(claim.status, "failed");
  assert.equal(claim.record.failure.code, "execution_lease_expired");
  assert.equal(claim.record.failure.retrySafe, false);
  assert.equal((await store.loadAudit(record.id)).state, "failed");
});

test("cleanup fails stale running and waiting rows, preserves active work, and prunes expired failures", async (t) => {
  const { store, db } = testStore(t);
  const staleRunning = auditRecord({ id: auditId(5), state: "running", approvalExpiresAt: NOW + 60_000 });
  const staleWaiting = auditRecord({ id: auditId(6), state: "waiting_for_effects", approvalExpiresAt: NOW - 2, retentionUntil: NOW - 1 });
  const active = auditRecord({ id: auditId(7), state: "running", approvalExpiresAt: NOW + 60_000 });
  await store.insertAudit(staleRunning, "cleanup-running");
  await store.insertAudit(staleWaiting, "cleanup-waiting");
  await store.insertAudit(active, "cleanup-active");
  await setLease(db, staleRunning.id, "running", "stale-running", NOW - 1);
  await setLease(db, staleWaiting.id, "waiting_for_effects", "stale-waiting", NOW - 1);
  await setLease(db, active.id, "running", "active-running", NOW + 10_000);

  const cleaned = await store.pruneExpiredAudits(NOW);

  assert.deepEqual(cleaned, { failed: 2, pruned: 1 });
  assert.equal((await store.loadAudit(staleRunning.id)).state, "failed");
  assert.equal(await store.loadAudit(staleWaiting.id), null);
  assert.equal((await store.loadAudit(active.id)).state, "running");
});

test("an atomically claimed hosted audit can execute the isolated checkout fixture", async (t) => {
  const { store } = testStore(t);
  const privateApproval = {
    capabilityHash: HASHES.capabilityHash,
    sessionHash: HASHES.sessionHash,
    nonceId: "hosted_nonce_0008",
  };
  const record = await createHostedAudit({ id: auditId(8), version: "fixed", privateApproval, now: NOW });
  await store.insertAudit(record, "hosted-integration");

  const claim = await store.claimApproval({
    id: record.id,
    now: NOW + 1,
    proof: { capabilityHash: privateApproval.capabilityHash, sessionHash: privateApproval.sessionHash },
  });
  assert.equal(claim.status, "claimed");
  const invocation = await claimHostedInvocation(store, claim, NOW + 2);
  const result = await completeHostedAudit(invocation.record, { now: NOW + 3 });
  assert.equal(result.verdict, "pass");
  assert.equal(result.approval.nonceId, privateApproval.nonceId);
});

test("saving completed evidence atomically synchronizes its full retention deadline", async (t) => {
  const { store, db } = testStore(t);
  const privateApproval = {
    capabilityHash: HASHES.capabilityHash,
    sessionHash: HASHES.sessionHash,
    nonceId: "hosted_nonce_0011",
  };
  const record = await createHostedAudit({ id: auditId(11), version: "fixed", privateApproval, now: NOW });
  await store.insertAudit(record, "hosted-retention");
  const claim = await store.claimApproval({
    id: record.id,
    now: NOW + 1,
    proof: { capabilityHash: privateApproval.capabilityHash, sessionHash: privateApproval.sessionHash },
  });
  assert.equal(claim.status, "claimed");

  const completionAt = NOW + 2_000;
  const invocation = await claimHostedInvocation(store, claim, NOW + 2);
  const result = await completeHostedAudit(invocation.record, { now: completionAt });
  invocation.record.state = "completed";
  invocation.record.updatedAt = new Date(completionAt).toISOString();
  invocation.record.result = result;
  await store.saveAudit(invocation.record, {
    expectedState: "waiting_for_effects",
    leaseId: claim.leaseId,
    releaseLease: true,
  });

  const stored = await store.loadAudit(record.id);
  const row = await db.prepare("SELECT retention_until FROM audits WHERE id = ?").bind(record.id).first();
  assert.equal(Date.parse(stored.retentionUntil) - Date.parse(result.evidence.generatedAt), 2_592_000_000);
  assert.equal(stored.retentionUntil, result.evidence.retentionUntil);
  assert.equal(row.retention_until, Date.parse(stored.retentionUntil));
});

test("saving retention metadata rejects non-canonical deadlines and lost leases without partial writes", async (t) => {
  const { store, db } = testStore(t);
  const record = auditRecord({ id: auditId(12), state: "running" });
  await store.insertAudit(record, "retention-guards");
  await setLease(db, record.id, "running", "retention-lease", NOW + 30_000);
  const original = await db.prepare("SELECT state, retention_until, payload FROM audits WHERE id = ?")
    .bind(record.id).first();

  const malformed = structuredClone(record);
  malformed.state = "completed";
  malformed.updatedAt = new Date(NOW + 1).toISOString();
  malformed.retentionUntil = "2026-09-29";
  await assert.rejects(
    () => store.saveAudit(malformed, {
      expectedState: "running",
      leaseId: "retention-lease",
      releaseLease: true,
    }),
    /audit retention/,
  );
  assert.deepEqual(
    await db.prepare("SELECT state, retention_until, payload FROM audits WHERE id = ?").bind(record.id).first(),
    original,
  );

  const lostLease = structuredClone(record);
  lostLease.state = "completed";
  lostLease.updatedAt = new Date(NOW + 2).toISOString();
  lostLease.retentionUntil = new Date(NOW + 2_592_000_000 + 2).toISOString();
  await assert.rejects(
    () => store.saveAudit(lostLease, {
      expectedState: "running",
      leaseId: "wrong-retention-lease",
      releaseLease: true,
    }),
    /audit execution lease was lost/,
  );
  assert.deepEqual(
    await db.prepare("SELECT state, retention_until, payload FROM audits WHERE id = ?").bind(record.id).first(),
    original,
  );
});

test("expired awaiting approvals cannot be rotated", async (t) => {
  const { store } = testStore(t);
  const record = auditRecord({ id: auditId(9), approvalExpiresAt: NOW });
  await store.insertAudit(record, "expired-rotation");

  const rotated = await store.rotateApprovalCapability(record, {
    capabilityHash: "R".repeat(43),
    sessionHash: HASHES.sessionHash,
    nonceId: "rotated_nonce_0009",
  }, NOW);

  assert.equal(rotated, false);
  assert.equal((await store.loadAudit(record.id)).privateApproval.nonceId, "original_nonce_0001");
});

test("completed signed evidence survives approval expiry until its independent retention boundary", async (t) => {
  const { store } = testStore(t);
  const record = auditRecord({
    id: auditId(10),
    state: "completed",
    approvalExpiresAt: NOW - 60_000,
    retentionUntil: NOW + 30 * 24 * 60 * 60_000,
  });
  await store.insertAudit(record, "retained-proof");

  assert.deepEqual(await store.pruneExpiredAudits(NOW), { failed: 0, pruned: 0 });
  assert.equal((await store.loadAudit(record.id)).state, "completed");

  assert.deepEqual(await store.pruneExpiredAudits(recordRetention(record)), { failed: 0, pruned: 0 });
  assert.deepEqual(await store.pruneExpiredAudits(recordRetention(record) + 1), { failed: 0, pruned: 1 });
  assert.equal(await store.loadAudit(record.id), null);
});

test("audit starts are admitted six times per fixed window and reset exactly at the boundary", async (t) => {
  const { store, db } = testStore(t);
  const input = {
    bucketKey: `audit-start:v1:${HASHES.sessionHash}`,
    now: NOW,
    limit: 6,
    windowMs: 600_000,
  };

  const admitted = [];
  for (let attempt = 0; attempt < 6; attempt += 1) {
    admitted.push(await store.consumeAuditStartLimit({ ...input, now: NOW + attempt }));
  }
  assert.equal(admitted.every((result) => result.allowed), true);

  const denied = await store.consumeAuditStartLimit({ ...input, now: NOW + 599_999 });
  assert.deepEqual(denied, { allowed: false, resetAt: NOW + 600_000 });
  assert.equal((await db.prepare("SELECT request_count FROM audit_start_limits WHERE bucket_key = ?")
    .bind(input.bucketKey).first()).request_count, 6);

  const reset = await store.consumeAuditStartLimit({ ...input, now: NOW + 600_000 });
  assert.deepEqual(reset, { allowed: true, resetAt: NOW + 1_200_000 });
  assert.equal((await db.prepare("SELECT request_count FROM audit_start_limits WHERE bucket_key = ?")
    .bind(input.bucketKey).first()).request_count, 1);
});

test("the production global, network, and session policies satisfy the real store contract", async (t) => {
  const { store } = testStore(t);
  const request = new Request("https://arena.example/api/audits", {
    method: "POST",
    headers: { "cf-connecting-ip": "203.0.113.80" },
  });

  const admitted = await admitAuditStart({
    request,
    sessionHash: HASHES.sessionHash,
    now: NOW,
    consume: store.consumeAuditStartLimit,
  });

  assert.deepEqual(admitted, { allowed: true });
});

test("one abusive network cannot spend the global allowance with starts rejected by its narrower bucket", async (t) => {
  const { store } = testStore(t);
  const abusiveRequest = new Request("https://arena.example/api/audits", {
    method: "POST",
    headers: { "cf-connecting-ip": "203.0.113.90" },
  });
  const attempts = [];
  for (let index = 0; index < 120; index += 1) {
    attempts.push(await admitAuditStart({
      request: abusiveRequest,
      sessionHash: await testDigest(`abusive-session-${index}`),
      now: NOW + index,
      consume: store.consumeAuditStartLimit,
    }));
  }
  assert.equal(attempts.filter(({ allowed }) => allowed).length, 20);
  assert.equal(attempts.filter((result) => !result.allowed && result.scope === "network").length, 100);

  const unrelated = await admitAuditStart({
    request: new Request("https://arena.example/api/audits", {
      method: "POST",
      headers: { "cf-connecting-ip": "198.51.100.25" },
    }),
    sessionHash: await testDigest("unrelated-session"),
    now: NOW + 121,
    consume: store.consumeAuditStartLimit,
  });
  assert.deepEqual(unrelated, { allowed: true });
});

test("concurrent audit starts admit only one remaining slot and keep session buckets isolated", async (t) => {
  const { store } = testStore(t);
  const firstBucket = `audit-start:v1:${HASHES.sessionHash}`;
  const secondBucket = `audit-start:v1:${"Q".repeat(43)}`;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    assert.equal((await store.consumeAuditStartLimit({
      bucketKey: firstBucket,
      now: NOW + attempt,
      limit: 6,
      windowMs: 600_000,
    })).allowed, true);
  }

  const racing = await Promise.all(Array.from({ length: 10 }, () => store.consumeAuditStartLimit({
    bucketKey: firstBucket,
    now: NOW + 10,
    limit: 6,
    windowMs: 600_000,
  })));
  assert.equal(racing.filter(({ allowed }) => allowed).length, 1);
  assert.equal(racing.filter(({ allowed }) => !allowed).length, 9);

  const isolated = await store.consumeAuditStartLimit({
    bucketKey: secondBucket,
    now: NOW + 10,
    limit: 6,
    windowMs: 600_000,
  });
  assert.equal(isolated.allowed, true);
});

test("audit start limit cleanup prunes expired rows without touching active windows", async (t) => {
  const { store, db } = testStore(t);
  await db.prepare("INSERT INTO audit_start_limits (bucket_key, request_count, reset_at) VALUES (?, ?, ?)")
    .bind("audit-start:v1:expired", 6, NOW - 1).run();
  await db.prepare("INSERT INTO audit_start_limits (bucket_key, request_count, reset_at) VALUES (?, ?, ?)")
    .bind("audit-start:v1:active", 2, NOW + 1).run();

  assert.equal(await store.pruneExpiredAuditStartLimits(NOW, 100), 1);
  assert.equal(await db.prepare("SELECT COUNT(*) AS total FROM audit_start_limits").first().then((row) => row.total), 1);
  assert.equal((await db.prepare("SELECT bucket_key FROM audit_start_limits").first()).bucket_key, "audit-start:v1:active");
});

function testStore(t) {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(`CREATE TABLE audits (
    id TEXT PRIMARY KEY NOT NULL,
    idempotency_key TEXT UNIQUE,
    version TEXT NOT NULL CHECK (version IN ('vulnerable', 'fixed')),
    state TEXT NOT NULL CHECK (state IN ('awaiting_approval', 'running', 'waiting_for_effects', 'completed', 'failed')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    retention_until INTEGER NOT NULL,
    lease_id TEXT,
    lease_expires_at INTEGER,
    payload TEXT NOT NULL
  );
  CREATE TABLE audit_start_limits (
    bucket_key TEXT PRIMARY KEY NOT NULL,
    request_count INTEGER NOT NULL CHECK (request_count >= 1),
    reset_at INTEGER NOT NULL
  );
  CREATE INDEX idx_audit_start_limits_reset_at ON audit_start_limits(reset_at);`);
  const db = d1Like(sqlite);
  t.after(() => sqlite.close());
  return { db, store: createAuditStore(async () => db) };
}

function d1Like(sqlite) {
  return {
    prepare(sql) {
      const statement = sqlite.prepare(sql);
      let values = [];
      const prepared = {
        bind(...next) {
          values = next;
          return prepared;
        },
        async first() {
          return statement.get(...values) || null;
        },
        async run() {
          const result = statement.run(...values);
          return { meta: { changes: Number(result.changes) } };
        },
        async all() {
          return { results: statement.all(...values) };
        },
      };
      return prepared;
    },
  };
}

function auditRecord({
  id,
  state = "awaiting_approval",
  approvalExpiresAt = NOW + 60_000,
  retentionUntil = NOW + 30 * 24 * 60 * 60_000,
}) {
  const timestamp = new Date(NOW).toISOString();
  return {
    id,
    version: "fixed",
    state,
    createdAt: timestamp,
    updatedAt: timestamp,
    approvalExpiresAt: new Date(approvalExpiresAt).toISOString(),
    retentionUntil: new Date(retentionUntil).toISOString(),
    review: {
      contractHash: HASHES.contractHash,
      targetHash: HASHES.targetHash,
      toolHash: HASHES.toolHash,
      argumentsHash: HASHES.argumentsHash,
      releaseHash: HASHES.releaseHash,
      agentHash: HASHES.agentHash,
      principalHash: HASHES.principalHash,
      toolDefinitionHash: HASHES.toolDefinitionHash,
    },
    privateApproval: {
      capabilityHash: HASHES.capabilityHash,
      sessionHash: HASHES.sessionHash,
      nonceId: "original_nonce_0001",
    },
    approval: null,
    history: [{ state, at: timestamp }],
    result: null,
  };
}

function recordRetention(record) {
  return Date.parse(record.retentionUntil);
}

function setLease(db, id, state, leaseId, leaseExpiresAt) {
  return db.prepare("UPDATE audits SET state = ?, lease_id = ?, lease_expires_at = ? WHERE id = ?")
    .bind(state, leaseId, leaseExpiresAt, id).run();
}

function auditId(value) {
  return `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;
}

async function testDigest(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("base64url");
}

async function claimHostedInvocation(store, approval, invokedAt) {
  const receipt = await createWebMcpInvocationReceipt({
    auditId: approval.record.id,
    review: approval.record.review,
    approval: approval.record.approval,
    pageOrigin: "https://arena.example",
    invocationLease: approval.leaseId,
    invokedAt: new Date(invokedAt).toISOString(),
  });
  const claimed = await store.claimInvocation({
    id: approval.record.id,
    now: invokedAt,
    leaseId: approval.leaseId,
    sessionHash: approval.record.approval.sessionCommitment,
    receipt,
  });
  assert.equal(claimed.status, "claimed");
  return claimed;
}
