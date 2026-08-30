import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { createAuditStore } from "../src/audit-store-core.js";
import { completeHostedAudit, createHostedAudit } from "../src/hosted-audit.js";

const NOW = Date.parse("2026-08-30T12:00:00.000Z");
const HASHES = Object.freeze({
  capabilityHash: "C".repeat(43),
  sessionHash: "S".repeat(43),
  contractHash: "K".repeat(43),
  targetHash: "T".repeat(43),
  toolHash: "W".repeat(43),
  argumentsHash: "A".repeat(43),
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
  assert.equal(currentClaim.record.approval.expiresAt, original.expiresAt);
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
  assert.equal((await store.loadAudit(record.id)).history.filter(({ state }) => state === "running").length, 1);
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
  const staleRunning = auditRecord({ id: auditId(5), state: "running", expiresAt: NOW + 60_000 });
  const staleWaiting = auditRecord({ id: auditId(6), state: "waiting_for_effects", expiresAt: NOW - 1 });
  const active = auditRecord({ id: auditId(7), state: "running", expiresAt: NOW + 60_000 });
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

  const result = await completeHostedAudit(claim.record, { now: NOW + 2 });
  assert.equal(result.verdict, "pass");
  assert.equal(result.approval.nonceId, privateApproval.nonceId);
});

test("expired awaiting approvals cannot be rotated", async (t) => {
  const { store } = testStore(t);
  const record = auditRecord({ id: auditId(9), expiresAt: NOW });
  await store.insertAudit(record, "expired-rotation");

  const rotated = await store.rotateApprovalCapability(record, {
    capabilityHash: "R".repeat(43),
    sessionHash: HASHES.sessionHash,
    nonceId: "rotated_nonce_0009",
  }, NOW);

  assert.equal(rotated, false);
  assert.equal((await store.loadAudit(record.id)).privateApproval.nonceId, "original_nonce_0001");
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
    lease_id TEXT,
    lease_expires_at INTEGER,
    payload TEXT NOT NULL
  )`);
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

function auditRecord({ id, state = "awaiting_approval", expiresAt = NOW + 60_000 }) {
  const timestamp = new Date(NOW).toISOString();
  return {
    id,
    version: "fixed",
    state,
    createdAt: timestamp,
    updatedAt: timestamp,
    expiresAt: new Date(expiresAt).toISOString(),
    review: {
      contractHash: HASHES.contractHash,
      targetHash: HASHES.targetHash,
      toolHash: HASHES.toolHash,
      argumentsHash: HASHES.argumentsHash,
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

function setLease(db, id, state, leaseId, leaseExpiresAt) {
  return db.prepare("UPDATE audits SET state = ?, lease_id = ?, lease_expires_at = ? WHERE id = ?")
    .bind(state, leaseId, leaseExpiresAt, id).run();
}

function auditId(value) {
  return `00000000-0000-4000-8000-${String(value).padStart(12, "0")}`;
}
