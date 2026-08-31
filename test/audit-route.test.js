import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import { createAuditPostHandler } from "../app/api/audits/post-handler.js";
import { createAuditStore } from "../src/audit-store-core.js";

const NOW = Date.parse("2026-08-31T12:00:00.000Z");
const AUDIT_ID = "00000000-0000-4000-8000-000000000042";

test("same-key idempotent POSTs are admitted only within the six-request session budget", async (t) => {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
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
  );`);
  const store = createAuditStore(async () => d1Like(sqlite));
  let idempotencyReads = 0;
  let rotations = 0;
  const handler = createAuditPostHandler({
    ...store,
    async loadAuditByIdempotencyKey(key) {
      idempotencyReads += 1;
      return store.loadAuditByIdempotencyKey(key);
    },
    async rotateApprovalCapability(record, replacement, now) {
      rotations += 1;
      return store.rotateApprovalCapability(record, replacement, now);
    },
  }, {
    now: () => NOW,
    createAuditId: () => AUDIT_ID,
  });

  const first = await handler(auditRequest());
  assert.equal(first.status, 201);
  const cookie = first.headers.get("set-cookie")?.split(";", 1)[0];
  assert.match(cookie || "", /^arena_session=/);
  const accepted = [await first.json()];

  for (let attempt = 1; attempt < 6; attempt += 1) {
    const response = await handler(auditRequest(cookie));
    assert.equal(response.status, 200);
    accepted.push(await response.json());
  }

  assert.deepEqual(accepted.map(({ audit }) => audit.id), Array(6).fill(AUDIT_ID));
  assert.equal(new Set(accepted.map(({ approvalCapability }) => approvalCapability)).size, 6);
  assert.equal(accepted.every(({ approvalCapability }) => typeof approvalCapability === "string"), true);
  assert.equal(idempotencyReads, 6);
  assert.equal(rotations, 5);

  const readsBeforeDenial = idempotencyReads;
  const rotationsBeforeDenial = rotations;
  const denied = await handler(auditRequest(cookie));
  assert.equal(denied.status, 429);
  assert.equal(denied.headers.get("retry-after"), "600");
  assert.deepEqual(await denied.json(), {
    error: "audit start limit reached; retry in 600 seconds",
    code: "audit_start_rate_limited",
    retryAfterSeconds: 600,
    limitScope: "session",
  });
  assert.equal(idempotencyReads, readsBeforeDenial, "denied retries must not perform an idempotency read");
  assert.equal(rotations, rotationsBeforeDenial, "denied retries must not rotate the approval capability");
});

function auditRequest(cookie = "") {
  return new Request("https://arena.example/api/audits", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://arena.example",
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      "cf-connecting-ip": "203.0.113.42",
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify({ version: "fixed", idempotencyKey: "same-key-retry" }),
  });
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
