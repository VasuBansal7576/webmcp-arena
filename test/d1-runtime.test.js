import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import {
  createAuditDatabaseProvider,
  initializeAuditDatabase,
} from "../db/runtime.ts";

test("runtime initialization upgrades the legacy schema, purges incompatible rows, and preserves current rows", async (t) => {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  sqlite.exec(`CREATE TABLE audits (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    version TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    lease_id TEXT,
    lease_expires_at INTEGER,
    payload TEXT NOT NULL
  )`);
  sqlite.prepare("INSERT INTO audits VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(
    "legacy-audit",
    "legacy-key",
    "fixed",
    "completed",
    1,
    1,
    2,
    null,
    null,
    JSON.stringify({ id: "legacy-audit", expiresAt: "2026-08-31T00:00:00.000Z" }),
  );
  const db = sqliteD1(sqlite);

  await initializeAuditDatabase(db);

  assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM audits").get().count, 0);
  assert.equal(
    sqlite.prepare("SELECT COUNT(*) AS count FROM pragma_table_info('audits') WHERE name = 'retention_until'").get().count,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'audit_start_limits'").get().count,
    1,
  );

  const currentPayload = JSON.stringify({
    id: "current-audit",
    approvalExpiresAt: "2026-08-31T00:10:00.000Z",
    retentionUntil: "2026-09-30T00:00:00.000Z",
  });
  sqlite.prepare(`INSERT INTO audits (
    id, idempotency_key, version, state, created_at, updated_at, expires_at,
    retention_until, lease_id, lease_expires_at, payload
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run("current-audit", "current-key", "fixed", "completed", 1, 1, 2, 3, null, null, currentPayload);

  await initializeAuditDatabase(db);
  assert.deepEqual(
    sqlite.prepare("SELECT id FROM audits ORDER BY id").all().map(({ id }) => id),
    ["current-audit"],
  );
});

test("one provider coalesces concurrent initialization and remains idempotent", async () => {
  const calls = [];
  const db = currentSchemaD1(calls);
  const getAuditDb = createAuditDatabaseProvider(() => db);

  const resolved = await Promise.all(Array.from({ length: 12 }, () => getAuditDb()));
  assert.equal(resolved.every((candidate) => candidate === db), true);
  assert.equal(calls.filter((sql) => sql.startsWith("PRAGMA table_info")).length, 1);
  assert.equal(calls.filter((sql) => sql.startsWith("DELETE FROM audits")).length, 2);

  await getAuditDb();
  assert.equal(calls.filter((sql) => sql.startsWith("PRAGMA table_info")).length, 1);
});

test("separate concurrent initializers tolerate a retention-column race", async () => {
  const db = racingLegacyD1();
  const firstProvider = createAuditDatabaseProvider(() => db);
  const secondProvider = createAuditDatabaseProvider(() => db);

  const [first, second] = await Promise.all([firstProvider(), secondProvider()]);

  assert.equal(first, db);
  assert.equal(second, db);
  assert.equal(db.retentionColumnPresent(), true);
  assert.equal(db.alterAttempts(), 2, "both cold starts must exercise the migration race");
});

function sqliteD1(sqlite) {
  return {
    async exec(sql) {
      sqlite.exec(sql);
    },
    prepare(sql) {
      return {
        async all() {
          return { results: sqlite.prepare(sql).all() };
        },
      };
    },
  };
}

function currentSchemaD1(calls) {
  return {
    async exec(sql) {
      calls.push(sql);
      await Promise.resolve();
    },
    prepare(sql) {
      calls.push(sql);
      return {
        async all() {
          await Promise.resolve();
          return { results: [{ name: "id" }, { name: "retention_until" }] };
        },
      };
    },
  };
}

function racingLegacyD1() {
  let hasRetentionColumn = false;
  let retentionAlterAttempts = 0;
  const initialColumnReaders = [];

  return {
    async exec(sql) {
      if (!sql.startsWith("ALTER TABLE audits ADD COLUMN retention_until")) return;
      retentionAlterAttempts += 1;
      await Promise.resolve();
      if (hasRetentionColumn) throw new Error("duplicate column name: retention_until");
      hasRetentionColumn = true;
    },
    prepare(sql) {
      return {
        async all() {
          if (!sql.startsWith("PRAGMA table_info")) return { results: [] };
          if (hasRetentionColumn) return columnResult(true);
          return new Promise((resolve) => {
            initialColumnReaders.push(resolve);
            if (initialColumnReaders.length === 2) {
              for (const release of initialColumnReaders) release(columnResult(false));
            }
          });
        },
      };
    },
    retentionColumnPresent() {
      return hasRetentionColumn;
    },
    alterAttempts() {
      return retentionAlterAttempts;
    },
  };
}

function columnResult(includeRetention) {
  return {
    results: includeRetention
      ? [{ name: "id" }, { name: "retention_until" }]
      : [{ name: "id" }],
  };
}
