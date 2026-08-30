import { mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";

const require = createRequire(import.meta.url);

export function createSqliteRepository({ path }) {
  if (!path) throw new Error("SQLite repository requires a path");
  const { DatabaseSync } = require("node:sqlite");
  const resolved = resolve(path);
  mkdirSync(dirname(resolved), { recursive: true });
  const database = new DatabaseSync(resolved);
  database.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
  database.exec(`
    CREATE TABLE IF NOT EXISTS arena_state (
      key TEXT PRIMARY KEY,
      payload TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT
  `);
  const select = database.prepare("SELECT payload FROM arena_state WHERE key = ?");
  const upsert = database.prepare(`
    INSERT INTO arena_state (key, payload, updated_at) VALUES (?, ?, ?)
    ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at
  `);
  let writeLockDepth = 0;

  return {
    read(key, fallback = null) {
      const row = select.get(String(key));
      if (!row) return structuredClone(fallback);
      return JSON.parse(row.payload);
    },
    write(key, value) {
      upsert.run(String(key), JSON.stringify(value), new Date().toISOString());
    },
    withWriteLock(callback) {
      if (writeLockDepth > 0) return callback();
      database.exec("BEGIN IMMEDIATE");
      writeLockDepth += 1;
      try {
        const result = callback();
        database.exec("COMMIT");
        return result;
      } catch (error) {
        database.exec("ROLLBACK");
        throw error;
      } finally {
        writeLockDepth -= 1;
      }
    },
    close() {
      database.close();
    },
    path: resolved,
    durability: "sqlite_wal_full_sync",
  };
}

export function createMemoryRepository(initial = {}) {
  const values = new Map(Object.entries(structuredClone(initial)));
  return {
    read: (key, fallback = null) => structuredClone(values.has(String(key)) ? values.get(String(key)) : fallback),
    write: (key, value) => values.set(String(key), structuredClone(value)),
    withWriteLock: (callback) => callback(),
    close() {},
    durability: "memory",
  };
}

export function scopedStateStore(repository, key) {
  if (!repository?.read || !repository?.write) throw new Error("state repository must implement read and write");
  return {
    load: () => repository.read(key, null),
    save: (value) => repository.write(key, value),
    withLock: (callback) => repository.withWriteLock ? repository.withWriteLock(callback) : callback(),
  };
}
