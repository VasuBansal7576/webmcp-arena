const CREATE_AUDITS_SQL = "CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE, version TEXT NOT NULL CHECK (version IN ('vulnerable', 'fixed')), state TEXT NOT NULL CHECK (state IN ('awaiting_approval', 'running', 'waiting_for_effects', 'completed', 'failed')), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, retention_until INTEGER NOT NULL, lease_id TEXT, lease_expires_at INTEGER, payload TEXT NOT NULL);";
const ADD_RETENTION_COLUMN_SQL = "ALTER TABLE audits ADD COLUMN retention_until INTEGER NOT NULL DEFAULT 0;";
const PURGE_INVALID_JSON_SQL = "DELETE FROM audits WHERE json_valid(payload) != 1;";
const PURGE_INCOMPATIBLE_AUDITS_SQL = "DELETE FROM audits WHERE retention_until <= 0 OR json_type(payload, '$.approvalExpiresAt') IS NOT 'text' OR json_type(payload, '$.retentionUntil') IS NOT 'text';";

export function createAuditDatabaseProvider(getBinding: () => D1Database | undefined) {
  let initializationPromise: Promise<void> | null = null;

  return async function getAuditDb() {
    const db = getBinding();
    if (!db) throw new Error("Arena's D1 binding is unavailable");
    initializationPromise ||= initializeAuditDatabase(db).catch((error) => {
      initializationPromise = null;
      throw error;
    });
    await initializationPromise;
    return db;
  };
}

export async function initializeAuditDatabase(db: D1Database) {
  await db.exec(CREATE_AUDITS_SQL);
  if (!await hasRetentionColumn(db)) {
    try {
      await db.exec(ADD_RETENTION_COLUMN_SQL);
    } catch (error) {
      if (!await hasRetentionColumn(db)) throw error;
    }
  }

  await db.exec(PURGE_INVALID_JSON_SQL);
  await db.exec(PURGE_INCOMPATIBLE_AUDITS_SQL);
  await db.exec("CREATE INDEX IF NOT EXISTS idx_audits_state_updated_at ON audits(state, updated_at);");
  await db.exec("CREATE INDEX IF NOT EXISTS idx_audits_expires_at ON audits(expires_at);");
  await db.exec("CREATE INDEX IF NOT EXISTS idx_audits_retention_until ON audits(retention_until);");
  await db.exec("CREATE TABLE IF NOT EXISTS audit_start_limits (bucket_key TEXT PRIMARY KEY, request_count INTEGER NOT NULL CHECK (request_count >= 1), reset_at INTEGER NOT NULL);");
  await db.exec("CREATE INDEX IF NOT EXISTS idx_audit_start_limits_reset_at ON audit_start_limits(reset_at);");
}

async function hasRetentionColumn(db: D1Database) {
  const columns = await db.prepare("PRAGMA table_info(audits)").all<{ name: string }>();
  return (columns.results || []).some(({ name }) => name === "retention_until");
}
