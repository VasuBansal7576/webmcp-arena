import { env } from "cloudflare:workers";

let initialized = false;

export async function getAuditDb() {
  if (!env.DB) throw new Error("Arena's D1 binding is unavailable");
  if (!initialized) {
    await env.DB.exec("CREATE TABLE IF NOT EXISTS audits (id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE, version TEXT NOT NULL CHECK (version IN ('vulnerable', 'fixed')), state TEXT NOT NULL CHECK (state IN ('awaiting_approval', 'running', 'waiting_for_effects', 'completed', 'failed')), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, lease_id TEXT, lease_expires_at INTEGER, payload TEXT NOT NULL);");
    await env.DB.exec("CREATE INDEX IF NOT EXISTS idx_audits_state_updated_at ON audits(state, updated_at);");
    await env.DB.exec("CREATE INDEX IF NOT EXISTS idx_audits_expires_at ON audits(expires_at);");
    initialized = true;
  }
  return env.DB;
}
