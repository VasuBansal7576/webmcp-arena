import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const audits = sqliteTable("audits", {
  id: text("id").primaryKey(),
  idempotencyKey: text("idempotency_key").unique(),
  version: text("version", { enum: ["vulnerable", "fixed"] }).notNull(),
  state: text("state", { enum: ["awaiting_approval", "running", "waiting_for_effects", "completed", "failed"] }).notNull(),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
  approvalExpiresAt: integer("expires_at").notNull(),
  retentionUntil: integer("retention_until").notNull(),
  leaseId: text("lease_id"),
  leaseExpiresAt: integer("lease_expires_at"),
  payload: text("payload", { mode: "json" }).notNull(),
}, (table) => [
  index("idx_audits_state_updated_at").on(table.state, table.updatedAt),
  index("idx_audits_expires_at").on(table.approvalExpiresAt),
  index("idx_audits_retention_until").on(table.retentionUntil),
]);

export const auditStartLimits = sqliteTable("audit_start_limits", {
  bucketKey: text("bucket_key").primaryKey(),
  requestCount: integer("request_count").notNull(),
  resetAt: integer("reset_at").notNull(),
}, (table) => [
  index("idx_audit_start_limits_reset_at").on(table.resetAt),
]);
