import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const audits = sqliteTable("audits", {
  id: text("id").primaryKey(),
  idempotencyKey: text("idempotency_key").unique(),
  version: text("version", { enum: ["vulnerable", "fixed"] }).notNull(),
  state: text("state", { enum: ["awaiting_approval", "running", "waiting_for_effects", "completed", "failed"] }).notNull(),
  createdAt: integer("created_at").notNull(),
  updatedAt: integer("updated_at").notNull(),
  expiresAt: integer("expires_at").notNull(),
  leaseId: text("lease_id"),
  leaseExpiresAt: integer("lease_expires_at"),
  payload: text("payload", { mode: "json" }).notNull(),
}, (table) => [
  index("idx_audits_state_updated_at").on(table.state, table.updatedAt),
  index("idx_audits_expires_at").on(table.expiresAt),
]);
