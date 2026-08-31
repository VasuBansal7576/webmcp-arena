import { getAuditDb } from "@/db";
import { createAuditStore } from "@/src/audit-store-core.js";

const store = createAuditStore(getAuditDb);

type AuditRecord = {
  state: string;
  updatedAt: string;
  history: Array<Record<string, unknown>>;
  result: unknown;
  [key: string]: unknown;
};

type ApprovalClaimResult =
  | { status: "claimed"; record: AuditRecord; leaseId: string }
  | { status: "completed" | "conflict" | "expired" | "failed" | "invalid"; record: AuditRecord | null; leaseId: null }
  | { status: "missing"; record: null; leaseId: null };

type InvocationReceipt = {
  auditId: string;
  toolName: string;
  toolDefinitionHash: string;
  argumentsHash: string;
  sessionCommitment: string;
  invokedAt: string;
  [key: string]: unknown;
};

type InvocationClaimResult =
  | { status: "claimed"; record: AuditRecord; leaseId: string }
  | { status: "completed" | "conflict" | "expired" | "failed" | "invalid"; record: AuditRecord | null; leaseId: null }
  | { status: "missing"; record: null; leaseId: null };

export const claimApproval: (input: {
  id: string;
  now: number;
  proof: { capabilityHash: string; sessionHash: string };
}) => Promise<ApprovalClaimResult> = store.claimApproval;
export const claimInvocation: (input: {
  id: string;
  now: number;
  leaseId: string;
  sessionHash: string;
  receipt: InvocationReceipt;
}) => Promise<InvocationClaimResult> = store.claimInvocation;
export const consumeAuditStartLimit: (input: {
  bucketKey: string;
  now: number;
  limit: number;
  windowMs: number;
}) => Promise<{ allowed: boolean; resetAt: number }> = store.consumeAuditStartLimit;
export const insertAudit = store.insertAudit;
export const loadAudit = store.loadAudit;
export const loadAuditByIdempotencyKey = store.loadAuditByIdempotencyKey;
export const pruneExpiredAudits = store.pruneExpiredAudits;
export const pruneExpiredAuditStartLimits: (now: number, limit?: number) => Promise<number> = store.pruneExpiredAuditStartLimits;
export const rotateApprovalCapability = store.rotateApprovalCapability;
export const saveAudit = store.saveAudit;
