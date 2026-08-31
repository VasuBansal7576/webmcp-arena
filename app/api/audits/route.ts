import { createHostedAudit, publicHostedAudit } from "@/src/hosted-audit.js";
import {
  admitAuditStart,
  createApprovalCapability,
  ensureAuditSession,
  hashAuditIdempotency,
  sameOriginMutation,
} from "@/src/audit-capability.js";
import {
  consumeAuditStartLimit,
  insertAudit,
  loadAudit,
  loadAuditByIdempotencyKey,
  pruneExpiredAuditStartLimits,
  pruneExpiredAudits,
  rotateApprovalCapability,
} from "@/lib/audit-store";

export const runtime = "edge";

export async function POST(request: Request) {
  if (!sameOriginMutation(request)) return Response.json({ error: "cross-origin audit creation is blocked" }, { status: 403 });
  let body: { version?: unknown; idempotencyKey?: unknown };
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "request body must be JSON" }, { status: 400 });
  }
  const version = body.version;
  const idempotencyKey = body.idempotencyKey;
  if (version !== "vulnerable" && version !== "fixed") return Response.json({ error: "version must be vulnerable or fixed" }, { status: 400 });
  if (typeof idempotencyKey !== "string" || !/^[A-Za-z0-9_-]{8,128}$/.test(idempotencyKey)) {
    return Response.json({ error: "a valid idempotency key is required" }, { status: 400 });
  }

  let phase = "session initialization";
  try {
    const now = Date.now();
    const session = await ensureAuditSession(request);
    phase = "idempotency lookup";
    const storageKey = await hashAuditIdempotency({ sessionHash: session.sessionHash, version, key: idempotencyKey });
    let existing = await loadAuditByIdempotencyKey(storageKey);
    if (existing) {
      if (existing.version !== version) return Response.json({ error: "idempotency key conflicts with another audit" }, { status: 409 });
      const replacement = await createApprovalCapability(session.sessionHash);
      if (await rotateApprovalCapability(existing, replacement.privateApproval, now)) {
        return auditResponse(existing, replacement.capability, session.setCookie);
      }
      existing = await loadAuditByIdempotencyKey(storageKey);
      return auditResponse(existing, null, session.setCookie);
    }

    phase = "audit start admission";
    let admission: { allowed: true } | { allowed: false; resetAt: number; scope: string };
    try {
      admission = await admitAuditStart({
        request,
        sessionHash: session.sessionHash,
        now,
        consume: consumeAuditStartLimit,
      });
    } catch (error) {
      console.error("Arena audit start admission failed closed", error);
      return unavailableAuditStartResponse(session.setCookie);
    }
    if (!admission.allowed) return rateLimitedAuditStartResponse(admission.resetAt, now, session.setCookie, admission.scope);

    phase = "approval capability creation";
    const approval = await createApprovalCapability(session.sessionHash);
    phase = "hosted audit preparation";
    const record = await createHostedAudit({
      id: crypto.randomUUID(),
      version,
      privateApproval: approval.privateApproval,
      now,
    });
    try {
      phase = "audit insertion";
      await insertAudit(record, storageKey);
    } catch (error) {
      existing = await loadAuditByIdempotencyKey(storageKey);
      if (!existing) throw error;
      const replacement = await createApprovalCapability(session.sessionHash);
      if (!await rotateApprovalCapability(existing, replacement.privateApproval, Date.now())) {
        existing = await loadAuditByIdempotencyKey(storageKey);
        return auditResponse(existing, null, session.setCookie);
      }
      return auditResponse(existing, replacement.capability, session.setCookie);
    }
    phase = "expired audit cleanup";
    const cleanup = await Promise.allSettled([
      pruneExpiredAudits(now),
      pruneExpiredAuditStartLimits(now),
    ]);
    for (const result of cleanup) {
      if (result.status === "rejected") console.warn("Arena background audit cleanup failed", result.reason);
    }
    return auditResponse(record, approval.capability, session.setCookie, 201);
  } catch (error) {
    console.error(`Arena audit creation failed during ${phase}`, error);
    return Response.json({ error: "Arena could not prepare the audit" }, { status: 500 });
  }
}

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get("id") || "";
  if (!/^[0-9a-f-]{36}$/i.test(id)) return Response.json({ error: "a valid audit id is required" }, { status: 400 });
  try {
    const record = await loadAudit(id);
    return record ? noStore(await publicHostedAudit(record)) : Response.json({ error: "audit not found" }, { status: 404 });
  } catch (error) {
    console.error("Arena audit lookup failed", error);
    return Response.json({ error: "Arena could not load the audit" }, { status: 500 });
  }
}

async function auditResponse(record: Record<string, unknown>, approvalCapability: string | null, setCookie: string | null, status = 200) {
  const headers = new Headers({ "cache-control": "no-store", "content-type": "application/json" });
  if (setCookie) headers.set("set-cookie", setCookie);
  return new Response(JSON.stringify({ audit: await publicHostedAudit(record), approvalCapability }), { status, headers });
}

function noStore(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { "cache-control": "no-store" } });
}

function rateLimitedAuditStartResponse(resetAt: number, now: number, setCookie: string | null, scope: string) {
  const retryAfterSeconds = Math.max(1, Math.ceil((resetAt - now) / 1_000));
  const headers = auditStartHeaders(setCookie);
  headers.set("retry-after", String(retryAfterSeconds));
  return new Response(JSON.stringify({
    error: `audit start limit reached; retry in ${retryAfterSeconds} seconds`,
    code: "audit_start_rate_limited",
    retryAfterSeconds,
    limitScope: scope,
  }), { status: 429, headers });
}

function unavailableAuditStartResponse(setCookie: string | null) {
  const headers = auditStartHeaders(setCookie);
  headers.set("retry-after", "30");
  return new Response(JSON.stringify({
    error: "Arena is temporarily unable to accept new audits",
    code: "audit_start_temporarily_unavailable",
  }), { status: 503, headers });
}

function auditStartHeaders(setCookie: string | null) {
  const headers = new Headers({ "cache-control": "no-store", "content-type": "application/json" });
  if (setCookie) headers.set("set-cookie", setCookie);
  return headers;
}
