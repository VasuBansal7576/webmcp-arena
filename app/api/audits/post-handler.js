import { createHostedAudit, publicHostedAudit } from "../../../src/hosted-audit.js";
import {
  admitAuditStart,
  createApprovalCapability,
  ensureAuditSession,
  hashAuditIdempotency,
  sameOriginMutation,
} from "../../../src/audit-capability.js";

export function createAuditPostHandler(store, {
  now: currentTime = Date.now,
  createAuditId = () => crypto.randomUUID(),
} = {}) {
  return async function postAudit(request) {
    if (!sameOriginMutation(request)) {
      return Response.json({ error: "cross-origin audit creation is blocked" }, { status: 403 });
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return Response.json({ error: "request body must be JSON" }, { status: 400 });
    }
    const version = body?.version;
    const idempotencyKey = body?.idempotencyKey;
    if (version !== "vulnerable" && version !== "fixed") {
      return Response.json({ error: "version must be vulnerable or fixed" }, { status: 400 });
    }
    if (typeof idempotencyKey !== "string" || !/^[A-Za-z0-9_-]{8,128}$/.test(idempotencyKey)) {
      return Response.json({ error: "a valid idempotency key is required" }, { status: 400 });
    }

    let phase = "session initialization";
    try {
      const now = currentTime();
      const session = await ensureAuditSession(request);
      phase = "audit start admission";
      let admission;
      try {
        admission = await admitAuditStart({
          request,
          sessionHash: session.sessionHash,
          now,
          consume: store.consumeAuditStartLimit,
        });
      } catch (error) {
        console.error("Arena audit start admission failed closed", error);
        return unavailableAuditStartResponse(session.setCookie);
      }
      if (!admission.allowed) {
        return rateLimitedAuditStartResponse(admission.resetAt, now, session.setCookie, admission.scope);
      }

      phase = "idempotency lookup";
      const storageKey = await hashAuditIdempotency({ sessionHash: session.sessionHash, version, key: idempotencyKey });
      let existing = await store.loadAuditByIdempotencyKey(storageKey);
      if (existing) {
        if (existing.version !== version) {
          return Response.json({ error: "idempotency key conflicts with another audit" }, { status: 409 });
        }
        const replacement = await createApprovalCapability(session.sessionHash);
        if (await store.rotateApprovalCapability(existing, replacement.privateApproval, now)) {
          return auditResponse(existing, replacement.capability, session.setCookie);
        }
        existing = await store.loadAuditByIdempotencyKey(storageKey);
        return auditResponse(existing, null, session.setCookie);
      }

      phase = "approval capability creation";
      const approval = await createApprovalCapability(session.sessionHash);
      phase = "hosted audit preparation";
      const record = await createHostedAudit({
        id: createAuditId(),
        version,
        privateApproval: approval.privateApproval,
        now,
      });
      try {
        phase = "audit insertion";
        await store.insertAudit(record, storageKey);
      } catch (error) {
        existing = await store.loadAuditByIdempotencyKey(storageKey);
        if (!existing) throw error;
        const replacement = await createApprovalCapability(session.sessionHash);
        if (!await store.rotateApprovalCapability(existing, replacement.privateApproval, currentTime())) {
          existing = await store.loadAuditByIdempotencyKey(storageKey);
          return auditResponse(existing, null, session.setCookie);
        }
        return auditResponse(existing, replacement.capability, session.setCookie);
      }
      phase = "expired audit cleanup";
      const cleanup = await Promise.allSettled([
        store.pruneExpiredAudits(now),
        store.pruneExpiredAuditStartLimits(now),
      ]);
      for (const result of cleanup) {
        if (result.status === "rejected") console.warn("Arena background audit cleanup failed", result.reason);
      }
      return auditResponse(record, approval.capability, session.setCookie, 201);
    } catch (error) {
      console.error(`Arena audit creation failed during ${phase}`, error);
      return Response.json({ error: "Arena could not prepare the audit" }, { status: 500 });
    }
  };
}

async function auditResponse(record, approvalCapability, setCookie, status = 200) {
  const headers = new Headers({ "cache-control": "no-store", "content-type": "application/json" });
  if (setCookie) headers.set("set-cookie", setCookie);
  return new Response(JSON.stringify({ audit: await publicHostedAudit(record), approvalCapability }), { status, headers });
}

function rateLimitedAuditStartResponse(resetAt, now, setCookie, scope) {
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

function unavailableAuditStartResponse(setCookie) {
  const headers = auditStartHeaders(setCookie);
  headers.set("retry-after", "30");
  return new Response(JSON.stringify({
    error: "Arena is temporarily unable to accept new audits",
    code: "audit_start_temporarily_unavailable",
  }), { status: 503, headers });
}

function auditStartHeaders(setCookie) {
  const headers = new Headers({ "cache-control": "no-store", "content-type": "application/json" });
  if (setCookie) headers.set("set-cookie", setCookie);
  return headers;
}
