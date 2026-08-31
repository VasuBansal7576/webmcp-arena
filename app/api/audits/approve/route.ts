import { completeHostedAudit, publicHostedAudit } from "@/src/hosted-audit.js";
import {
  approvalCapabilityProof,
  auditSessionFromRequest,
  sameOriginMutation,
} from "@/src/audit-capability.js";
import { claimApproval, saveAudit } from "@/lib/audit-store";
import { signEvidence } from "@/lib/evidence-signing";

export const runtime = "edge";

export async function POST(request: Request) {
  if (!sameOriginMutation(request) || request.headers.get("x-arena-interface-confirmation") !== "?1") {
    return Response.json({ error: "approval requires the same-origin review interface" }, { status: 403 });
  }
  let body: { auditId?: unknown; approvalCapability?: unknown };
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "request body must be JSON" }, { status: 400 });
  }
  const auditId = typeof body.auditId === "string" ? body.auditId : "";
  const approvalCapability = typeof body.approvalCapability === "string" ? body.approvalCapability : "";
  if (!/^[0-9a-f-]{36}$/i.test(auditId)) return Response.json({ error: "a valid audit id is required" }, { status: 400 });

  const sessionId = auditSessionFromRequest(request);
  if (!sessionId) return Response.json({ error: "approval session is missing or expired" }, { status: 403 });

  const proof = await approvalCapabilityProof({ capability: approvalCapability, sessionId });
  if (!proof) {
    return Response.json({ error: "approval capability is invalid or belongs to another browser session" }, { status: 403 });
  }

  const claimed = await claimApproval({ id: auditId, now: Date.now(), proof });
  if (claimed.status === "missing") return Response.json({ error: "audit not found" }, { status: 404 });
  if (claimed.status === "expired") return Response.json({ error: "review window expired; start a new audit" }, { status: 410 });
  if (claimed.status === "completed") return noStore(await publicHostedAudit(claimed.record));
  if (claimed.status === "invalid") {
    return Response.json({ error: "approval capability is invalid or belongs to another browser session" }, { status: 403 });
  }
  if (claimed.status === "failed") {
    return Response.json({ error: "the prior fixture execution lease expired; start a new audit" }, { status: 409 });
  }
  if (claimed.status !== "claimed" || !claimed.record || !claimed.leaseId) {
    return Response.json({ error: "audit is already running or was already reviewed" }, { status: 409 });
  }

  const record = claimed.record;
  const leaseId = claimed.leaseId;
  let persistedState = "running";
  try {
    record.state = "waiting_for_effects";
    record.updatedAt = new Date().toISOString();
    record.history = [...record.history, { state: "waiting_for_effects", at: record.updatedAt }];
    await saveAudit(record, { expectedState: "running", leaseId });
    persistedState = "waiting_for_effects";

    const result = await completeHostedAudit(record);
    const attestation = await signEvidence(result.evidence, result.payloadHash);
    record.state = "completed";
    record.result = { ...result, attestation };
    record.updatedAt = new Date().toISOString();
    record.history = [...record.history, { state: "completed", at: record.updatedAt }];
    await saveAudit(record, { expectedState: "waiting_for_effects", leaseId, releaseLease: true });
    return noStore(await publicHostedAudit(record));
  } catch (error) {
    console.error("Arena audit execution failed", error);
    record.state = "failed";
    record.updatedAt = new Date().toISOString();
    record.history = [...record.history, { state: "failed", at: record.updatedAt }];
    try {
      await saveAudit(record, { expectedState: persistedState, leaseId, releaseLease: true });
    } catch (saveError) {
      console.error("Arena could not persist the failed audit state", saveError);
    }
    return Response.json({ error: "Arena could not produce a signed evidence bundle" }, { status: 500, headers: { "cache-control": "no-store" } });
  }
}

function noStore(value: unknown) {
  return Response.json(value, { headers: { "cache-control": "no-store" } });
}
