import { claimInvocation, saveAudit } from "@/lib/audit-store";
import { signEvidence } from "@/lib/evidence-signing";
import { auditSessionFromRequest, hashCapability, sameOriginMutation } from "@/src/audit-capability.js";
import { completeHostedAudit, publicHostedAudit } from "@/src/hosted-audit.js";
import {
  createWebMcpInvocationReceipt,
  hashWebMcpInvocationArguments,
} from "@/src/webmcp-invocation.js";

export const runtime = "edge";

export async function POST(request: Request) {
  if (!sameOriginMutation(request) || request.headers.get("x-arena-webmcp-callback") !== "?1") {
    return failure("invocation_requires_registered_callback", "invocation requires Arena's same-origin registered WebMCP callback", 403);
  }
  let body: Record<string, unknown>;
  try {
    body = await request.json();
  } catch {
    return failure("invalid_json", "request body must be JSON", 400);
  }
  const auditId = typeof body.auditId === "string" ? body.auditId : "";
  const invocationLease = typeof body.invocationLease === "string" ? body.invocationLease : "";
  const toolName = typeof body.toolName === "string" ? body.toolName : "";
  const toolDefinitionHash = typeof body.toolDefinitionHash === "string" ? body.toolDefinitionHash : "";
  const args = body.arguments;
  if (!/^[0-9a-f-]{36}$/i.test(auditId) || !/^[0-9a-f-]{36}$/i.test(invocationLease) ||
      !args || typeof args !== "object" || Array.isArray(args)) {
    return failure("invalid_invocation", "audit id, invocation lease, and object arguments are required", 400);
  }
  const sessionId = auditSessionFromRequest(request);
  if (!sessionId) return failure("invocation_session_missing", "invocation session is missing or expired", 403);

  const now = Date.now();
  const argumentsHash = await hashWebMcpInvocationArguments(args);
  const sessionHash = await hashCapability(sessionId);
  const review = { toolName, toolDefinitionHash, argumentsHash };
  const approval = { sessionCommitment: sessionHash };
  let receipt;
  try {
    receipt = await createWebMcpInvocationReceipt({
      auditId,
      review,
      approval,
      pageOrigin: new URL(request.url).origin,
      invocationLease,
      invokedAt: new Date(now).toISOString(),
    });
  } catch {
    return failure("invocation_binding_invalid", "invocation does not match a reviewable WebMCP commitment", 400);
  }

  const claimed = await claimInvocation({ id: auditId, now, leaseId: invocationLease, sessionHash, receipt });
  if (claimed.status === "missing") return failure("audit_not_found", "audit not found", 404);
  if (claimed.status === "expired") return failure("invocation_lease_expired", "invocation lease expired; start a new audit", 410);
  if (claimed.status === "invalid") return failure("invocation_binding_mismatch", "lease, session, tool, definition, or arguments did not match the approved intent", 403);
  if (claimed.status !== "claimed" || !claimed.record || !claimed.leaseId) {
    return failure("invocation_already_consumed", "invocation lease was already consumed", 409);
  }

  const record = claimed.record;
  try {
    const generatedAt = new Date();
    const result = await completeHostedAudit(record, { now: generatedAt.getTime() });
    const attestation = await signEvidence(result.evidence, result.payloadHash, generatedAt);
    record.state = "completed";
    record.phase = "proof_signed";
    record.result = { ...result, attestation };
    record.updatedAt = generatedAt.toISOString();
    record.history = [...record.history, { state: "completed", at: record.updatedAt }];
    await saveAudit(record, { expectedState: "waiting_for_effects", leaseId: claimed.leaseId, releaseLease: true });
    return noStore({
      audit: await publicHostedAudit(record),
      toolResult: agentToolResult(result.evidence),
      nextAction: "verify_signed_proof",
      retryAfterMs: 0,
    });
  } catch (error) {
    console.error("Arena WebMCP callback execution failed", error);
    record.state = "failed";
    record.phase = "execution_failed";
    record.updatedAt = new Date().toISOString();
    record.history = [...record.history, { state: "failed", at: record.updatedAt }];
    try {
      await saveAudit(record, { expectedState: "waiting_for_effects", leaseId: claimed.leaseId, releaseLease: true });
    } catch (saveError) {
      console.error("Arena could not persist callback failure", saveError);
    }
    return failure("proof_generation_failed", "Arena could not produce a signed evidence bundle", 500);
  }
}

function agentToolResult(evidence: unknown) {
  if (!isObject(evidence) || !isObject(evidence.boundaryBundle) || !Array.isArray(evidence.boundaryBundle.events)) {
    return null;
  }
  for (const event of evidence.boundaryBundle.events) {
    if (isObject(event) && event.route === "agent" && isObject(event.payload) && event.payload.kind === "outcome") {
      return event.payload;
    }
  }
  return null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function failure(code: string, error: string, status: number) {
  return Response.json({ error, code, retryAfterMs: status >= 500 ? 1_000 : 0 }, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

function noStore(value: unknown) {
  return Response.json(value, { headers: { "cache-control": "no-store" } });
}
