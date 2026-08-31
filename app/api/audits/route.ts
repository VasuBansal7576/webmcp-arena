import { publicHostedAudit } from "@/src/hosted-audit.js";
import {
  consumeAuditStartLimit,
  insertAudit,
  loadAudit,
  loadAuditByIdempotencyKey,
  pruneExpiredAuditStartLimits,
  pruneExpiredAudits,
  rotateApprovalCapability,
} from "@/lib/audit-store";
import { createAuditPostHandler } from "./post-handler.js";

export const runtime = "edge";

const handlePost = createAuditPostHandler({
  consumeAuditStartLimit,
  insertAudit,
  loadAuditByIdempotencyKey,
  pruneExpiredAuditStartLimits,
  pruneExpiredAudits,
  rotateApprovalCapability,
});

export function POST(request: Request) {
  return handlePost(request);
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

function noStore(value: unknown, status = 200) {
  return Response.json(value, { status, headers: { "cache-control": "no-store" } });
}
