import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import ts from "typescript";

test("completed WebMCP status stays compact and points to the full signed evidence", async () => {
  const pageSource = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const agentAuditStatus = loadAgentAuditStatus(pageSource);
  const audit = auditRecord("completed");
  const original = structuredClone(audit);

  const status = agentAuditStatus(audit);
  const serialized = JSON.stringify(status);

  assert.ok(Buffer.byteLength(serialized) < 4_096, `status was ${Buffer.byteLength(serialized)} bytes`);
  assert.equal(status.state, "completed");
  assert.equal(status.nextAction, "verify_signed_proof");
  assert.equal(status.approval.required, false);
  assert.equal(status.outcome.verdict, "fail");
  assert.equal(status.outcome.findingCount, 1);
  assert.equal(status.evidence.signedEvidenceUrl, "/api/audits?id=audit%2Fwith%20spaces");
  assert.equal(status.evidence.verificationUrl, "/api/audits/verify?id=audit%2Fwith%20spaces");
  assert.equal(serialized.includes("large-private-evidence"), false);
  assert.equal(serialized.includes("approvalCapability"), false);
  assert.deepEqual(audit, original, "the compact response must not strip the UI's full audit record");
});

test("pending WebMCP status sends approval to the visible exact-intent review", async () => {
  const pageSource = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  const agentAuditStatus = loadAgentAuditStatus(pageSource);
  const audit = auditRecord("awaiting_approval");
  audit.result = null;

  const status = agentAuditStatus(audit);

  assert.equal(status.nextAction, "review_and_approve_in_visible_interface");
  assert.deepEqual(status.approval, {
    required: true,
    method: "visible_interface_only",
    expiresAt: "2026-08-31T12:10:00.000Z",
  });
  assert.equal(status.evidence.visibleReviewUrl, "/#proof-title");
  assert.equal("outcome" in status, false);
  assert.match(pageSource, /adoptAudit\(response\.audit\);\s*return agentAuditStatus\(response\.audit\);/);
  assert.doesNotMatch(pageSource, /\bnative WebMCP\b/i);
});

function loadAgentAuditStatus(source) {
  const parsed = ts.createSourceFile("page.tsx", source, ts.ScriptTarget.ESNext, true, ts.ScriptKind.TSX);
  const declaration = parsed.statements.find((statement) =>
    ts.isFunctionDeclaration(statement) && statement.name?.text === "agentAuditStatus"
  );
  assert.ok(declaration, "agentAuditStatus function was not found");
  const compiled = ts.transpileModule(declaration.getText(parsed), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None },
  }).outputText;
  return Function(`"use strict"; ${compiled}; return agentAuditStatus;`)();
}

function auditRecord(state) {
  return {
    id: "audit/with spaces",
    state,
    approvalExpiresAt: "2026-08-31T12:10:00.000Z",
    retentionUntil: "2026-09-30T12:00:00.000Z",
    review: {
      releaseHash: "R".repeat(43),
      toolName: "place_order",
      toolDefinitionHash: "D".repeat(43),
      argumentsHash: "A".repeat(43),
      targetHash: "T".repeat(43),
      contractHash: "C".repeat(43),
      agentHash: "G".repeat(43),
    },
    result: {
      verdict: "fail",
      selectedToolVerdict: "fail",
      bundle: { routeParity: { status: "fail" }, baselineSafety: { status: "pass" } },
      display: { settlement: { complete: true }, humanEvents: [], agentEvents: [] },
      findings: [{ code: "approval_bypassed", detail: "large-private-evidence".repeat(2_000) }],
      payloadHash: "P".repeat(43),
      attestation: { keyId: "arena-key-2026" },
      evidence: { body: "large-private-evidence".repeat(2_000) },
    },
  };
}
