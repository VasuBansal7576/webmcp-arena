import assert from "node:assert/strict";
import test from "node:test";

import {
  getEvidenceSigningKeySetWithEnvironment,
  signEvidenceWithEnvironment,
} from "../lib/evidence-signing.ts";
import {
  parsePortableHostedAuditProof,
  PortableProofError,
  verifyPortableHostedAuditProof,
} from "../lib/portable-proof.ts";
import {
  readUtf8RequestBody,
  RequestBodyLimitError,
} from "../lib/request-body.ts";
import {
  completeHostedAudit,
  createHostedAudit,
} from "../src/hosted-audit.js";
import { createWebMcpInvocationReceipt } from "../src/webmcp-invocation.js";

const now = Date.parse("2026-08-31T10:00:00.000Z");
const environment = { ARENA_ALLOW_EPHEMERAL_SIGNING: "true" };
const privateApproval = Object.freeze({
  capabilityHash: "A".repeat(43),
  sessionHash: "B".repeat(43),
  nonceId: "nonce_portable_test_01",
});

test("a downloaded hosted proof verifies without loading its stored audit record", async () => {
  const record = await invoke(approve(await createHostedAudit({
    id: "44444444-4444-4444-8444-444444444444",
    version: "fixed",
    privateApproval,
    now,
  })), now + 1_500);
  const result = await completeHostedAudit(record, { now: now + 2_000 });
  const attestation = await signEvidenceWithEnvironment(
    result.evidence,
    result.payloadHash,
    environment,
    new Date(now + 2_000),
  );
  const proof = parsePortableHostedAuditProof({
    kind: "arena.portable_hosted_audit_proof",
    version: 1,
    auditId: record.id,
    approvalExpiresAt: record.approvalExpiresAt,
    retentionUntil: result.evidence.retentionUntil,
    evidence: result.evidence,
    payloadHash: result.payloadHash,
    attestation,
    trustRoot: "https://arena.example/.well-known/arena-signing-keys.json",
  });
  const verification = await verifyPortableHostedAuditProof(
    proof,
    await getEvidenceSigningKeySetWithEnvironment(environment),
  );

  assert.equal(verification.valid, true);
  assert.equal(verification.semanticValid, true);
  assert.equal(verification.signatureValid, true);
  assert.equal(verification.keyMatches, true);

  const tampered = structuredClone(proof);
  tampered.evidence.releaseVerdict = "fail";
  const rejected = await verifyPortableHostedAuditProof(
    parsePortableHostedAuditProof(tampered),
    await getEvidenceSigningKeySetWithEnvironment(environment),
  );
  assert.equal(rejected.valid, false);
  assert.equal(rejected.semanticValid, false);
  assert.equal(rejected.signatureValid, false);
});

test("portable proof parsing rejects extra fields and mismatched envelope commitments", async (t) => {
  const base = {
    kind: "arena.portable_hosted_audit_proof",
    version: 1,
    auditId: "55555555-5555-4555-8555-555555555555",
    approvalExpiresAt: "2026-08-31T10:10:00.000Z",
    retentionUntil: "2026-09-30T10:00:00.000Z",
    evidence: {
      auditId: "55555555-5555-4555-8555-555555555555",
      retentionUntil: "2026-09-30T10:00:00.000Z",
      approval: { expiresAt: "2026-08-31T10:10:00.000Z" },
    },
    payloadHash: "A".repeat(43),
    attestation: { payloadHash: "A".repeat(43) },
    trustRoot: "https://arena.example/.well-known/arena-signing-keys.json",
  };
  for (const [name, change, reason] of [
    ["extra field", (value) => { value.injected = true; }, "portable_proof_schema_invalid"],
    ["audit id", (value) => { value.evidence.auditId = "other"; }, "portable_proof_envelope_mismatch"],
    ["payload hash", (value) => { value.attestation.payloadHash = "B".repeat(43); }, "portable_proof_envelope_mismatch"],
    ["trust root", (value) => { value.trustRoot = "file:///tmp/key.json"; }, "portable_proof_schema_invalid"],
  ]) {
    await t.test(name, () => {
      const changed = structuredClone(base);
      change(changed);
      assert.throws(
        () => parsePortableHostedAuditProof(changed),
        (error) => error instanceof PortableProofError && error.reason === reason,
      );
    });
  }
});

test("streamed request bodies without Content-Length stay memory-bounded and drain cleanly", async () => {
  const maxBytes = 128 * 1024;
  const chunk = new Uint8Array(16 * 1024).fill(65);
  const totalChunks = 12;
  let pulls = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(chunk);
      if (pulls === totalChunks) controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://arena.example/api/audits/verify", {
    method: "POST",
    body,
    duplex: "half",
  });

  await assert.rejects(
    readUtf8RequestBody(request, maxBytes),
    (error) => error instanceof RequestBodyLimitError,
  );
  assert.equal(request.headers.has("content-length"), false);
  assert.equal(cancelled, false);
  assert.equal(pulls, totalChunks);
});

test("request-body limits accept valid Content-Length values with leading zeros", async () => {
  const request = new Request("https://arena.example/api/audits/verify", {
    method: "POST",
    headers: { "content-length": "0002" },
    body: "{}",
  });

  assert.equal(await readUtf8RequestBody(request, 2), "{}");
});

function approve(record) {
  record.state = "running";
  record.approval = {
    status: "approved",
    method: "one_time_interface_session_capability",
    approvedAt: new Date(now + 1_000).toISOString(),
    expiresAt: record.approvalExpiresAt,
    nonceId: privateApproval.nonceId,
    sessionCommitment: privateApproval.sessionHash,
    reviewerClaim: "same_origin_interface_session_controller",
    assuranceClaim: "session_capability_verified_human_presence_not_attested",
    reviewedReleaseHash: record.review.release.hash,
    reviewedAgentHash: record.review.agent.hash,
    reviewedPrincipalHash: record.review.principal.hash,
    reviewedToolDefinitionHash: record.review.toolDefinitionHash,
    reviewedToolHash: record.review.toolHash,
    reviewedArgumentsHash: record.review.argumentsHash,
    reviewedContractHash: record.review.contractHash,
    reviewedTargetHash: record.review.targetHash,
  };
  return record;
}

async function invoke(record, invokedAt) {
  record.state = "waiting_for_effects";
  record.invocation = await createWebMcpInvocationReceipt({
    auditId: record.id,
    review: record.review,
    approval: record.approval,
    pageOrigin: "https://arena.example",
    invocationLease: "77777777-7777-4777-8777-777777777777",
    invokedAt: new Date(invokedAt).toISOString(),
  });
  return record;
}
