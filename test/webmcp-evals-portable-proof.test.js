import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  getEvidenceSigningKeySetWithEnvironment,
  signEvidenceWithEnvironment,
} from "../lib/evidence-signing.ts";
import { runArenaCli } from "../src/arena-cli.js";
import { completeHostedAudit, createHostedAudit } from "../src/hosted-audit.js";
import { verifyPortableProof } from "../src/proof-gate.js";
import { createWebMcpInvocationReceipt } from "../src/webmcp-invocation.js";

const NOW = Date.parse("2026-08-31T10:00:00.000Z");
const ENVIRONMENT = { ARENA_ALLOW_EPHEMERAL_SIGNING: "true" };
const PRIVATE_APPROVAL = Object.freeze({
  capabilityHash: "A".repeat(43),
  sessionHash: "B".repeat(43),
  nonceId: "nonce_webmcp_eval_integration_01",
});

test("arena eval accepts a semantically valid Ed25519-signed portable boundary proof", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-eval-real-proof-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const proofPath = join(directory, "arena-proof.json");
  const record = approve(await createHostedAudit({
    id: "88888888-8888-4888-8888-888888888888",
    version: "fixed",
    privateApproval: PRIVATE_APPROVAL,
    now: NOW,
  }));
  await invoke(record, NOW + 1_500);
  const completed = await completeHostedAudit(record, { now: NOW + 2_000 });
  const attestation = await signEvidenceWithEnvironment(
    completed.evidence,
    completed.payloadHash,
    ENVIRONMENT,
    new Date(NOW + 2_000),
  );
  const proof = {
    kind: "arena.portable_hosted_audit_proof",
    version: 1,
    auditId: record.id,
    approvalExpiresAt: record.approvalExpiresAt,
    retentionUntil: completed.evidence.retentionUntil,
    evidence: completed.evidence,
    payloadHash: completed.payloadHash,
    attestation,
    trustRoot: "https://arena.example/.well-known/arena-signing-keys.json",
  };
  await writeFile(proofPath, JSON.stringify(proof));
  const keySet = await getEvidenceSigningKeySetWithEnvironment(ENVIRONMENT);
  const fixture = (name) => new URL(`../examples/webmcp-evals/${name}.json`, import.meta.url).pathname;

  const result = await runArenaCli([
    "eval",
    "--evals", fixture("evals"),
    "--results", fixture("results"),
    "--tools", fixture("tools"),
    "--observations", fixture("observations"),
    "--proof", proofPath,
  ], {
    verifyProof: (candidate) => verifyPortableProof(candidate, {
      fetchImpl: async () => new Response(JSON.stringify(keySet), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    }),
  });

  assert.equal(result.exitCode, 0, result.stdout || result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(report.verdict, "pass");
  assert.equal(report.layers.selection.passCount, 1);
  assert.equal(report.layers.guidance.status, "pass");
  assert.equal(report.layers.behavior.valid, true);
  assert.equal(report.layers.behavior.payloadHash, completed.payloadHash);

  const written = JSON.parse(await readFile(proofPath, "utf8"));
  written.evidence.releaseVerdict = "fail";
  await writeFile(proofPath, JSON.stringify(written));
  const tampered = await runArenaCli([
    "eval",
    "--evals", fixture("evals"),
    "--results", fixture("results"),
    "--tools", fixture("tools"),
    "--observations", fixture("observations"),
    "--proof", proofPath,
  ], {
    verifyProof: (candidate) => verifyPortableProof(candidate, {
      fetchImpl: async () => new Response(JSON.stringify(keySet), { status: 200 }),
    }),
  });
  assert.equal(tampered.exitCode, 1);
  assert.equal(JSON.parse(tampered.stdout).layers.behavior.status, "fail");
});

function approve(record) {
  record.state = "running";
  record.approval = {
    status: "approved",
    method: "one_time_interface_session_capability",
    approvedAt: new Date(NOW + 1_000).toISOString(),
    expiresAt: record.approvalExpiresAt,
    nonceId: PRIVATE_APPROVAL.nonceId,
    sessionCommitment: PRIVATE_APPROVAL.sessionHash,
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
    invocationLease: "99999999-9999-4999-8999-999999999999",
    invokedAt: new Date(invokedAt).toISOString(),
  });
}
