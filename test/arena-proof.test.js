import assert from "node:assert/strict";
import test from "node:test";

import { createArenaProof, generateArenaProofKeys, verifyArenaAttestation } from "../src/arena-proof.js";

test("Arena Proof produces independently verifiable Ed25519 attestations", () => {
  const keys = generateArenaProofKeys();
  const proof = createArenaProof({
    ...keys,
    issuer: "https://arena.example",
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
  });
  const attestation = proof.issue({
    kind: "arena.execution_receipt",
    tool_name: "book_flight",
    arguments_hash: "args-12000",
    effect_trace_hash: "trace-safe",
    decision: "allow",
  });

  assert.equal(attestation.proof.algorithm, "Ed25519");
  assert.equal(attestation.proof.issuer, "https://arena.example");
  assert.equal(attestation.proof.key_id, proof.keyId);
  assert.equal(proof.verify(attestation), true);
  assert.equal(verifyArenaAttestation(attestation, keys.publicKey), true);
  assert.equal(verifyArenaAttestation({ ...attestation, decision: "deny" }, keys.publicKey), false);
});

test("Arena Proof hash-links consecutive attestations", () => {
  const proof = createArenaProof({
    ...generateArenaProofKeys(),
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    id: sequenceIds(),
  });
  const first = proof.issue({ kind: "arena.boundary_attestation", audit_id: "audit_1", verdict: "fail" });
  const second = proof.issue({ kind: "arena.boundary_attestation", audit_id: "audit_2", verdict: "pass" });

  assert.equal(first.previous_attestation_hash, null);
  assert.equal(second.previous_attestation_hash, proof.hash(first));
  assert.equal(proof.verifyChain([first, second]).valid, true);
  assert.equal(proof.verifyChain([second, first]).valid, false);
});

function sequenceIds() {
  let value = 0;
  return () => `proof_${++value}`;
}
