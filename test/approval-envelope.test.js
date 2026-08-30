import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";

import {
  createApprovalChallenge,
  createApprovalCommitments,
  createApprovalEnvelopeIssuer,
  verifyApprovalEnvelope,
} from "../src/approval-envelope.js";

const HASH = {
  planId: "plan_checkout_42",
  artifactHash: "01".repeat(32),
  targetHash: "02".repeat(32),
  toolHash: "03".repeat(32),
  argumentsHash: "04".repeat(32),
  contractHash: "05".repeat(32),
  reviewerId: "reviewer_local_7",
  nonceHash: "06".repeat(32),
  issuedAt: "2026-08-30T10:00:00.000Z",
  expiresAt: "2026-08-30T10:05:00.000Z",
};

test("the approval challenge binds every security-relevant field", () => {
  const base = createApprovalCommitments(HASH);
  const challenge = createApprovalChallenge(base);
  const changes = {
    planId: "plan_checkout_43",
    artifactHash: "11".repeat(32),
    targetHash: "12".repeat(32),
    toolHash: "13".repeat(32),
    argumentsHash: "14".repeat(32),
    contractHash: "15".repeat(32),
    reviewerId: "reviewer_local_8",
    nonceHash: "16".repeat(32),
    issuedAt: "2026-08-30T10:00:01.000Z",
    expiresAt: "2026-08-30T10:05:01.000Z",
  };

  for (const [field, value] of Object.entries(changes)) {
    const changed = createApprovalCommitments({ ...HASH, [field]: value });
    assert.notEqual(createApprovalChallenge(changed), challenge, `${field} must be bound to the challenge`);
  }
});

test("Arena issues a minimal Ed25519 approval envelope after passkey verification", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const commitments = createApprovalCommitments(HASH);
  const challenge = createApprovalChallenge(commitments);
  const issuer = createApprovalEnvelopeIssuer({
    privateKey,
    publicKey,
    issuer: "https://arena.example",
    arenaInstanceId: "arena-prod-1",
    now: () => new Date("2026-08-30T10:00:10.000Z"),
    id: () => "approval_1",
    verifyPasskeyAssertion: ({ assertion }) => ({
      verified: assertion.approved,
      claim: "registered_passkey_user_verified_by_this_arena_instance",
      arenaInstanceId: "arena-prod-1",
      reviewerId: HASH.reviewerId,
      challenge,
      verifiedAt: "2026-08-30T10:00:09.000Z",
      credentialId: "must-not-leak",
      assertion: { clientDataJSON: "must-not-leak" },
    }),
  });

  const envelope = issuer.issue({
    commitments,
    assertion: { approved: true, clientDataJSON: "must-not-leak" },
  });

  assert.equal(envelope.kind, "arena.passkey_approval");
  assert.equal(envelope.assurance.claim, "registered_passkey_user_verified_by_this_arena_instance");
  assert.deepEqual(envelope.commitments, commitments);
  assert.equal(verifyApprovalEnvelope(envelope, publicKey), true);
  assert.equal(issuer.verify(envelope), true);

  const serialized = JSON.stringify(envelope);
  assert.doesNotMatch(serialized, /must-not-leak|clientDataJSON|credentialId|assertion/);
  assert.equal(verifyApprovalEnvelope({ ...envelope, commitments: { ...commitments, argumentsHash: "44".repeat(32) } }, publicKey), false);
});

test("approval envelope issuance invokes its trusted verifier and fails closed", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const commitments = createApprovalCommitments(HASH);
  const unverifiedIssuer = createApprovalEnvelopeIssuer({
    privateKey,
    issuer: "https://arena.example",
    arenaInstanceId: "arena-prod-1",
    now: () => new Date("2026-08-30T10:00:10.000Z"),
    verifyPasskeyAssertion: () => ({ verified: false }),
  });

  assert.throws(() => unverifiedIssuer.issue({ commitments, assertion: {} }), { code: "passkey_not_verified" });
  const mismatchedIssuer = createApprovalEnvelopeIssuer({
    privateKey,
    issuer: "https://arena.example",
    arenaInstanceId: "arena-prod-1",
    now: () => new Date("2026-08-30T10:00:10.000Z"),
    verifyPasskeyAssertion: () => ({
      verified: true,
      claim: "registered_passkey_user_verified_by_this_arena_instance",
      arenaInstanceId: "another-arena",
      reviewerId: HASH.reviewerId,
      challenge: createApprovalChallenge(commitments),
    }),
  });
  assert.throws(() => mismatchedIssuer.issue({
    commitments,
    assertion: {},
  }), { code: "arena_instance_mismatch" });
});
