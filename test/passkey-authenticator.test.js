import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { createApprovalChallenge, createApprovalCommitments } from "../src/approval-envelope.js";
import { createPasskeyAuthenticator } from "../src/passkey-authenticator.js";

const NOW = "2026-08-30T10:00:10.000Z";
const RP_ID = "arena.example";
const ORIGIN = "https://arena.example";

test("a valid UV WebAuthn assertion verifies a registered reviewer and consumes its nonce", () => {
  const harness = createHarness();
  const commitments = approval({ nonceHash: "11".repeat(32) });
  const result = harness.authenticator.verify({ commitments, assertion: harness.assertion(commitments, { signCount: 8 }) });

  assert.deepEqual(result, {
    verified: true,
    claim: "registered_passkey_user_verified_by_this_arena_instance",
    arenaInstanceId: "arena-prod-1",
    reviewerId: "reviewer_local_7",
    challenge: createApprovalChallenge(commitments),
    verifiedAt: NOW,
    userPresent: true,
    userVerified: true,
    signCount: 8,
  });
});

test("an ES256 passkey assertion follows the same approval path", () => {
  const harness = createHarness({ keyType: "ec" });
  const commitments = approval({ nonceHash: "12".repeat(32) });
  const result = harness.authenticator.verify({ commitments, assertion: harness.assertion(commitments, { signCount: 8 }) });
  assert.equal(result.verified, true);
  assert.equal(result.userVerified, true);
});

test("changed approval fields invalidate the signed challenge", () => {
  for (const [field, value] of Object.entries({
    planId: "plan_changed",
    artifactHash: "21".repeat(32),
    targetHash: "22".repeat(32),
    toolHash: "23".repeat(32),
    argumentsHash: "24".repeat(32),
    contractHash: "25".repeat(32),
    reviewerId: "reviewer_local_8",
    nonceHash: "26".repeat(32),
    issuedAt: "2026-08-30T10:00:01.000Z",
    expiresAt: "2026-08-30T10:04:59.000Z",
  })) {
    const harness = createHarness();
    const signed = approval();
    const assertion = harness.assertion(signed, { signCount: 8 });
    assert.throws(
      () => harness.authenticator.verify({ commitments: { ...signed, [field]: value }, assertion }),
      { code: field === "reviewerId" ? "credential_owner_mismatch" : "challenge_mismatch" },
      field,
    );
  }
});

test("origin, RP ID, UV, expiry, replay, counter, and signature checks fail closed", async (t) => {
  await t.test("origin", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "31".repeat(32) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { origin: "https://evil.example", signCount: 8 }),
    }), { code: "origin_mismatch" });
  });

  await t.test("RP ID hash", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "32".repeat(32) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { rpId: "evil.example", signCount: 8 }),
    }), { code: "rp_id_mismatch" });
  });

  await t.test("user verification", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "33".repeat(32) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { flags: 0x01, signCount: 8 }),
    }), { code: "user_verification_required" });
  });

  await t.test("user presence", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "38".repeat(32) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { flags: 0x04, signCount: 8 }),
    }), { code: "user_presence_required" });
  });

  await t.test("expiration", () => {
    const harness = createHarness({ now: "2026-08-30T10:10:00.000Z" });
    const commitments = approval({ nonceHash: "34".repeat(32) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { signCount: 8 }),
    }), { code: "approval_expired" });
  });

  await t.test("nonce replay", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "35".repeat(32) });
    harness.authenticator.verify({ commitments, assertion: harness.assertion(commitments, { signCount: 8 }) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { signCount: 9 }),
    }), { code: "nonce_replayed" });
  });

  await t.test("monotonic counter", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "36".repeat(32) });
    assert.throws(() => harness.authenticator.verify({
      commitments,
      assertion: harness.assertion(commitments, { signCount: 7 }),
    }), { code: "signature_counter_not_advanced" });
  });

  await t.test("signature", () => {
    const harness = createHarness();
    const commitments = approval({ nonceHash: "37".repeat(32) });
    const assertion = harness.assertion(commitments, { signCount: 8 });
    assertion.response.signature = Buffer.from(assertion.response.signature, "base64url").subarray(0, 20).toString("base64url");
    assert.throws(() => harness.authenticator.verify({ commitments, assertion }), { code: "invalid_signature" });
  });
});

test("configuration rejects an allowed origin outside the relying-party boundary", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  assert.throws(() => createPasskeyAuthenticator({
    rpId: RP_ID,
    allowedOrigins: ["https://evil.example"],
    arenaInstanceId: "arena-prod-1",
    credentials: [{
      credentialId: Buffer.from("credential-7").toString("base64url"),
      reviewerId: "reviewer_local_7",
      publicKey,
    }],
  }), /must be the RP ID or one of its subdomains/);
});

function approval(overrides = {}) {
  return createApprovalCommitments({
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
    ...overrides,
  });
}

function createHarness({ now = NOW, keyType = "ed25519" } = {}) {
  const credentialId = Buffer.from("credential-7").toString("base64url");
  const { privateKey, publicKey } = keyType === "ec"
    ? generateKeyPairSync("ec", { namedCurve: "prime256v1" })
    : generateKeyPairSync("ed25519");
  const authenticator = createPasskeyAuthenticator({
    rpId: RP_ID,
    allowedOrigins: [ORIGIN],
    arenaInstanceId: "arena-prod-1",
    credentials: [{ credentialId, reviewerId: "reviewer_local_7", publicKey, signCount: 7 }],
    now: () => new Date(now),
  });

  function assertion(commitments, {
    origin = ORIGIN,
    rpId = RP_ID,
    flags = 0x05,
    signCount = 8,
  } = {}) {
    const clientDataJSON = Buffer.from(JSON.stringify({
      type: "webauthn.get",
      challenge: createApprovalChallenge(commitments),
      origin,
      crossOrigin: false,
    }));
    const authenticatorData = Buffer.alloc(37);
    createHash("sha256").update(rpId).digest().copy(authenticatorData, 0);
    authenticatorData[32] = flags;
    authenticatorData.writeUInt32BE(signCount, 33);
    const signedData = Buffer.concat([
      authenticatorData,
      createHash("sha256").update(clientDataJSON).digest(),
    ]);
    return {
      id: credentialId,
      type: "public-key",
      response: {
        clientDataJSON: clientDataJSON.toString("base64url"),
        authenticatorData: authenticatorData.toString("base64url"),
        signature: sign(keyType === "ec" ? "sha256" : null, signedData, privateKey).toString("base64url"),
      },
    };
  }

  return { authenticator, assertion };
}
