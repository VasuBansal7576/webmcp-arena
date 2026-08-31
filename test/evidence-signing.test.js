import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  getEvidenceSigningKeySetWithEnvironment,
  getEvidenceSigningPublicKeyWithEnvironment,
  resolveEvidenceSigningKey,
  signEvidenceWithEnvironment,
  verifyEvidenceAttestation,
} from "../lib/evidence-signing.ts";

const issuedAt = new Date("2026-08-30T12:00:00.000Z");
const bundle = {
  auditId: "11111111-1111-4111-8111-111111111111",
  routeParity: { status: "fail" },
};
const canonicalBundle = '{"auditId":"11111111-1111-4111-8111-111111111111","routeParity":{"status":"fail"}}';
const payloadHash = createHash("sha256").update(canonicalBundle).digest("base64url");

test("evidence signing fails closed unless ephemeral development keys are explicitly allowed", async () => {
  await assert.rejects(
    () => signEvidenceWithEnvironment(bundle, payloadHash, {}, issuedAt),
    /signing keys are not configured/,
  );
  await assert.rejects(
    () => signEvidenceWithEnvironment(bundle, payloadHash, { ARENA_ALLOW_EPHEMERAL_SIGNING: "TRUE" }, issuedAt),
    /signing keys are not configured/,
  );
  await assert.rejects(
    () => signEvidenceWithEnvironment(bundle, payloadHash, { ARENA_SIGNING_PRIVATE_JWK: "{}" }, issuedAt),
    /both signing keys/,
  );
});

test("explicit ephemeral signing covers every attestation statement field", async () => {
  const attestation = await signEvidenceWithEnvironment(
    bundle,
    payloadHash,
    { ARENA_ALLOW_EPHEMERAL_SIGNING: "true" },
    issuedAt,
  );

  assert.equal(attestation.kind, "arena.evidence_attestation");
  assert.equal(attestation.version, 1);
  assert.equal(attestation.algorithm, "Ed25519");
  assert.equal(attestation.payloadHash, payloadHash);
  assert.match(attestation.keyId, /^ed25519:[A-Za-z0-9_-]{43}$/);
  assert.equal(attestation.issuedAt, issuedAt.toISOString());
  assert.equal(attestation.keySource, "ephemeral_development");
  assert.equal(attestation.publicKey.kty, "OKP");
  assert.equal(attestation.publicKey.crv, "Ed25519");
  assert.equal("d" in attestation.publicKey, false);
  assert.equal(await verifyEvidenceAttestation(bundle, attestation, attestation.publicKey), true);

  for (const change of [
    { payloadHash: "A".repeat(43) },
    { keyId: `ed25519:${"A".repeat(43)}` },
    { algorithm: "Ed448" },
    { issuedAt: "2026-08-30T12:00:01.000Z" },
    { keySource: "configured" },
  ]) {
    assert.equal(
      await verifyEvidenceAttestation(bundle, { ...attestation, ...change }, attestation.publicKey),
      false,
      `mutating ${Object.keys(change)[0]} must invalidate the attestation`,
    );
  }
  assert.equal(
    await verifyEvidenceAttestation({ ...bundle, injected: true }, attestation, attestation.publicKey),
    false,
  );
});

test("configured signing validates the Ed25519 pair and returns only public parameters", async () => {
  const configured = await generateJwkPair();
  const publicWithPrivateMaterial = { ...configured.publicJwk, d: configured.privateJwk.d, p: "must-not-leak" };
  const environment = {
    ARENA_SIGNING_PRIVATE_JWK: JSON.stringify(configured.privateJwk),
    ARENA_SIGNING_PUBLIC_JWK: JSON.stringify(publicWithPrivateMaterial),
  };
  const attestation = await signEvidenceWithEnvironment(bundle, payloadHash, environment, issuedAt);
  const discovery = await getEvidenceSigningPublicKeyWithEnvironment(environment);

  assert.equal(attestation.keySource, "configured");
  assert.equal(discovery.kind, "arena.signing_key");
  assert.equal(discovery.version, 1);
  assert.equal(discovery.algorithm, "Ed25519");
  assert.equal(discovery.keyId, attestation.keyId);
  assert.deepEqual(discovery.publicKey, attestation.publicKey);
  assert.deepEqual(Object.keys(attestation.publicKey).sort(), ["alg", "crv", "ext", "key_ops", "kty", "x"]);
  assert.equal("d" in attestation.publicKey, false);
  assert.equal("p" in attestation.publicKey, false);
  assert.equal(await verifyEvidenceAttestation(bundle, attestation, configured.publicJwk), true);

  const other = await generateJwkPair();
  await assert.rejects(
    () => signEvidenceWithEnvironment(bundle, payloadHash, {
      ARENA_SIGNING_PRIVATE_JWK: JSON.stringify(configured.privateJwk),
      ARENA_SIGNING_PUBLIC_JWK: JSON.stringify(other.publicJwk),
    }, issuedAt),
    /signing key pair does not match/,
  );
  assert.equal(await verifyEvidenceAttestation(bundle, attestation, other.publicJwk), false);
});

test("public key discovery refuses unconfigured identities and shares an explicitly enabled process-local development key", async () => {
  await assert.rejects(
    () => getEvidenceSigningPublicKeyWithEnvironment({}),
    /signing identity is unavailable/,
  );
  const environment = { ARENA_ALLOW_EPHEMERAL_SIGNING: "true" };
  const attestation = await signEvidenceWithEnvironment(bundle, payloadHash, environment, issuedAt);
  const first = await getEvidenceSigningPublicKeyWithEnvironment(environment);
  const second = await getEvidenceSigningPublicKeyWithEnvironment(environment);

  assert.equal(first.keySource, "ephemeral_development");
  assert.equal(first.keyId, attestation.keyId);
  assert.deepEqual(second, first);
  assert.equal(
    await verifyEvidenceAttestation(bundle, attestation, first.publicKey),
    true,
  );
});

test("signing refuses a caller-provided payload hash that does not match the bundle", async () => {
  await assert.rejects(
    () => signEvidenceWithEnvironment(
      bundle,
      "A".repeat(43),
      { ARENA_ALLOW_EPHEMERAL_SIGNING: "true" },
      issuedAt,
    ),
    /payload hash does not match/,
  );
});

test("a rotated proof remains verifiable only while its retired public key is in the trusted archive", async () => {
  const retired = await generateJwkPair();
  const current = await generateJwkPair();
  const retiredEnvironment = configuredEnvironment(retired);
  const currentEnvironment = configuredEnvironment(current);
  const retiredAttestation = await signEvidenceWithEnvironment(bundle, payloadHash, retiredEnvironment, issuedAt);

  const trustedAfterRotation = await getEvidenceSigningKeySetWithEnvironment({
    ...currentEnvironment,
    ARENA_SIGNING_ARCHIVED_PUBLIC_JWKS: JSON.stringify([
      retired.publicJwk,
      retired.publicJwk,
      current.publicJwk,
    ]),
  });
  const retiredTrustKey = resolveEvidenceSigningKey(trustedAfterRotation, retiredAttestation);

  assert.equal(
    trustedAfterRotation.currentKeyId,
    (await getEvidenceSigningPublicKeyWithEnvironment(currentEnvironment)).keyId,
  );
  assert.equal(trustedAfterRotation.keys.length, 2, "current and duplicate archived keys must be deduplicated");
  assert.equal(retiredTrustKey?.status, "archived");
  assert.equal(
    await verifyEvidenceAttestation(bundle, retiredAttestation, retiredTrustKey?.publicKey),
    true,
  );

  const withoutHistory = await getEvidenceSigningKeySetWithEnvironment(currentEnvironment);
  assert.equal(resolveEvidenceSigningKey(withoutHistory, retiredAttestation), null);
  assert.equal(resolveEvidenceSigningKey(withoutHistory, { keyId: `ed25519:${"A".repeat(43)}` }), null);
});

test("archived signing history is validated and fails closed when malformed or oversized", async () => {
  const current = await generateJwkPair();
  const environment = configuredEnvironment(current);

  for (const archived of ["{}", "[{}]", JSON.stringify(Array.from({ length: 65 }, () => current.publicJwk))]) {
    await assert.rejects(
      () => getEvidenceSigningKeySetWithEnvironment({
        ...environment,
        ARENA_SIGNING_ARCHIVED_PUBLIC_JWKS: archived,
      }),
      /signing key set is unavailable/,
    );
  }
});

async function generateJwkPair() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  return {
    privateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey),
    publicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
  };
}

function configuredEnvironment(pair) {
  return {
    ARENA_SIGNING_PRIVATE_JWK: JSON.stringify(pair.privateJwk),
    ARENA_SIGNING_PUBLIC_JWK: JSON.stringify(pair.publicJwk),
  };
}
