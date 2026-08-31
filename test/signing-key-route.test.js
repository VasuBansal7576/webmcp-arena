import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  getEvidenceSigningKeySet,
  getEvidenceSigningPublicKey,
  signEvidence,
  verifyEvidenceAttestation,
} from "../lib/evidence-signing.ts";
import nextConfig from "../next.config.ts";

test("the well-known rewrite exposes the same process-local development key used to sign evidence", async () => {
  const previous = process.env.ARENA_ALLOW_EPHEMERAL_SIGNING;
  process.env.ARENA_ALLOW_EPHEMERAL_SIGNING = "true";
  try {
    const rewrites = await nextConfig.rewrites();
    assert.deepEqual(rewrites, [
      {
        source: "/.well-known/arena-signing-key.json",
        destination: "/api/signing-key",
      },
      {
        source: "/.well-known/arena-signing-keys.json",
        destination: "/api/signing-keys",
      },
    ]);

    const evidence = { kind: "arena.route_test", version: 1 };
    const payloadHash = createHash("sha256")
      .update('{"kind":"arena.route_test","version":1}')
      .digest("base64url");
    const completionAt = new Date("2026-08-30T12:00:00.000Z");
    const attestation = await signEvidence(evidence, payloadHash, completionAt);
    const discovery = await getEvidenceSigningPublicKey();
    const keySet = await getEvidenceSigningKeySet();

    assert.equal(discovery.keySource, "ephemeral_development");
    assert.equal(attestation.issuedAt, completionAt.toISOString());
    assert.equal(discovery.keyId, attestation.keyId);
    assert.equal(keySet.kind, "arena.signing_key_set");
    assert.equal(keySet.version, 1);
    assert.equal(keySet.currentKeyId, discovery.keyId);
    assert.deepEqual(keySet.keys, [{
      keyId: discovery.keyId,
      status: "current",
      publicKey: discovery.publicKey,
    }]);
    assert.equal(await verifyEvidenceAttestation(evidence, attestation, discovery.publicKey), true);
  } finally {
    if (previous === undefined) delete process.env.ARENA_ALLOW_EPHEMERAL_SIGNING;
    else process.env.ARENA_ALLOW_EPHEMERAL_SIGNING = previous;
  }
});
