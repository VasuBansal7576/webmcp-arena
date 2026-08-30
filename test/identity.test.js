import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import { createTrustedIssuerVerifier } from "../src/identity.js";

test("a trusted issuer JWT cryptographically establishes the agent identity", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  publicJwk.kid = "issuer-key-1";
  publicJwk.alg = "EdDSA";
  publicJwk.use = "sig";
  const token = jwt({
    privateKey,
    header: { alg: "EdDSA", kid: "issuer-key-1", typ: "JWT" },
    payload: {
      iss: "https://agents.example",
      aud: "arena.example",
      sub: "agent-session-42",
      agent_id: "trusted-browser-agent",
      jti: "attestation-9",
      iat: 1787997540,
      exp: 1787997660,
    },
  });
  const verifier = createTrustedIssuerVerifier({
    issuers: [{
      issuer: "https://agents.example",
      audience: "arena.example",
      jwksUri: "https://agents.example/.well-known/jwks.json",
      algorithms: ["EdDSA"],
      agentIdClaim: "agent_id",
    }],
    now: () => new Date("2026-08-29T10:00:00.000Z"),
    fetch: async (url) => {
      assert.equal(url, "https://agents.example/.well-known/jwks.json");
      return new Response(JSON.stringify({ keys: [publicJwk] }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });

  const identity = await verifier.verifyAgentToken(token);

  assert.deepEqual(identity, {
    verified: true,
    issuer: "https://agents.example",
    subject: "agent-session-42",
    agent_id: "trusted-browser-agent",
    token_id: "attestation-9",
    algorithm: "EdDSA",
  });
});

function jwt({ privateKey, header, payload }) {
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}
