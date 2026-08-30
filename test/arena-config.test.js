import assert from "node:assert/strict";
import test from "node:test";

import { loadArenaConfig } from "../src/arena-config.js";

test("production configuration fails closed without trust secrets and issuers", () => {
  assert.throws(
    () => loadArenaConfig({ NODE_ENV: "production" }),
    /ARENA_SIGNING_SECRET/,
  );

  assert.throws(
    () => loadArenaConfig({
      NODE_ENV: "production",
      ARENA_SIGNING_SECRET: "production-signing-secret-with-at-least-32-characters",
      ARENA_TRUSTED_ISSUERS_JSON: JSON.stringify([{
        issuer: "https://agents.example",
        audience: "arena.example",
        jwksUri: "https://agents.example/.well-known/jwks.json",
      }]),
    }),
    /ARENA_OPERATOR_TOKEN/,
  );

  const config = loadArenaConfig({
    NODE_ENV: "production",
    ARENA_SIGNING_SECRET: "production-signing-secret-with-at-least-32-characters",
    ARENA_OPERATOR_TOKEN: "production-operator-token-with-at-least-32-characters",
    ARENA_ENABLE_REMOTE_EXECUTION: "true",
    ARENA_DATA_PATH: "/var/lib/arena/arena.sqlite",
    ARENA_TRUSTED_ISSUERS_JSON: JSON.stringify([{
      issuer: "https://agents.example",
      audience: "arena.example",
      jwksUri: "https://agents.example/.well-known/jwks.json",
      algorithms: ["EdDSA"],
    }]),
  });

  assert.deepEqual(
    {
      production: config.production,
      requireVerifiedAgents: config.requireVerifiedAgents,
      remoteExecutionEnabled: config.remoteExecutionEnabled,
      dataPath: config.dataPath,
      trustedIssuer: config.trustedIssuers[0].issuer,
    },
    {
      production: true,
      requireVerifiedAgents: true,
      remoteExecutionEnabled: true,
      dataPath: "/var/lib/arena/arena.sqlite",
      trustedIssuer: "https://agents.example",
    },
  );
});
