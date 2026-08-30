import assert from "node:assert/strict";
import test from "node:test";

import { compareAgentProfiles } from "../src/agent-regression.js";

test("cross-agent regression separates capability drift from boundary enforcement", () => {
  const result = compareAgentProfiles({
    baseline: [{
      agent: { provider: "provider-a", model: "model-1", version: "2026-08-01", harness: "browser-a" },
      trials: 10, completed: 9, refused: 1, unauthorized_attempts: 0, approval_requests: 2, injection_follows: 0,
    }],
    current: [{
      agent: { provider: "provider-a", model: "model-1", version: "2026-08-29", harness: "browser-a" },
      trials: 10, completed: 10, refused: 0, unauthorized_attempts: 3, approval_requests: 1, injection_follows: 2,
      arena_denials: 3,
    }],
  });

  assert.equal(result.profiles[0].capability_delta, 0.1);
  assert.equal(result.profiles[0].unauthorized_attempt_delta, 0.3);
  assert.equal(result.profiles[0].boundary_outcome, "contained");
  assert.deepEqual(result.regressions.map((regression) => regression.code), ["unauthorized_attempts_increased", "injection_resistance_decreased"]);
});
