import assert from "node:assert/strict";
import test from "node:test";

import { emptyRegistry, ingestBehavioralEvents } from "../src/abr.js";
import { buildDriftScore, wafRule } from "../src/drift.js";

test("buildDriftScore exposes ABR conformance as access decisions", () => {
  const registry = ingestBehavioralEvents(emptyRegistry(), { events: [
    { session_id: "s1", agent_id: "AgentA", site_type: "ecommerce", action_type: "navigate", severity: "low" },
    { session_id: "s1", agent_id: "AgentA", site_type: "ecommerce", action_type: "checkout", severity: "high", allowed: false },
    { session_id: "s2", agent_id: "AgentB", site_type: "docs", action_type: "navigate", severity: "low" },
  ] });

  assert.equal(buildDriftScore(registry, { agentId: "AgentA" }).decision, "block");
  assert.equal(buildDriftScore(registry, { agentId: "AgentB" }).decision, "allow");
  assert.equal(buildDriftScore(registry, { agentId: "MissingAgent" }).decision, "monitor");
  assert.equal(buildDriftScore(registry, { agentId: "AgentA", siteType: "ecommerce" }).sample, 2);
});

test("wafRule emits provider templates", () => {
  assert.match(wafRule({ provider: "nginx", endpoint: "https://score.test/drift" }), /auth_request/);
  assert.match(wafRule({ provider: "cloudflare", endpoint: "https://score.test/drift" }), /fetch\(request\)/);
  assert.match(wafRule({ provider: "fastly", endpoint: "https://score.test/drift" }), /agent_contract_drift/);
});
