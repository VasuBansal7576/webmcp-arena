import assert from "node:assert/strict";
import test from "node:test";

import { emptyRegistry, ingestBehavioralEvents, registrySummary } from "../src/abr.js";

test("ingestBehavioralEvents stores sessions and weighted conformance scores", () => {
  const registry = ingestBehavioralEvents(emptyRegistry(), { events: [
    { session_id: "s1", agent_id: "GPTBot/1.0", site_id: "shop", action_type: "navigate", url: "https://shop.test/pricing", severity: "low" },
    { session_id: "s1", agent_id: "GPTBot/1.0", site_id: "shop", action_type: "submit_form", url: "https://shop.test/checkout", severity: "high" },
  ] }, {
    agents: {
      "GPTBot/1.0": {
        allowed_actions: ["navigate"],
        forbidden_paths: ["/checkout"],
      },
    },
  });

  assert.equal(Object.keys(registry.sessions).length, 1);
  assert.equal(registry.agents["GPTBot/1.0"].total_actions, 2);
  assert.equal(registry.agents["GPTBot/1.0"].conforming_actions, 1);
  assert.equal(registry.agents["GPTBot/1.0"].conformance_score, 0.25);
});

test("runtime deviation events are recorded without attributing agent conformance", () => {
  const registry = ingestBehavioralEvents(emptyRegistry(), { events: [
    { type: "runtime_dom_deviation", user_agent: "ClaudeBot/1.0", url: "https://docs.test/", severity: "high" },
  ] });
  const score = registrySummary(registry, "ClaudeBot/1.0");

  assert.equal(score.conformance_score, null);
  assert.equal(score.unknown_actions, 1);
  assert.equal(registry.sessions[Object.keys(registry.sessions)[0]].events[0].conformance.reason, "runtime_deviation_is_not_agent_intent");
});
