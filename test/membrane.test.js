import assert from "node:assert/strict";
import test from "node:test";

import { browserSnippet, buildMembraneBaseline, evaluateRuntimeObservation, observationFromHtml } from "../src/membrane.js";

test("buildMembraneBaseline carries page and high-risk zone hashes", () => {
  const baseline = buildMembraneBaseline(scanFixture());

  assert.equal(baseline.layer, "agent_session_membrane.layer1");
  assert.equal(baseline.page.content_hash, "sha256:clean-page");
  assert.deepEqual(baseline.watch_zones.map((zone) => zone.id), ["pricing", "ipi_risk_1"]);
  assert.equal(baseline.watch_zones.find((zone) => zone.id === "pricing").priority, "high");
});

test("evaluateRuntimeObservation emits page and region deviation events", () => {
  const baseline = buildMembraneBaseline(scanFixture());
  const clean = evaluateRuntimeObservation(baseline, { url: "https://example.test/", content_hash: "sha256:clean-page" });
  const changed = evaluateRuntimeObservation(baseline, {
    url: "https://example.test/",
    user_agent: "GPTBot/1.0",
    content_hash: "sha256:changed-page",
    regions: [{ id: "pricing", content_hash: "sha256:changed-pricing" }],
  });

  assert.equal(clean.status, "clean");
  assert.equal(changed.status, "deviation");
  assert.deepEqual(changed.events.map((event) => event.type), ["runtime_dom_deviation", "runtime_region_deviation"]);
  assert.equal(changed.events[0].user_agent, "GPTBot/1.0");
});

test("observationFromHtml and browserSnippet use SHA-256 content hashes", () => {
  const observation = observationFromHtml({ url: "https://example.test/", html: "<html>changed</html>" });
  const snippet = browserSnippet({ endpoint: "https://collector.example.test/events", siteId: "site_123" });

  assert.match(observation.content_hash, /^sha256:/);
  assert.match(snippet, /crypto\.subtle\.digest\("SHA-256"/);
  assert.match(snippet, /https:\/\/collector\.example\.test\/events/);
  assert.match(snippet, /site_123/);
});

function scanFixture() {
  return {
    source: { url: "https://example.test/", content_hash: "clean-page" },
    page: {
      critical_elements: [
        { id: "pricing", structural_risk: true, cpi: 0.52, content_hash: "sha256:clean-pricing" },
      ],
      ipi_risks: [
        { severity: "high", content_hash: "clean-ipi", snippet: "ignore previous instruction" },
      ],
    },
  };
}
