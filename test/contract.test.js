import assert from "node:assert/strict";
import test from "node:test";

import { buildContract } from "../src/contract.js";

test("buildContract carries MCP compliance and partial CuP user-consent score", () => {
  const contract = buildContract({
    scan: {
      generated_at: "2026-06-23T00:00:00.000Z",
      source: { url: "https://example.test", content_hash: "abc" },
      robots: { ok: true },
      sitemap: { ok: true },
      llms: { ok: true },
      page: { looksJsOnly: false },
      checks: [],
      readiness: { score: 91, level: "gold", critical_gaps: [] },
      mcp: {
        source: "mcp.json",
        discovered: true,
        name: "safe",
        tool_count: 1,
        spec_version: "2025-06-18",
        spec_version_compliant: true,
        tool_description_hash: "hash",
        dangerous_tools: [],
        unapproved_dangerous_tools: [],
      },
      agent_skills: { discovered: false },
    },
    missionReport: { tested: 2, passed: 2, failed: 0, results: [] },
  });

  assert.equal(contract.surface.mcp.spec_version_compliant, true);
  assert.equal(contract.surface.mcp.tool_description_hash, "hash");
  assert.equal(contract.cup.score, 1);
  assert.equal(Object.keys(contract.cup.dimensions).length, 6);
  assert.equal(contract.cup.user_consent.score, 1);
  assert.deepEqual(contract.cup.user_consent.violations, []);
});
