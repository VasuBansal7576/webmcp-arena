import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { evaluatePolicyPack, writePolicyAudit } from "../src/policy.js";

test("evaluatePolicyPack reports pass/fail controls from contract evidence", () => {
  const good = evaluatePolicyPack(enterpriseContract(), enterprisePolicy());
  assert.equal(good.status, "passed");
  assert.equal(good.controls.every((control) => control.status === "passed"), true);

  const badContract = enterpriseContract({
    surface: { website: { has_llms_txt: false }, api: { has_error_examples: false, auth_methods: [] } },
    missions: { tested: 3, passed: 2, failed: 1 },
  });
  const bad = evaluatePolicyPack(badContract, enterprisePolicy());
  assert.equal(bad.status, "failed");
  assert.deepEqual(
    bad.controls.filter((control) => control.status === "failed").map((control) => control.id).sort(),
    ["api_auth_documented", "api_error_examples", "llms_txt_present", "synthetic_missions_pass"].sort(),
  );
});

test("evaluatePolicyPack emits MCP spec comparison and compliance delta", () => {
  const audit = evaluatePolicyPack(enterpriseContract({
    surface: {
      mcp: {
        discovered: true,
        spec_version: "2025-03-26",
        spec_version_compliant: false,
      },
    },
  }), enterprisePolicy());

  assert.equal(audit.mcp_compliance.current_spec, "2025-06-18");
  assert.equal(audit.mcp_compliance.spec_version_declared, "2025-03-26");
  assert.equal(audit.mcp_compliance.status, "outdated_or_missing");
  assert.ok(audit.mcp_compliance.compliance_delta > 0);
});

test("writePolicyAudit writes JSON and Markdown audit reports", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-policy-"));
  t.after(() => rm(dir, { recursive: true, force: true }));

  const result = await writePolicyAudit(dir, enterpriseContract(), enterprisePolicy());
  assert.equal(result.status, "passed");
  assert.deepEqual(result.files.sort(), ["compliance-report.md", "policy-audit.json"].sort());
  assert.match(await readFile(join(dir, "compliance-report.md"), "utf8"), /Enterprise Agent Contract Policy/);
  assert.equal(JSON.parse(await readFile(join(dir, "policy-audit.json"), "utf8")).status, "passed");
});

function enterprisePolicy() {
  return {
    name: "Enterprise Agent Contract Policy",
    controls: [
      { id: "robots_txt_present", require: "surface.website.has_robots_txt", equals: true, severity: "high" },
      { id: "llms_txt_present", require: "surface.website.has_llms_txt", equals: true, severity: "high" },
      { id: "readiness_score", require: "readiness.score", min: 80, severity: "high" },
      { id: "synthetic_missions_pass", require: "missions.failed", equals: 0, severity: "critical" },
      { id: "api_error_examples", require: "surface.api.has_error_examples", equals: true, severity: "medium" },
      { id: "api_auth_documented", require: "surface.api.auth_methods.length", min: 1, severity: "medium" },
    ],
  };
}

function enterpriseContract(overrides = {}) {
  const base = {
    source: { url: "https://example.test" },
    surface: {
      website: { has_robots_txt: true, has_llms_txt: true, has_sitemap: true },
      api: { has_error_examples: true, auth_methods: ["documented"] },
      mcp: { discovered: false, spec_version_compliant: true },
    },
    readiness: { score: 92, critical_gaps: [] },
    missions: { tested: 3, passed: 3, failed: 0 },
  };
  return merge(base, overrides);
}

function merge(base, overrides) {
  const out = structuredClone(base);
  for (const [key, value] of Object.entries(overrides)) {
    out[key] = value && typeof value === "object" && !Array.isArray(value) ? merge(out[key] || {}, value) : value;
  }
  return out;
}
