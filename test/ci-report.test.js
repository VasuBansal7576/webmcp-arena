import assert from "node:assert/strict";
import test from "node:test";

import { buildCiArtifacts } from "../src/ci-report.js";

test("Arena CI exports JSON, JUnit, and SARIF from behavioral findings", () => {
  const artifacts = buildCiArtifacts({
    reports: [{
      id: "audit_1",
      verdict: "fail",
      contract: { tool_name: "preview_order" },
      findings: [{
        code: "read_only_contract_violated",
        severity: "critical",
        title: "Read-only contract performed a write",
        root_cause: "The tool created an order.",
        evidence: "POST https://shop.example/api/orders",
        recommended_repair: "Enforce the invariant on the server.",
      }],
    }],
  });

  assert.equal(artifacts.summary.passed, false);
  assert.equal(artifacts.summary.critical, 1);
  assert.match(artifacts.junit, /failures="1"/);
  assert.match(artifacts.junit, /preview_order/);
  assert.equal(artifacts.sarif.runs[0].results[0].ruleId, "read_only_contract_violated");
  assert.equal(artifacts.sarif.runs[0].results[0].level, "error");
  assert.equal(artifacts.json.reports[0].id, "audit_1");
});

test("Arena CI passes a clean behavioral report", () => {
  const artifacts = buildCiArtifacts({ reports: [{ id: "audit_2", verdict: "pass", contract: { tool_name: "join_waitlist" }, findings: [] }] });
  assert.deepEqual(artifacts.summary, { passed: true, reports: 1, findings: 0, critical: 0, high: 0, medium: 0, low: 0 });
  assert.match(artifacts.junit, /failures="0"/);
  assert.deepEqual(artifacts.sarif.runs[0].results, []);
});

test("Arena CI fails closed when no audits ran or evidence is inconclusive", () => {
  const empty = buildCiArtifacts({ reports: [] });
  const inconclusive = buildCiArtifacts({ reports: [{ id: "audit_3", verdict: "inconclusive", findings: [], inconclusive_reasons: ["instrumentation_missing"] }] });

  assert.equal(empty.summary.passed, false);
  assert.equal(empty.summary.reports, 0);
  assert.equal(inconclusive.summary.passed, false);
  assert.match(inconclusive.junit, /<error/);
  assert.equal(inconclusive.sarif.runs[0].results[0].ruleId, "arena_inconclusive");
});
