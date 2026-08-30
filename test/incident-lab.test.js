import assert from "node:assert/strict";
import test from "node:test";

import { createIncidentLab } from "../src/incident-lab.js";

test("the incident corpus ships vulnerable and fixed behavioral fixtures", () => {
  const lab = createIncidentLab({ now: () => new Date("2026-08-29T10:00:00.000Z") });
  const scenarios = lab.listScenarios();

  assert.ok(scenarios.length >= 7);
  for (const scenario of scenarios) {
    const vulnerable = lab.run({ scenarioId: scenario.id, version: "vulnerable", mode: "observe" });
    const fixed = lab.run({ scenarioId: scenario.id, version: "fixed", mode: "enforce" });
    assert.equal(vulnerable.report.verdict, "fail", `${scenario.id} must demonstrate a real failure`);
    assert.equal(fixed.report.verdict, "pass", `${scenario.id} must ship a passing repair fixture`);
  }
});

test("gym counterfactual shows what each enforcement mode changes", () => {
  const lab = createIncidentLab({ now: () => new Date("2026-08-29T10:00:00.000Z") });
  const expected = {
    observe: { status: "observed", execution_allowed: true },
    warn: { status: "warning", execution_allowed: true },
    challenge: { status: "challenge_required", execution_allowed: false },
    enforce: { status: "denied", execution_allowed: false },
  };

  for (const [mode, outcome] of Object.entries(expected)) {
    const run = lab.run({ scenarioId: "gym_waitlist", version: "vulnerable", mode });
    assert.deepEqual(run.enforcement, { mode, would_deny: true, ...outcome });
  }

  const run = lab.run({ scenarioId: "gym_waitlist", version: "vulnerable", mode: "enforce" });
  assert.ok(run.report.findings.some((finding) => finding.code === "booking_window_bypassed"));
  assert.ok(run.report.findings.some((finding) => finding.code === "resource_ownership_violated"));
  assert.equal(run.counterfactual.raw.agent_outcome, "another member removed");
  assert.equal(run.counterfactual.governed.agent_outcome, "mutation prevented");
});
