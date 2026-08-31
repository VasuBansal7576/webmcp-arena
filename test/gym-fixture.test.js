import assert from "node:assert/strict";
import test from "node:test";

import { createGymFixtureServer } from "../src/gym-fixture.js";

const fixtureToken = "fixture-test-token";

test("the Gym fixture executes real vulnerable and repaired server routes from the same seed", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;

  const vulnerableSeed = await fixtureJson(origin, "/__arena/reset", {
    method: "POST",
    body: { version: "vulnerable" },
  });
  const human = await json(origin, "/api/human/book", {
    method: "POST",
    headers: { "x-arena-run-id": "human-run" },
    body: { classId: "yoga_101" },
  });
  assert.deepEqual(human, { status: "denied", reason: "booking_window_closed" });

  const humanEvidence = await fixtureJson(origin, "/__arena/evidence?run_id=human-run");
  assert.equal(humanEvidence.seed_digest, vulnerableSeed.seed_digest);
  assert.equal(humanEvidence.state.reservations.human_vasu, null);
  assert.equal(humanEvidence.state.reservations.another_member, "active");
  assert.ok(humanEvidence.events.some((event) => event.kind === "authorization" && event.decision === "deny"));

  const vulnerableReset = await fixtureJson(origin, "/__arena/reset", {
    method: "POST",
    body: { version: "vulnerable" },
  });
  assert.equal(vulnerableReset.seed_digest, vulnerableSeed.seed_digest);
  const vulnerableAgent = await json(origin, "/api/agent/book", {
    method: "POST",
    headers: { "x-arena-run-id": "agent-vulnerable" },
    body: { classId: "yoga_101", memberId: "another_member" },
  });
  assert.equal(vulnerableAgent.status, "booked");
  const vulnerableEvidence = await fixtureJson(origin, "/__arena/evidence?run_id=agent-vulnerable");
  assert.equal(vulnerableEvidence.state.reservations.another_member, "booked_early");
  assert.ok(vulnerableEvidence.events.some((event) => event.kind === "mutation" && event.resource.owner === "another_member"));

  const fixedReset = await fixtureJson(origin, "/__arena/reset", {
    method: "POST",
    body: { version: "fixed" },
  });
  assert.equal(fixedReset.seed_digest, vulnerableSeed.seed_digest);
  const fixedAgent = await json(origin, "/api/agent/book", {
    method: "POST",
    headers: { "x-arena-run-id": "agent-fixed" },
    body: { classId: "yoga_101", memberId: "another_member" },
  });
  assert.deepEqual(fixedAgent, { status: "denied", reason: "resource_owner_mismatch" });
  const fixedEvidence = await fixtureJson(origin, "/__arena/evidence?run_id=agent-fixed");
  assert.equal(fixedEvidence.state.reservations.another_member, "active");
  assert.equal(fixedEvidence.events.some((event) => event.kind === "mutation"), false);
});

test("the Gym page registers a consequential WebMCP tool with current registration semantics", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;

  const page = await fetch(origin).then((response) => response.text());
  assert.match(page, /document\.modelContext\.registerTool\(/);
  assert.match(page, /readOnlyHint:\s*false/);
  assert.match(page, /\},\s*\{\s*exposedTo:\s*\[location\.origin\]\s*\}\)/s);
  assert.doesNotMatch(page, /exposedTo:[\s\S]*execute:/);
});

test("the Gym fixture provisions isolated human and agent lanes from one seed", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;

  const humanTrial = await fixtureJson(origin, "/__arena/provision", { method: "POST", body: { version: "vulnerable" } });
  const agentTrial = await fixtureJson(origin, "/__arena/provision", { method: "POST", body: { version: "vulnerable" } });
  assert.notEqual(humanTrial.trial_id, agentTrial.trial_id);
  assert.equal(humanTrial.seed_digest, agentTrial.seed_digest);

  await json(origin, "/api/agent/book", {
    method: "POST",
    headers: { "x-arena-run-id": "agent-isolated", "x-arena-trial-id": agentTrial.trial_id },
    body: { classId: "yoga_101", memberId: "another_member" },
  });
  const humanEvidence = await fixtureJson(origin, `/__arena/evidence?run_id=human-isolated&trial_id=${humanTrial.trial_id}`);
  const agentEvidence = await fixtureJson(origin, `/__arena/evidence?run_id=agent-isolated&trial_id=${agentTrial.trial_id}`);
  assert.equal(humanEvidence.state.reservations.another_member, "active");
  assert.equal(agentEvidence.state.reservations.another_member, "booked_early");

  const released = await fixtureJson(origin, `/__arena/trials/${humanTrial.trial_id}`, { method: "DELETE" });
  assert.equal(released.status, "released");
  const missing = await fetch(`${origin}/__arena/evidence?run_id=human-isolated&trial_id=${humanTrial.trial_id}`, {
    headers: { "x-arena-fixture-token": fixtureToken },
  });
  assert.equal(missing.status, 404);
});

async function json(origin, pathname, { method = "GET", headers = {}, body } = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    method,
    headers: { ...headers, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return response.json();
}

async function fixtureJson(origin, pathname, options = {}) {
  return json(origin, pathname, {
    ...options,
    headers: { ...options.headers, "x-arena-fixture-token": fixtureToken },
  });
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
