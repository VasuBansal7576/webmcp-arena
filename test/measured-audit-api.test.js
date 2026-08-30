import assert from "node:assert/strict";
import test from "node:test";

import { createArenaServer } from "../scripts/arena-server.js";

test("the guided Checkout API runs vulnerable and fixed measured audits from server-owned presets", async (t) => {
  const server = createArenaServer({ secret: "measured-audit-api-test-secret-with-entropy" });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const vulnerable = await start(origin, {
    presetId: "checkout_vulnerable",
    idempotencyKey: "checkout-vulnerable-1",
  });
  assert.equal(vulnerable.response.status, 201);
  assert.equal(vulnerable.body.state, "awaiting_approval");
  assert.equal(vulnerable.body.review.toolName, "preview_checkout");
  assert.equal(vulnerable.body.review.claimScope, "owned_fixture:checkout");
  assert.equal(Object.hasOwn(vulnerable.body, "execution"), false);

  const repeated = await start(origin, {
    presetId: "checkout_vulnerable",
    idempotencyKey: "checkout-vulnerable-1",
  });
  assert.equal(repeated.body.id, vulnerable.body.id);

  const approved = await post(origin, `/api/measured-audits/${vulnerable.body.id}/approve`, {
    humanId: "human_demo_reviewer",
  });
  assert.equal(approved.response.status, 200);
  assert.equal(approved.body.state, "completed");
  assert.equal(approved.body.result.verdict, "fail");
  assert.equal(approved.body.result.assurance.tier, "server_attested");
  assert.ok(approved.body.result.findings.some(({ code }) => code === "unexpected_consequential_effect"));
  assert.ok(approved.body.result.bundle.events.some(({ route, payload }) =>
    route === "agent" && payload.kind === "money" && payload.amount === 149));
  assert.ok(approved.body.result.bundle.events.some(({ route, payload }) =>
    route === "agent" && payload.kind === "effect_settlement" && payload.complete === true));

  const inspection = await post(origin, "/api/boundary-bundles/inspect", {
    bundle: approved.body.result.bundle,
  });
  assert.equal(inspection.body.verification.valid, true);
  assert.equal(inspection.body.authenticity.status, "authenticated");
  assert.equal(inspection.body.summary.verdict, "fail");

  const polled = await get(origin, `/api/measured-audits/${vulnerable.body.id}`);
  assert.equal(polled.response.status, 200);
  assert.equal(polled.body.state, "completed");
  assert.equal(polled.body.result.bundle.bundleHash, approved.body.result.bundle.bundleHash);

  const fixed = await start(origin, {
    presetId: "checkout_fixed",
    idempotencyKey: "checkout-fixed-1",
  });
  const fixedApproved = await post(origin, `/api/measured-audits/${fixed.body.id}/approve`, {
    humanId: "human_demo_reviewer",
  });
  assert.equal(fixedApproved.body.result.verdict, "pass");
  assert.equal(fixedApproved.body.result.routeParity.status, "pass");
  assert.equal(fixedApproved.body.result.baselineSafety.status, "pass");
});

test("the measured API rejects caller-authored routes and keeps approval human-only", async (t) => {
  const server = createArenaServer({ secret: "measured-audit-api-test-secret-with-entropy" });
  await listen(server);
  t.after(() => close(server));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const rejected = await start(origin, {
    presetId: "checkout_vulnerable",
    idempotencyKey: "caller-evidence",
    evidence: [{ kind: "money", amount: 0 }],
  });
  assert.equal(rejected.response.status, 400);
  assert.match(rejected.body.error, /server-owned preset fields/i);

  const [page, script] = await Promise.all([
    fetch(origin).then((response) => response.text()),
    fetch(`${origin}/arena.js`).then((response) => response.text()),
  ]);
  assert.match(page, /Start measured checkout audit/);
  assert.match(page, /Approve and run/);
  assert.match(script, /start_measured_checkout_audit/);
  assert.match(script, /get_measured_audit_status/);
  assert.doesNotMatch(script, /approve_measured_checkout_audit/);
});

async function start(origin, body) {
  return post(origin, "/api/measured-audits", body);
}

async function post(origin, path, body) {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

async function get(origin, path) {
  const response = await fetch(`${origin}${path}`);
  return { response, body: await response.json() };
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}
