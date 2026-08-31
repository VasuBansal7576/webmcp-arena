import assert from "node:assert/strict";
import test from "node:test";

import {
  admitAuditStart,
  auditSessionFromRequest,
  createApprovalCapability,
  ensureAuditSession,
  sameOriginMutation,
  verifyApprovalCapability,
} from "../src/audit-capability.js";

test("cookie-less clients cannot escape network and global audit-start limits", async () => {
  const first = await ensureAuditSession(mutationRequest({ connectingIp: "203.0.113.42" }));
  const second = await ensureAuditSession(mutationRequest({ connectingIp: "203.0.113.42" }));
  const calls = [];
  const consume = async (input) => {
    calls.push(input);
    return { allowed: true, resetAt: input.now + input.windowMs };
  };

  await admitAuditStart({
    request: mutationRequest({ connectingIp: "203.0.113.42" }),
    sessionHash: first.sessionHash,
    now: 1_000,
    consume,
  });
  const firstBuckets = calls.splice(0);
  await admitAuditStart({
    request: mutationRequest({ connectingIp: "203.0.113.42" }),
    sessionHash: second.sessionHash,
    now: 2_000,
    consume,
  });
  const secondBuckets = calls;

  assert.notEqual(first.sessionHash, second.sessionHash);
  assert.deepEqual(firstBuckets.map(({ scope, limit }) => [scope, limit]), [
    ["session", 6],
    ["network", 20],
    ["global", 120],
  ]);
  assert.notEqual(firstBuckets[0].bucketKey, secondBuckets[0].bucketKey);
  assert.equal(firstBuckets[1].bucketKey, secondBuckets[1].bucketKey);
  assert.equal(firstBuckets[2].bucketKey, secondBuckets[2].bucketKey);
  assert.equal(firstBuckets.every(({ bucketKey }) => /^audit-start:v1:[A-Za-z0-9_-]{43}$/.test(bucketKey)), true);
});

test("a narrow denial does not consume broader availability buckets", async () => {
  const calls = [];
  const result = await admitAuditStart({
    request: mutationRequest({ connectingIp: "198.51.100.19" }),
    sessionHash: "S".repeat(43),
    now: 10_000,
    consume: async (input) => {
      calls.push(input);
      return { allowed: false, resetAt: 20_000 };
    },
  });

  assert.deepEqual(result, { allowed: false, resetAt: 20_000, scope: "session" });
  assert.equal(calls.length, 1);
});

test("approval capabilities are bound to one HttpOnly browser session and never stored in plaintext", async () => {
  const initial = mutationRequest();
  const session = await ensureAuditSession(initial);
  assert.match(session.setCookie, /^arena_session=.*HttpOnly; SameSite=Strict/);
  const cookie = session.setCookie.split(";", 1)[0];
  const approval = await createApprovalCapability(session.sessionHash);
  const record = { privateApproval: approval.privateApproval };

  assert.notEqual(approval.privateApproval.capabilityHash, approval.capability);
  assert.equal(await verifyApprovalCapability(record, { capability: approval.capability, sessionId: session.sessionId }), true);
  assert.equal(await verifyApprovalCapability(record, { capability: approval.capability, sessionId: "X".repeat(43) }), false);
  assert.equal(auditSessionFromRequest(mutationRequest({ cookie })), session.sessionId);
});

test("state-changing endpoints require browser-supplied same-origin fetch metadata", () => {
  assert.equal(sameOriginMutation(mutationRequest()), true);
  assert.equal(sameOriginMutation(mutationRequest({ origin: "https://attacker.example" })), false);
  assert.equal(sameOriginMutation(mutationRequest({ fetchSite: "cross-site" })), false);
  assert.equal(sameOriginMutation(new Request("https://arena.example/api/audits", { method: "POST" })), false);
});

function mutationRequest({ origin = "https://arena.example", fetchSite = "same-origin", cookie = "", connectingIp = "" } = {}) {
  return new Request("https://arena.example/api/audits", {
    method: "POST",
    headers: {
      origin,
      "sec-fetch-site": fetchSite,
      "sec-fetch-mode": "cors",
      ...(connectingIp ? { "cf-connecting-ip": connectingIp } : {}),
      ...(cookie ? { cookie } : {}),
    },
  });
}
