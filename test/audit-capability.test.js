import assert from "node:assert/strict";
import test from "node:test";

import {
  auditSessionFromRequest,
  createApprovalCapability,
  ensureAuditSession,
  sameOriginMutation,
  verifyApprovalCapability,
} from "../src/audit-capability.js";

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

function mutationRequest({ origin = "https://arena.example", fetchSite = "same-origin", cookie = "" } = {}) {
  return new Request("https://arena.example/api/audits", {
    method: "POST",
    headers: {
      origin,
      "sec-fetch-site": fetchSite,
      "sec-fetch-mode": "cors",
      ...(cookie ? { cookie } : {}),
    },
  });
}
