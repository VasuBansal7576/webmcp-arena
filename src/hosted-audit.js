import { createBoundaryAuditor, verifyAuditBundle } from "./boundary-audit.js";
import { createCheckoutAuditAdapter } from "./checkout-audit-adapter.js";
import { CHECKOUT_CART_ID } from "./checkout-fixture.js";

const VERSIONS = new Set(["vulnerable", "fixed"]);
const APPROVAL_RECEIPT_FIELDS = Object.freeze([
  "approvedAt",
  "assuranceClaim",
  "expiresAt",
  "method",
  "nonceId",
  "reviewedArgumentsHash",
  "reviewedContractHash",
  "reviewedTargetHash",
  "reviewedToolHash",
  "reviewerClaim",
  "sessionCommitment",
  "status",
]);
export const HOSTED_APPROVAL_REVIEWER_CLAIM = "same_origin_interface_session_controller";
export const HOSTED_APPROVAL_ASSURANCE_CLAIM = "session_capability_verified_human_presence_not_attested";
const TARGETS = Object.freeze({
  vulnerable: Object.freeze({
    label: "Checkout · vulnerable delayed charge",
    url: "arena-owned://checkout/?version=vulnerable",
  }),
  fixed: Object.freeze({
    label: "Checkout · fixed preview",
    url: "arena-owned://checkout/?version=fixed",
  }),
});

export async function createHostedAudit({ id, version, privateApproval, now = Date.now() }) {
  validateAuditId(id);
  validateVersion(version);
  validatePrivateApproval(privateApproval);

  const measured = await prepareMeasuredCheckout(version);
  const issuedAt = iso(now);
  return {
    id,
    version,
    state: "awaiting_approval",
    createdAt: issuedAt,
    updatedAt: issuedAt,
    expiresAt: new Date(epoch(now) + 10 * 60_000).toISOString(),
    review: {
      adapterId: measured.adapter.manifest.id,
      implementationVersion: version,
      targetPreset: TARGETS[version].label,
      targetHash: measured.targetHash,
      toolName: measured.recipe.agent.toolName,
      toolHash: measured.prepared.approvalBinding.toolHash,
      arguments: structuredClone(measured.recipe.agent.arguments),
      argumentKeys: Object.keys(measured.recipe.agent.arguments).sort(),
      argumentsHash: measured.prepared.approvalBinding.argumentsHash,
      claimScope: measured.adapter.manifest.claimScope[0],
      contractHash: measured.prepared.contractHash,
      invariants: structuredClone(measured.prepared.proposedContract.invariants),
      baselineSafety: structuredClone(measured.prepared.baselineSafety),
      trustMode: measured.adapter.manifest.trustMode,
      approvalAssurance: "one_time_interface_session_capability",
    },
    privateApproval: structuredClone(privateApproval),
    approval: null,
    history: [
      { state: "preparing", at: issuedAt },
      { state: "awaiting_approval", at: issuedAt },
    ],
    result: null,
  };
}

export async function completeHostedAudit(record, { now = Date.now() } = {}) {
  if (!record || !VERSIONS.has(record.version) || !record.review?.contractHash) {
    throw new Error("invalid hosted audit record");
  }
  const approvalReceipt = validateApprovalReceipt(record);

  const measured = await prepareMeasuredCheckout(record.version);
  assertReviewedPlan(record, measured);
  const outcome = await measured.auditor.run({
    planId: measured.prepared.planId,
    approval: {
      status: "approved",
      planId: measured.prepared.planId,
      ...measured.prepared.approvalBinding,
    },
  });

  const verification = await verifyAuditBundle(outcome.bundle);
  if (verification.valid !== true) {
    throw new Error(`measured boundary bundle failed verification: ${verification.reason || "unknown"}`);
  }
  if (outcome.bundle.targetHash !== measured.targetHash) {
    throw new Error("the executed checkout target no longer matches the reviewed target");
  }

  const humanEvents = timeline(outcome.bundle.events, "human");
  const agentEvents = timeline(outcome.bundle.events, "agent");
  const settlement = agentEvents.find((event) => event.kind === "effect_settlement") || {
    status: "inconclusive",
    complete: false,
    pendingEffects: null,
    reason: "missing_terminal_watermark",
  };
  const findings = outcome.findings.map((finding) => ({
    ...structuredClone(finding),
    kind: findingKind(finding.code),
  }));
  const evidence = {
    kind: "arena.hosted_boundary_evidence",
    version: 1,
    auditId: record.id,
    generatedAt: iso(now),
    approval: structuredClone(approvalReceipt),
    boundaryBundle: structuredClone(outcome.bundle),
  };
  const payloadHash = await sha256Base64Url(canonicalJson(evidence));

  return {
    verdict: outcome.verdict,
    summary: summarize(outcome.verdict, humanEvents, agentEvents),
    findings,
    bundle: structuredClone(outcome.bundle),
    display: { humanEvents, agentEvents, settlement },
    approval: structuredClone(approvalReceipt),
    evidence,
    payloadHash,
    verification: { semanticValid: true, hashValid: true, attestedByCore: verification.attested === true },
  };
}

export function publicHostedAudit(record) {
  if (!record || typeof record !== "object") return record;
  const visible = structuredClone(record);
  delete visible.privateApproval;
  return visible;
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function prepareMeasuredCheckout(version) {
  const adapter = createCheckoutAuditAdapter({
    chargeDelayMs: 75,
    settlementPollIntervalMs: 10,
    settlementTimeoutMs: 1_500,
  });
  const auditor = createBoundaryAuditor({
    targetHarness: adapter.targetHarness,
    routeRunner: adapter.routeRunner,
  });
  const recipe = await adapter.createRecipe({ target: TARGETS[version].url });
  const targetHash = await sha256Base64Url(recipe.target);
  const prepared = await auditor.prepare(recipe);
  return { adapter, auditor, recipe, prepared, targetHash };
}

function assertReviewedPlan(record, measured) {
  const { prepared, targetHash } = measured;
  const expected = record.review;
  const actual = prepared.approvalBinding;
  if (expected.targetHash !== targetHash) {
    throw new Error("the executable checkout target no longer matches the reviewed target");
  }
  if (prepared.contractHash !== expected.contractHash ||
      actual.contractHash !== expected.contractHash ||
      actual.toolHash !== expected.toolHash ||
      actual.argumentsHash !== expected.argumentsHash) {
    throw new Error("the executable checkout plan no longer matches the reviewed contract");
  }
  if (record.approval.reviewedContractHash !== expected.contractHash ||
      record.approval.reviewedTargetHash !== expected.targetHash ||
      record.approval.reviewedToolHash !== expected.toolHash ||
      record.approval.reviewedArgumentsHash !== expected.argumentsHash) {
    throw new Error("approval is not bound to the executable checkout plan");
  }
}

function validateApprovalReceipt(record) {
  const approval = record.approval;
  if (!isPlainObject(approval) || !hasExactKeys(approval, APPROVAL_RECEIPT_FIELDS) ||
      approval.status !== "approved" ||
      approval.method !== "one_time_interface_session_capability" ||
      typeof approval.approvedAt !== "string" ||
      approval.expiresAt !== record.expiresAt ||
      approval.nonceId !== record.privateApproval?.nonceId ||
      approval.sessionCommitment !== record.privateApproval?.sessionHash ||
      approval.reviewerClaim !== HOSTED_APPROVAL_REVIEWER_CLAIM ||
      approval.assuranceClaim !== HOSTED_APPROVAL_ASSURANCE_CLAIM) {
    throw new Error("a bound interface-session approval receipt is required");
  }
  const approvedAt = canonicalTimestamp(approval.approvedAt);
  const expiresAt = canonicalTimestamp(approval.expiresAt);
  if (approvedAt > expiresAt) {
    throw new Error("approval receipt was issued after its review window expired");
  }
  return {
    status: approval.status,
    method: approval.method,
    nonceId: approval.nonceId,
    approvedAt: approval.approvedAt,
    expiresAt: approval.expiresAt,
    sessionCommitment: approval.sessionCommitment,
    reviewerClaim: approval.reviewerClaim,
    assuranceClaim: approval.assuranceClaim,
    reviewedTargetHash: approval.reviewedTargetHash,
    reviewedToolHash: approval.reviewedToolHash,
    reviewedArgumentsHash: approval.reviewedArgumentsHash,
    reviewedContractHash: approval.reviewedContractHash,
  };
}

function canonicalTimestamp(value) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error("approval receipt contains an invalid timestamp");
  }
  return timestamp;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function timeline(events, route) {
  return events
    .filter((event) => event.route === route)
    .map((event) => ({
      sequence: event.sequence,
      channel: event.provenance === "server_attested" ? "server" : "recorder",
      ...structuredClone(event.payload),
    }));
}

function findingKind(code) {
  if (String(code).includes("money") || code === "unexpected_consequential_effect") return "money";
  if (String(code).includes("authorization")) return "authorization";
  if (String(code).includes("approval")) return "approval";
  if (String(code).includes("settlement")) return "effect_settlement";
  return "final_state";
}

function summarize(verdict, humanEvents, agentEvents) {
  if (verdict === "pass") return "Measured human and agent routes preserved the same protection boundary.";
  const humanMoney = humanEvents.filter((event) => event.kind === "money").length;
  const hiddenCharge = agentEvents.find((event) => event.kind === "money" && Number(event.amount) > 0);
  if (hiddenCharge && humanMoney === 0) {
    return `Arena observed a hidden delayed ${hiddenCharge.currency || ""} ${hiddenCharge.amount} charge after the preview tool returned.`.replace(/\s+/g, " ");
  }
  return "Arena measured a security outcome on the agent route that the reviewed human route did not produce.";
}

function validateAuditId(id) {
  if (typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id)) throw new Error("audit id must be a UUID");
}

function validateVersion(version) {
  if (!VERSIONS.has(version)) throw new Error("version must be vulnerable or fixed");
}

function validatePrivateApproval(value) {
  if (!value || typeof value !== "object" ||
      !/^[A-Za-z0-9_-]{43}$/.test(value.capabilityHash) ||
      !/^[A-Za-z0-9_-]{43}$/.test(value.sessionHash) ||
      !/^[A-Za-z0-9_-]{16,128}$/.test(value.nonceId)) {
    throw new Error("a valid private approval binding is required");
  }
}

function epoch(value) {
  const result = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(result)) throw new Error("now must be a valid timestamp");
  return result;
}

function iso(value) {
  return new Date(epoch(value)).toISOString();
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export const HOSTED_CHECKOUT_CART_ID = CHECKOUT_CART_ID;
