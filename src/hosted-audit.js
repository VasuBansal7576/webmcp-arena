import { verifyAuditBundle } from "./boundary-audit.js";
import {
  CHECKOUT_AUDIT_PRINCIPAL,
  CHECKOUT_WEBMCP_TOOL,
  createCheckoutAuditAdapter,
} from "./checkout-audit-adapter.js";
import { CHECKOUT_RELEASE_ARTIFACTS } from "./checkout-release-artifacts.js";
import {
  createGeneratedReleaseAuditor,
  hashGeneratedRelease,
} from "./generated-release-audit.js";
import { hashWebMcpToolDefinition } from "./webmcp-tool-definition.js";
import {
  finalizeWebMcpInvocationReceipt,
  verifyPreparedWebMcpInvocationReceipt,
  verifyWebMcpInvocationReceipt,
} from "./webmcp-invocation.js";

const VERSIONS = new Set(["vulnerable", "fixed"]);
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const APPROVAL_RECEIPT_FIELDS = Object.freeze([
  "approvedAt",
  "assuranceClaim",
  "expiresAt",
  "method",
  "nonceId",
  "reviewedArgumentsHash",
  "reviewedAgentHash",
  "reviewedContractHash",
  "reviewedPrincipalHash",
  "reviewedReleaseHash",
  "reviewedTargetHash",
  "reviewedToolDefinitionHash",
  "reviewedToolHash",
  "reviewerClaim",
  "sessionCommitment",
  "status",
]);
export const HOSTED_APPROVAL_REVIEWER_CLAIM = "same_origin_interface_session_controller";
export const HOSTED_APPROVAL_ASSURANCE_CLAIM = "session_capability_verified_human_presence_not_attested";
export const HOSTED_AUDIT_RETENTION_MS = 30 * 24 * 60 * 60_000;
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
const GENERATED_AGENT = Object.freeze({
  id: "browser-agent-demo",
  assurance: "self_asserted_demo_identity",
});
const GENERATED_RELEASES = Object.freeze({
  vulnerable: Object.freeze({
    id: "arena.checkout.generated-release",
    version: "2026.08.31-vulnerable.1",
    generator: "vendor-neutral-demo-generator",
    artifact: CHECKOUT_RELEASE_ARTIFACTS.vulnerable,
    tools: Object.freeze([CHECKOUT_WEBMCP_TOOL]),
  }),
  fixed: Object.freeze({
    id: "arena.checkout.generated-release",
    version: "2026.08.31-fixed.1",
    generator: "vendor-neutral-demo-generator",
    artifact: CHECKOUT_RELEASE_ARTIFACTS.fixed,
    tools: Object.freeze([CHECKOUT_WEBMCP_TOOL]),
  }),
});
const HOSTED_EVIDENCE_FIELDS = Object.freeze([
  "approval",
  "auditId",
  "authorization",
  "authorizationChecks",
  "boundaryBundle",
  "exactIntent",
  "generatedAt",
  "invocationReceipt",
  "kind",
  "releaseCoverage",
  "releaseVerdict",
  "retentionUntil",
  "selectedToolVerdict",
  "version",
]);
const HOSTED_REVIEW_FIELDS = Object.freeze([
  "adapterId",
  "agent",
  "agentHash",
  "approvalAssurance",
  "argumentKeys",
  "arguments",
  "argumentsHash",
  "baselineSafety",
  "claimScope",
  "contractHash",
  "coverage",
  "effects",
  "implementationVersion",
  "invariants",
  "principal",
  "principalHash",
  "release",
  "releaseHash",
  "releaseManifest",
  "target",
  "targetHash",
  "targetPreset",
  "toolDefinition",
  "toolDefinitionHash",
  "toolHash",
  "toolName",
  "trustMode",
]);

export async function createHostedAudit({ id, version, privateApproval, now = Date.now() }) {
  validateAuditId(id);
  validateVersion(version);
  validatePrivateApproval(privateApproval);

  const measured = await prepareMeasuredCheckout(version, now);
  const issuedAt = iso(now);
  const issuedAtEpoch = epoch(now);
  return {
    id,
    version,
    state: "awaiting_approval",
    createdAt: issuedAt,
    updatedAt: issuedAt,
    approvalExpiresAt: new Date(issuedAtEpoch + 10 * 60_000).toISOString(),
    retentionUntil: new Date(issuedAtEpoch + HOSTED_AUDIT_RETENTION_MS).toISOString(),
    review: hostedReview(measured, version),
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
  const invocationRequest = await verifyPreparedWebMcpInvocationReceipt(record.invocation, {
    auditId: record.id,
    review: record.review,
    approval: approvalReceipt,
  });
  if (!invocationRequest.valid) {
    throw new Error(`a bound registered WebMCP callback receipt is required: ${invocationRequest.reason}`);
  }

  const measured = await prepareMeasuredCheckout(record.version, now);
  assertReviewedPlan(record, measured);
  const authorization = measured.approve({ humanId: approvalReceipt.reviewerClaim });
  const invalidCapability = await measured.generatedAuditor.run({
    auditId: measured.generatedPrepared.auditId,
    capability: "invalid_release_capability_000000000000000000000000",
    agent: measured.intent,
  });
  const changedTool = await measured.generatedAuditor.run({
    auditId: measured.generatedPrepared.auditId,
    capability: authorization.capability,
    agent: { ...measured.intent, toolName: "place_order" },
  });
  const wrongAgent = await measured.generatedAuditor.run({
    auditId: measured.generatedPrepared.auditId,
    capability: authorization.capability,
    agent: { ...measured.intent, id: "unreviewed-browser-agent" },
  });
  const changedArguments = await measured.generatedAuditor.run({
    auditId: measured.generatedPrepared.auditId,
    capability: authorization.capability,
    agent: { ...measured.intent, arguments: { cartId: "cart_changed_after_review" } },
  });
  const outcome = await measured.generatedAuditor.run({
    auditId: measured.generatedPrepared.auditId,
    capability: authorization.capability,
    agent: measured.intent,
  });
  const replay = await measured.generatedAuditor.run({
    auditId: measured.generatedPrepared.auditId,
    capability: authorization.capability,
    agent: measured.intent,
  });

  const verification = await verifyAuditBundle(outcome.selectedToolBundle);
  if (verification.valid !== true) {
    throw new Error(`measured boundary bundle failed verification: ${verification.reason || "unknown"}`);
  }
  if (outcome.selectedToolBundle.targetHash !== measured.targetHash) {
    throw new Error("the executed checkout target no longer matches the reviewed target");
  }

  const authorizationChecks = [
    authorizationCheck("invalid_capability", invalidCapability, "invalid_capability"),
    authorizationCheck("tool_substitution", changedTool, "tool_binding_mismatch"),
    authorizationCheck("wrong_agent", wrongAgent, "agent_identity_mismatch"),
    authorizationCheck("argument_substitution", changedArguments, "argument_substitution"),
    { check: "exact_intent", status: "executed", reason: null },
    authorizationCheck("replay", replay, "authorization_replayed"),
  ];
  assertAuthorizationChecks(authorizationChecks);
  const generatedAt = iso(now);
  const retentionUntil = new Date(epoch(now) + HOSTED_AUDIT_RETENTION_MS).toISOString();
  record.retentionUntil = retentionUntil;
  const invocationReceipt = await finalizeWebMcpInvocationReceipt(record.invocation, {
    result: agentOutcome(outcome.selectedToolBundle),
    backendTraceRoot: agentTraceRoot(outcome.selectedToolBundle),
    settledAt: generatedAt,
  });
  const evidence = {
    kind: "arena.hosted_boundary_evidence",
    version: 2,
    auditId: record.id,
    generatedAt,
    retentionUntil,
    approval: structuredClone(approvalReceipt),
    exactIntent: structuredClone(record.review),
    invocationReceipt,
    authorization: structuredClone(outcome.authorization),
    authorizationChecks: structuredClone(authorizationChecks),
    releaseCoverage: structuredClone(outcome.coverage),
    selectedToolVerdict: outcome.selectedToolVerdict,
    releaseVerdict: outcome.verdict,
    boundaryBundle: structuredClone(outcome.selectedToolBundle),
  };
  const hostedVerification = await verifyHostedAuditEvidence(evidence);
  if (!hostedVerification.valid) {
    throw new Error(`hosted evidence failed semantic verification: ${hostedVerification.reason}`);
  }
  const payloadHash = await sha256Base64Url(canonicalJson(evidence));

  return {
    ...projectHostedEvidence(evidence),
    evidence,
    payloadHash,
    verification: { semanticValid: true, hashValid: true, attestedByCore: verification.attested === true },
  };
}

export async function publicHostedAudit(record) {
  if (!record || typeof record !== "object") return record;
  const visible = structuredClone(record);
  delete visible.privateApproval;
  if (!visible.result) return visible;

  const semantic = await verifyHostedAuditRecord(visible);
  if (!semantic.valid) {
    throw new Error(`stored hosted evidence is invalid: ${semantic.reason || "unknown"}`);
  }
  const payloadHash = await sha256Base64Url(canonicalJson(visible.result.evidence));
  if (visible.result.payloadHash !== payloadHash || visible.result.attestation?.payloadHash !== payloadHash) {
    throw new Error("stored hosted evidence hash diverges from its attestation");
  }

  const projection = projectHostedEvidence(visible.result.evidence);
  for (const field of Object.keys(projection)) {
    if (canonicalJson(visible.result[field]) !== canonicalJson(projection[field])) {
      throw new Error("stored hosted result diverges from signed evidence");
    }
  }
  visible.result = {
    ...projection,
    evidence: structuredClone(visible.result.evidence),
    payloadHash,
    attestation: structuredClone(visible.result.attestation),
    verification: { semanticValid: true, hashValid: true, projectionValid: true },
  };
  return visible;
}

export async function verifyHostedAuditRecord(record) {
  if (!isPlainObject(record) || record.state !== "completed" || !VERSIONS.has(record.version) ||
      !isPlainObject(record.review) || !isPlainObject(record.approval) || !isPlainObject(record.result) ||
      !isPlainObject(record.result.evidence)) {
    return invalidEvidence("hosted_record_schema_invalid");
  }
  const semantic = await verifyHostedAuditEvidence(record.result.evidence);
  if (!semantic.valid) return semantic;
  const evidence = record.result.evidence;
  if (evidence.auditId !== record.id || evidence.exactIntent.implementationVersion !== record.version ||
      record.approvalExpiresAt !== record.approval.expiresAt ||
      record.approvalExpiresAt !== evidence.approval.expiresAt ||
      record.retentionUntil !== evidence.retentionUntil ||
      canonicalJson(evidence.exactIntent) !== canonicalJson(record.review) ||
      canonicalJson(evidence.approval) !== canonicalJson(record.approval)) {
    return invalidEvidence("hosted_record_evidence_mismatch");
  }
  return { valid: true };
}

function projectHostedEvidence(evidence) {
  const humanEvents = timeline(evidence.boundaryBundle.events, "human");
  const agentEvents = timeline(evidence.boundaryBundle.events, "agent");
  const settlement = agentEvents.find((event) => event.kind === "effect_settlement") || {
    status: "inconclusive",
    complete: false,
    pendingEffects: null,
    reason: "missing_terminal_watermark",
  };
  const findings = evidence.boundaryBundle.findings.map((finding) => ({
    ...structuredClone(finding),
    kind: findingKind(finding.code),
  }));
  if (!evidence.releaseCoverage.complete) {
    findings.push({
      code: "release_coverage_incomplete",
      message: `Only ${evidence.releaseCoverage.auditedTools.length} of ${evidence.releaseCoverage.totalTools} generated WebMCP tools were audited.`,
      kind: findingKind("release_coverage_incomplete"),
    });
  }
  return {
    verdict: evidence.releaseVerdict,
    summary: summarize(evidence.releaseVerdict, humanEvents, agentEvents),
    findings,
    bundle: structuredClone(evidence.boundaryBundle),
    release: structuredClone(evidence.exactIntent.release),
    authorization: structuredClone(evidence.authorization),
    invocationReceipt: structuredClone(evidence.invocationReceipt),
    authorizationChecks: structuredClone(evidence.authorizationChecks),
    releaseCoverage: structuredClone(evidence.releaseCoverage),
    selectedToolVerdict: evidence.selectedToolVerdict,
    display: { humanEvents, agentEvents, settlement },
    approval: structuredClone(evidence.approval),
  };
}

export async function verifyHostedAuditEvidence(evidence) {
  try {
    if (!isPlainObject(evidence) || !hasExactKeys(evidence, HOSTED_EVIDENCE_FIELDS) ||
        evidence.kind !== "arena.hosted_boundary_evidence" || evidence.version !== 2 ||
        typeof evidence.auditId !== "string" || !/^[0-9a-f-]{36}$/i.test(evidence.auditId)) {
      return invalidEvidence("hosted_evidence_schema_invalid");
    }
    canonicalTimestamp(evidence.generatedAt);
    const retentionUntil = canonicalTimestamp(evidence.retentionUntil);
    const review = evidence.exactIntent;
    if (!isPlainObject(review) || !hasExactKeys(review, HOSTED_REVIEW_FIELDS)) {
      return invalidEvidence("exact_intent_schema_invalid");
    }
    if (!isPlainObject(review.release) || !hasExactKeys(review.release, ["artifact", "generator", "hash", "id", "version"]) ||
        !isPlainObject(review.release.artifact) || !hasExactKeys(review.release.artifact, ["algorithm", "digest", "subject"]) ||
        !isPlainObject(review.agent) || !hasExactKeys(review.agent, ["assurance", "hash", "id"]) ||
        !isPlainObject(review.principal) || !hasExactKeys(review.principal, ["hash", "label", "scope"]) ||
        !isPlainObject(review.releaseManifest) || !Array.isArray(review.releaseManifest.tools) ||
        !isPlainObject(review.toolDefinition) || !isPlainObject(review.arguments) ||
        !Array.isArray(review.argumentKeys) || !isPlainObject(review.coverage)) {
      return invalidEvidence("exact_intent_schema_invalid");
    }
    const expectedTarget = TARGETS[review.implementationVersion];
    if (!expectedTarget || review.adapterId !== "arena.checkout" ||
        review.targetPreset !== expectedTarget.label || review.target !== expectedTarget.url ||
        review.claimScope !== "owned_fixture:checkout" || review.trustMode !== "server_attested" ||
        review.approvalAssurance !== "one_time_interface_session_capability" ||
        review.agent.id !== GENERATED_AGENT.id || review.agent.assurance !== GENERATED_AGENT.assurance ||
        review.toolName !== review.toolDefinition.name) {
      return invalidEvidence("hosted_profile_mismatch");
    }
    if (review.release.id !== review.releaseManifest.id ||
        review.release.version !== review.releaseManifest.version ||
        review.release.generator !== review.releaseManifest.generator ||
        canonicalJson(review.release.artifact) !== canonicalJson(review.releaseManifest.artifact) ||
        review.release.hash !== review.releaseHash ||
        hashGeneratedRelease(review.releaseManifest) !== review.releaseHash) {
      return invalidEvidence("release_commitment_mismatch");
    }
    const manifestTool = review.releaseManifest.tools.find((tool) => tool?.name === review.toolName);
    if (!manifestTool || canonicalJson(manifestTool) !== canonicalJson(review.toolDefinition) ||
        hashWebMcpToolDefinition(review.toolDefinition) !== review.toolDefinitionHash) {
      return invalidEvidence("tool_definition_commitment_mismatch");
    }
    const [targetHash, agentHash, argumentsHash, toolHash, reviewerHash] = await Promise.all([
      sha256Base64Url(String(review.target)),
      sha256Base64Url(`arena.agent.v1\0${review.agent.id}`),
      sha256Base64Url(canonicalJson(review.arguments)),
      sha256Base64Url(canonicalJson({ name: review.toolName, definitionHash: review.toolDefinitionHash })),
      sha256Base64Url(`arena.reviewer.v1\0${evidence.approval?.reviewerClaim}`),
    ]);
    if (targetHash !== review.targetHash || agentHash !== review.agent.hash ||
        review.agentHash !== review.agent.hash || argumentsHash !== review.argumentsHash ||
        toolHash !== review.toolHash || review.principalHash !== review.principal.hash ||
        canonicalJson(review.argumentKeys) !== canonicalJson(Object.keys(review.arguments).sort()) ||
        ![review.releaseHash, review.principalHash, review.contractHash].every((value) => DIGEST.test(value || ""))) {
      return invalidEvidence("exact_intent_commitment_mismatch");
    }
    if (canonicalJson({ label: review.principal.label, scope: review.principal.scope }) !==
        canonicalJson(CHECKOUT_AUDIT_PRINCIPAL)) {
      return invalidEvidence("principal_descriptor_mismatch");
    }
    const expectedCoverage = {
      auditedTools: [review.toolName],
      totalTools: review.releaseManifest.tools.length,
      complete: review.releaseManifest.tools.length === 1,
    };
    if (canonicalJson(review.coverage) !== canonicalJson(expectedCoverage) ||
        canonicalJson(evidence.releaseCoverage) !== canonicalJson(expectedCoverage)) {
      return invalidEvidence("release_coverage_mismatch");
    }
    if (!validEvidenceApproval(evidence.approval, review)) {
      return invalidEvidence("approval_commitment_mismatch");
    }
    if (!isPlainObject(evidence.authorization) ||
        !hasExactKeys(evidence.authorization, ["agentHash", "reviewerHash", "status"]) ||
        evidence.authorization.status !== "consumed" || evidence.authorization.agentHash !== review.agentHash ||
        evidence.authorization.reviewerHash !== reviewerHash) {
      return invalidEvidence("authorization_commitment_mismatch");
    }
    try {
      assertAuthorizationChecks(evidence.authorizationChecks);
    } catch {
      return invalidEvidence("authorization_probe_mismatch");
    }
    const boundaryVerification = await verifyAuditBundle(evidence.boundaryBundle);
    if (!boundaryVerification.valid) return invalidEvidence(`boundary_${boundaryVerification.reason}`);
    const boundary = evidence.boundaryBundle;
    const invocationVerification = await verifyWebMcpInvocationReceipt(evidence.invocationReceipt, {
      auditId: evidence.auditId,
      review,
      approval: evidence.approval,
      result: agentOutcome(boundary),
      backendTraceRoot: agentTraceRoot(boundary),
    });
    if (!invocationVerification.valid) return invalidEvidence(invocationVerification.reason);
    const approvedAt = canonicalTimestamp(evidence.approval.approvedAt);
    const approvalExpiresAt = canonicalTimestamp(evidence.approval.expiresAt);
    const evidenceGeneratedAt = canonicalTimestamp(evidence.generatedAt);
    const boundaryGeneratedAt = canonicalTimestamp(boundary.generatedAt);
    if (evidenceGeneratedAt !== boundaryGeneratedAt || approvedAt > boundaryGeneratedAt ||
        boundary.events.some((event) => canonicalTimestamp(event.observedAt) < approvedAt) ||
        boundaryGeneratedAt > approvalExpiresAt || retentionUntil <= approvalExpiresAt ||
        retentionUntil - evidenceGeneratedAt < HOSTED_AUDIT_RETENTION_MS) {
      return invalidEvidence("approval_chronology_mismatch");
    }
    if (boundary.targetHash !== review.targetHash || boundary.principalHash !== review.principalHash ||
        boundary.toolHash !== review.toolHash || boundary.argumentsHash !== review.argumentsHash ||
        boundary.contractHash !== review.contractHash || boundary.invocation?.toolName !== review.toolName ||
        boundary.invocation?.toolDefinitionHash !== review.toolDefinitionHash ||
        canonicalJson(boundary.invocation?.argumentKeys) !== canonicalJson(review.argumentKeys) ||
        canonicalJson(boundary.contract?.effects) !== canonicalJson(review.effects) ||
        canonicalJson(boundary.contract?.invariants) !== canonicalJson(review.invariants) ||
        canonicalJson(boundary.baselineSafety) !== canonicalJson(review.baselineSafety)) {
      return invalidEvidence("boundary_exact_intent_mismatch");
    }
    if (evidence.selectedToolVerdict !== boundary.verdict) {
      return invalidEvidence("selected_tool_verdict_mismatch");
    }
    const expectedReleaseVerdict = evidence.selectedToolVerdict === "fail"
      ? "fail"
      : expectedCoverage.complete ? evidence.selectedToolVerdict : "inconclusive";
    if (evidence.releaseVerdict !== expectedReleaseVerdict) {
      return invalidEvidence("release_verdict_mismatch");
    }
    return { valid: true };
  } catch {
    return invalidEvidence("hosted_evidence_invalid");
  }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

async function prepareMeasuredCheckout(version, now = Date.now()) {
  const adapter = createCheckoutAuditAdapter({
    chargeDelayMs: 75,
    settlementPollIntervalMs: 10,
    settlementTimeoutMs: 1_500,
  });
  let approve;
  const generatedAuditor = createGeneratedReleaseAuditor({
    adapter,
    now: () => new Date(epoch(now)),
    onApprovalRequired({ approve: trustedApprove }) {
      approve = trustedApprove;
    },
  });
  const recipe = await adapter.createRecipe({ target: TARGETS[version].url });
  const intent = {
    id: GENERATED_AGENT.id,
    toolName: recipe.agent.toolName,
    arguments: structuredClone(recipe.agent.arguments),
  };
  const release = GENERATED_RELEASES[version];
  const generatedPrepared = await generatedAuditor.prepare({
    release,
    target: TARGETS[version].url,
    principalRef: recipe.principalRef,
    agent: intent,
  });
  const prepared = {
    planId: generatedPrepared.auditId,
    contractHash: generatedPrepared.review.intent.contractHash,
    proposedContract: {
      effects: generatedPrepared.review.effects,
      invariants: generatedPrepared.review.invariants,
    },
    approvalBinding: {
      toolHash: generatedPrepared.review.intent.toolHash,
      argumentsHash: generatedPrepared.review.intent.argumentsHash,
      contractHash: generatedPrepared.review.intent.contractHash,
    },
    baselineSafety: generatedPrepared.review.baselineSafety,
    review: generatedPrepared.review,
  };
  return {
    adapter,
    generatedAuditor,
    generatedPrepared,
    approve,
    recipe,
    intent,
    prepared,
    release,
    targetHash: generatedPrepared.review.intent.targetHash,
  };
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
  if (prepared.review.release.hash !== expected.release?.hash ||
      expected.releaseHash !== expected.release?.hash ||
      prepared.review.intent.agentHash !== expected.agent?.hash ||
      expected.agentHash !== expected.agent?.hash ||
      prepared.review.intent.toolDefinitionHash !== expected.toolDefinitionHash) {
    throw new Error("the executable generated release no longer matches the reviewed exact intent");
  }
  if (canonicalJson(expected) !== canonicalJson(hostedReview(measured, record.version))) {
    throw new Error("the displayed review material no longer matches the executable generated release");
  }
  if (record.approval.reviewedContractHash !== expected.contractHash ||
      record.approval.reviewedTargetHash !== expected.targetHash ||
      record.approval.reviewedReleaseHash !== expected.release.hash ||
      record.approval.reviewedAgentHash !== expected.agent.hash ||
      record.approval.reviewedPrincipalHash !== expected.principal.hash ||
      record.approval.reviewedToolDefinitionHash !== expected.toolDefinitionHash ||
      record.approval.reviewedToolHash !== expected.toolHash ||
      record.approval.reviewedArgumentsHash !== expected.argumentsHash) {
    throw new Error("approval receipt is not bound to the executable checkout plan");
  }
}

function hostedReview(measured, version) {
  return {
    adapterId: measured.adapter.manifest.id,
    implementationVersion: version,
    targetPreset: TARGETS[version].label,
    target: TARGETS[version].url,
    targetHash: measured.targetHash,
    release: structuredClone(measured.prepared.review.release),
    releaseHash: measured.prepared.review.release.hash,
    releaseManifest: structuredClone(measured.release),
    coverage: structuredClone(measured.generatedPrepared.review.coverage),
    principal: {
      label: measured.generatedPrepared.review.intent.principalLabel,
      scope: measured.generatedPrepared.review.intent.principalScope,
      hash: measured.generatedPrepared.review.intent.principalHash,
    },
    principalHash: measured.generatedPrepared.review.intent.principalHash,
    agent: {
      id: GENERATED_AGENT.id,
      assurance: GENERATED_AGENT.assurance,
      hash: measured.prepared.review.intent.agentHash,
    },
    agentHash: measured.prepared.review.intent.agentHash,
    toolName: measured.recipe.agent.toolName,
    toolDefinition: structuredClone(CHECKOUT_WEBMCP_TOOL),
    toolDefinitionHash: measured.prepared.review.intent.toolDefinitionHash,
    toolHash: measured.prepared.approvalBinding.toolHash,
    arguments: structuredClone(measured.recipe.agent.arguments),
    argumentKeys: Object.keys(measured.recipe.agent.arguments).sort(),
    argumentsHash: measured.prepared.approvalBinding.argumentsHash,
    claimScope: measured.adapter.manifest.claimScope[0],
    contractHash: measured.prepared.contractHash,
    effects: structuredClone(measured.prepared.proposedContract.effects),
    invariants: structuredClone(measured.prepared.proposedContract.invariants),
    baselineSafety: structuredClone(measured.prepared.baselineSafety),
    trustMode: measured.adapter.manifest.trustMode,
    approvalAssurance: "one_time_interface_session_capability",
  };
}

function validateApprovalReceipt(record) {
  const approval = record.approval;
  if (!isPlainObject(approval) || !hasExactKeys(approval, APPROVAL_RECEIPT_FIELDS) ||
      approval.status !== "approved" ||
      approval.method !== "one_time_interface_session_capability" ||
      typeof approval.approvedAt !== "string" ||
      approval.expiresAt !== record.approvalExpiresAt ||
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
    reviewedReleaseHash: approval.reviewedReleaseHash,
    reviewedAgentHash: approval.reviewedAgentHash,
    reviewedPrincipalHash: approval.reviewedPrincipalHash,
    reviewedToolDefinitionHash: approval.reviewedToolDefinitionHash,
    reviewedToolHash: approval.reviewedToolHash,
    reviewedArgumentsHash: approval.reviewedArgumentsHash,
    reviewedContractHash: approval.reviewedContractHash,
  };
}

function validEvidenceApproval(approval, review) {
  if (!isPlainObject(approval) || !hasExactKeys(approval, APPROVAL_RECEIPT_FIELDS) ||
      approval.status !== "approved" || approval.method !== "one_time_interface_session_capability" ||
      approval.reviewerClaim !== HOSTED_APPROVAL_REVIEWER_CLAIM ||
      approval.assuranceClaim !== HOSTED_APPROVAL_ASSURANCE_CLAIM ||
      typeof approval.nonceId !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(approval.nonceId) ||
      !DIGEST.test(approval.sessionCommitment || "")) return false;
  try {
    if (canonicalTimestamp(approval.approvedAt) > canonicalTimestamp(approval.expiresAt)) return false;
  } catch {
    return false;
  }
  return approval.reviewedTargetHash === review.targetHash &&
    approval.reviewedReleaseHash === review.releaseHash &&
    approval.reviewedAgentHash === review.agentHash &&
    approval.reviewedPrincipalHash === review.principalHash &&
    approval.reviewedToolDefinitionHash === review.toolDefinitionHash &&
    approval.reviewedToolHash === review.toolHash &&
    approval.reviewedArgumentsHash === review.argumentsHash &&
    approval.reviewedContractHash === review.contractHash;
}

function invalidEvidence(reason) {
  return { valid: false, reason };
}

function agentOutcome(bundle) {
  const event = bundle?.events?.find((candidate) => candidate?.route === "agent" && candidate?.payload?.kind === "outcome");
  if (!event?.payload) throw new Error("the measured agent route did not produce a result payload");
  return structuredClone(event.payload);
}

function agentTraceRoot(bundle) {
  const events = bundle?.events?.filter((candidate) => candidate?.route === "agent") || [];
  const root = events.at(-1)?.eventHash;
  if (!DIGEST.test(root || "")) throw new Error("the measured agent route did not produce a backend trace root");
  return root;
}

function authorizationCheck(check, result, expectedReason) {
  const expected = result?.state === "denied" && result?.reason === expectedReason;
  return {
    check,
    status: expected ? "denied" : "unexpected",
    reason: result?.reason || "authorization_check_failed",
  };
}

function assertAuthorizationChecks(checks) {
  if (canonicalJson(checks) !== canonicalJson([
    { check: "invalid_capability", status: "denied", reason: "invalid_capability" },
    { check: "tool_substitution", status: "denied", reason: "tool_binding_mismatch" },
    { check: "wrong_agent", status: "denied", reason: "agent_identity_mismatch" },
    { check: "argument_substitution", status: "denied", reason: "argument_substitution" },
    { check: "exact_intent", status: "executed", reason: null },
    { check: "replay", status: "denied", reason: "authorization_replayed" },
  ])) {
    throw new Error("generated release authorization probes did not preserve the expected boundary");
  }
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
