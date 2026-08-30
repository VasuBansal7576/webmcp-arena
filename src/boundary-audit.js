import { createHash, randomUUID } from "node:crypto";

const SHA256_DIGEST = /^[A-Za-z0-9_-]{43}$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BUNDLE_KEYS = [
  "assurance",
  "attestation",
  "auditId",
  "argumentsHash",
  "baselineSafety",
  "bundleHash",
  "contract",
  "contractHash",
  "coverage",
  "events",
  "findings",
  "generatedAt",
  "invocation",
  "kind",
  "planId",
  "principalHash",
  "routeParity",
  "seedDigest",
  "targetHash",
  "toolHash",
  "verdict",
  "version",
];

export function createBoundaryAuditor({ targetHarness, routeRunner, attestor = null, now = () => new Date(), id = randomUUID, planTtlMs = 10 * 60 * 1000 } = {}) {
  if (!targetHarness?.establish || !targetHarness?.provision || !targetHarness?.release) {
    throw new Error("BoundaryAuditor requires a target harness with establish, provision, and release");
  }
  if (!routeRunner?.runHuman || !routeRunner?.runAgent) {
    throw new Error("BoundaryAuditor requires a route runner with runHuman and runAgent");
  }
  if (!Number.isSafeInteger(planTtlMs) || planTtlMs < 1_000 || planTtlMs > 60 * 60 * 1000) {
    throw new Error("BoundaryAuditor planTtlMs must be between one second and one hour");
  }
  const plans = new Map();

  async function prepare(recipe) {
    const invariants = validateRecipe(recipe);
    const ownedTarget = await targetHarness.establish({ target: recipe.target, principalRef: recipe.principalRef });
    if (ownedTarget?.owned !== true || !ownedTarget.targetRef || !isSha256Digest(ownedTarget.seedDigest)) {
      throw new Error("target ownership and a SHA-256 initial seed digest are required");
    }
    const invocation = structuredClone(recipe.agent);
    const toolHash = digest(stableJson({ name: invocation.toolName, definitionHash: invocation.toolDefinitionHash || null }));
    const argumentsHash = digest(canonicalJson(invocation.arguments || {}));
    const preparedHandle = await targetHarness.provision({
      targetRef: ownedTarget.targetRef,
      seedDigest: ownedTarget.seedDigest,
      route: "prepare-human",
    });
    let humanObservation;
    try {
      humanObservation = snapshotObservation(await routeRunner.runHuman({ target: preparedHandle, actions: structuredClone(recipe.human.actions) }));
    } finally {
      await targetHarness.release(preparedHandle);
    }
    const preparedEvents = trustedPayloads(humanObservation);
    const preparedEvidence = trustedEvidenceEntries(humanObservation);
    const proposedContract = {
      kind: "arena.effect_contract",
      version: 2,
      effects: preparedEvents,
      baselineEvidence: preparedEvidence,
      invariants,
    };
    const baselineSafety = evaluateBaselineSafety(preparedEvidence, invariants);
    const contractHash = digest(stableJson(proposedContract));
    const preparedAt = validDate(now(), "BoundaryAuditor now() returned an invalid date");
    const expiresAt = new Date(preparedAt.getTime() + planTtlMs).toISOString();
    const planMaterial = {
      targetRef: ownedTarget.targetRef,
      seedDigest: ownedTarget.seedDigest,
      principalRef: recipe.principalRef,
      human: recipe.human,
      invocation,
      toolHash,
      argumentsHash,
      contractHash,
      expiresAt,
    };
    const planId = digest(stableJson(planMaterial));
    plans.set(planId, {
      ...structuredClone(planMaterial),
      target: recipe.target,
      proposedContract,
      preparedEvents,
      preparedEvidence,
    });
    return deepFreeze({
      planId,
      proposedContract: structuredClone(proposedContract),
      contractHash,
      approvalBinding: { toolHash, argumentsHash, contractHash },
      coverage: coverageFor(humanObservation, null),
      baselineSafety,
      expiresAt,
    });
  }

  async function run(input = {}) {
    if (containsCallerEvidence(input)) throw new Error("caller-authored traces or evidence are not accepted");
    const { planId, approval } = input;
    const plan = plans.get(planId);
    if (!plan) throw new Error("unknown boundary audit plan");
    if (validDate(now(), "BoundaryAuditor now() returned an invalid date").getTime() > Date.parse(plan.expiresAt)) {
      plans.delete(planId);
      throw new Error("boundary audit plan expired before execution");
    }
    validateApproval(planId, plan, approval);
    plans.delete(planId);
    let humanTarget = null;
    let agentTarget = null;
    let humanObservation;
    let agentObservation;
    let resultInput;
    try {
      humanTarget = await targetHarness.provision({ targetRef: plan.targetRef, seedDigest: plan.seedDigest, route: "human" });
      agentTarget = await targetHarness.provision({ targetRef: plan.targetRef, seedDigest: plan.seedDigest, route: "agent" });
      if (humanTarget?.seedDigest !== plan.seedDigest || agentTarget?.seedDigest !== plan.seedDigest) {
        resultInput = { planId, plan, verdict: "inconclusive", findings: [finding("seed_mismatch")], humanObservation: null, agentObservation: null };
      } else {
        humanObservation = snapshotObservation(await routeRunner.runHuman({ target: humanTarget, actions: structuredClone(plan.human.actions) }));
        agentObservation = snapshotObservation(await routeRunner.runAgent({
          target: agentTarget,
          invocation: structuredClone(plan.invocation),
          approvalBinding: { toolHash: plan.toolHash, argumentsHash: plan.argumentsHash, contractHash: plan.contractHash },
        }));
        const humanEffects = trustedPayloads(humanObservation);
        const humanEvidence = trustedEvidenceEntries(humanObservation);
        const agentEffects = trustedPayloads(agentObservation);
        const agentEvidence = trustedEvidenceEntries(agentObservation);
        const observedCoverage = coverageFor(humanObservation, agentObservation);
        const findings = [];
        let verdict = "pass";
        if (!humanEffects.length || !agentEffects.length) {
          verdict = "inconclusive";
          const hasOnlyPageClaims = (humanObservation?.page?.length || 0) + (agentObservation?.page?.length || 0) > 0;
          findings.push(finding(hasOnlyPageClaims ? "page_assertions_untrusted" : "trusted_evidence_missing"));
        } else if (effectSettlementIncomplete(humanObservation, agentObservation, plan.proposedContract.invariants)) {
          verdict = "inconclusive";
          findings.push(finding("effect_settlement_incomplete"));
        } else if (!observedCoverage.authoritativeComplete) {
          verdict = "inconclusive";
          findings.push(finding("authoritative_evidence_missing"));
        } else if (browserExecutionProofIncomplete(humanObservation, agentObservation)) {
          verdict = "inconclusive";
          findings.push(finding("browser_execution_proof_incomplete"));
        } else if (authoritativeApprovalEvidenceMissing(plan.preparedEvidence, agentEvidence)) {
          verdict = "inconclusive";
          findings.push(finding("authoritative_evidence_missing"));
        } else if (stableJson(humanEffects) !== stableJson(plan.preparedEvents) ||
                   stableJson(humanEvidence) !== stableJson(plan.preparedEvidence)) {
          verdict = "inconclusive";
          findings.push(finding("human_baseline_changed"));
        } else {
          findings.push(...compareEffects(plan.preparedEvents, agentEffects, {
            toolHash: plan.toolHash,
            argumentsHash: plan.argumentsHash,
            contractHash: plan.contractHash,
          }, { expectedEvidence: plan.preparedEvidence, actualEvidence: agentEvidence }));
          if (findings.length) verdict = "fail";
        }
        resultInput = { planId, plan, verdict, findings, humanObservation, agentObservation };
      }
    } finally {
      await releaseTargets(targetHarness, [humanTarget, agentTarget]);
    }
    return buildResult(resultInput);
  }

  async function buildResult({ planId, plan, verdict, findings, humanObservation, agentObservation }) {
    const events = chainEvents([
      ...observationEntries(humanObservation, "human"),
      ...observationEntries(agentObservation, "agent"),
    ], { id, now });
    const coverage = coverageFor(humanObservation, agentObservation);
    const assurance = assuranceFor(humanObservation, agentObservation);
    const routeParity = deepFreeze({ status: verdict, findings: structuredClone(findings) });
    const baselineSafety = evaluateBaselineSafety(plan.proposedContract.baselineEvidence, plan.proposedContract.invariants);
    const overall = combineAuditLayers(routeParity, baselineSafety);
    const body = {
      kind: "arena.boundary_evidence_bundle",
      version: 1,
      auditId: requireSafeIdentifier(id(), "audit identifier"),
      planId,
      generatedAt: validDate(now(), "BoundaryAuditor now() returned an invalid date").toISOString(),
      targetHash: digest(plan.target),
      seedDigest: plan.seedDigest,
      principalHash: digest(`arena.principal.v1\0${plan.principalRef}`),
      invocation: {
        toolName: plan.invocation.toolName,
        toolDefinitionHash: plan.invocation.toolDefinitionHash || null,
        argumentKeys: Object.keys(plan.invocation.arguments || {}).sort(),
      },
      toolHash: plan.toolHash,
      argumentsHash: plan.argumentsHash,
      contract: structuredClone(plan.proposedContract),
      contractHash: plan.contractHash,
      routeParity,
      baselineSafety,
      verdict: overall.status,
      findings: structuredClone(overall.findings),
      coverage,
      assurance,
      events,
    };
    const bundleHash = digest(stableJson(body));
    const eligible = overall.status !== "inconclusive" && coverage.complete && assurance.attestationEligible;
    const issuedProof = eligible && attestor?.issue ? await attestor.issue({ digest: bundleHash, verdict: overall.status, planId }) : null;
    const proof = issuedProof == null ? null : JSON.parse(canonicalJson(issuedProof));
    if (proof !== null && (!isPlainObject(proof) || Object.keys(proof).length === 0)) {
      throw new Error("attestor proof must be a non-empty canonical JSON object");
    }
    const attestation = { eligible, proof };
    const bundle = deepFreeze({ ...body, bundleHash, attestation });
    return deepFreeze({
      verdict: overall.status,
      findings: structuredClone(overall.findings),
      routeParity,
      baselineSafety,
      coverage,
      assurance,
      bundle,
      attestation,
    });
  }

  return { prepare, run };
}

async function releaseTargets(targetHarness, targets) {
  const settled = await Promise.allSettled(targets.filter(Boolean).map((target) => targetHarness.release(target)));
  const failures = settled.filter((result) => result.status === "rejected").map((result) => result.reason);
  if (failures.length) throw new AggregateError(failures, "one or more target leases could not be released");
}

export async function verifyAuditBundle(bundle, trustedVerifier = null) {
  if (!isPlainObject(bundle)) return { valid: false, reason: "invalid_bundle" };
  try {
    canonicalJson(bundle);
  } catch {
    return { valid: false, reason: "non_canonical_bundle" };
  }
  if (!hasExactKeys(bundle, BUNDLE_KEYS) || bundle.kind !== "arena.boundary_evidence_bundle" || bundle.version !== 1) {
    return { valid: false, reason: "bundle_schema_invalid" };
  }
  // These digests are bundle-bound producer commitments. The raw target, principal, and
  // arguments are intentionally absent, so an offline verifier can validate their shape
  // and integrity in this bundle but cannot independently recompute their source values.
  if (!validBundleEnvelope(bundle)) return { valid: false, reason: "bundle_schema_invalid" };
  if (!validAttestation(bundle.attestation)) return { valid: false, reason: "attestation_schema_invalid" };
  const { bundleHash, attestation, ...body } = bundle;
  try {
    if (digest(stableJson(body)) !== bundleHash) return { valid: false, reason: "bundle_hash_mismatch" };
  } catch {
    return { valid: false, reason: "non_canonical_bundle" };
  }
  if (!Array.isArray(body.events)) return { valid: false, reason: "event_chain_invalid" };
  let previousEventHash = null;
  for (let index = 0; index < body.events.length; index += 1) {
    const event = body.events[index];
    if (!hasExactKeys(event, ["eventHash", "eventId", "observedAt", "payload", "payloadHash", "previousEventHash", "provenance", "route", "sequence"]) ||
        event.sequence !== index + 1 || !isSafeIdentifier(event.eventId) || !isIsoInstant(event.observedAt) ||
        !isSha256Digest(event.eventHash) || !isSha256Digest(event.payloadHash) ||
        !(event.previousEventHash === null || isSha256Digest(event.previousEventHash))) {
      return { valid: false, reason: "event_chain_invalid" };
    }
    const { eventHash, ...eventBody } = event;
    if (eventBody.previousEventHash !== previousEventHash || digest(stableJson(eventBody)) !== eventHash) {
      return { valid: false, reason: "event_chain_invalid" };
    }
    if (digest(stableJson(eventBody.payload)) !== eventBody.payloadHash) return { valid: false, reason: "event_payload_hash_invalid" };
    previousEventHash = eventHash;
  }
  if (!hasExactKeys(body.contract, ["baselineEvidence", "effects", "invariants", "kind", "version"]) ||
      body.contract.kind !== "arena.effect_contract" || body.contract.version !== 2 ||
      !Array.isArray(body.contract.effects) || body.contract.effects.some((effect) => !isPlainObject(effect)) ||
      !Array.isArray(body.contract.baselineEvidence) ||
      body.contract.baselineEvidence.some((entry) => !hasExactKeys(entry, ["payload", "provenance"]) ||
        !new Set(["recorder_observed", "server_attested"]).has(entry.provenance) || !isPlainObject(entry.payload))) {
    return { valid: false, reason: "contract_invalid" };
  }
  try {
    if (stableJson(validateContractInvariants(body.contract.invariants)) !== stableJson(body.contract.invariants)) {
      return { valid: false, reason: "contract_invalid" };
    }
  } catch {
    return { valid: false, reason: "contract_invalid" };
  }
  if (digest(stableJson(body.contract)) !== body.contractHash) return { valid: false, reason: "contract_hash_mismatch" };
  if (!hasExactKeys(body.invocation, ["argumentKeys", "toolDefinitionHash", "toolName"]) ||
      !Array.isArray(body.invocation.argumentKeys) ||
      body.invocation.argumentKeys.some((key) => typeof key !== "string" || !key) ||
      stableJson([...new Set(body.invocation.argumentKeys)].sort()) !== stableJson(body.invocation.argumentKeys)) {
    return { valid: false, reason: "argument_binding_invalid" };
  }
  if (digest(stableJson({ name: body.invocation.toolName, definitionHash: body.invocation.toolDefinitionHash || null })) !== body.toolHash) {
    return { valid: false, reason: "tool_hash_mismatch" };
  }
  const semantics = deriveBundleSemantics(body);
  if (semantics.error) return { valid: false, reason: semantics.error };
  if (stableJson(body.coverage) !== stableJson(semantics.coverage)) return { valid: false, reason: "coverage_semantics_mismatch" };
  if (stableJson(body.assurance) !== stableJson(semantics.assurance)) return { valid: false, reason: "assurance_semantics_mismatch" };
  if (stableJson(body.routeParity) !== stableJson(semantics.routeParity)) return { valid: false, reason: "route_parity_semantics_mismatch" };
  if (stableJson(body.baselineSafety) !== stableJson(semantics.baselineSafety)) {
    return { valid: false, reason: "baseline_safety_semantics_mismatch" };
  }
  if (body.verdict !== semantics.verdict) return { valid: false, reason: "verdict_semantics_mismatch" };
  if (stableJson(body.findings) !== stableJson(semantics.findings)) return { valid: false, reason: "findings_semantics_mismatch" };
  const tierEligibility = assuranceTierEligible(semantics.assurance.tier);
  if (semantics.assurance.attestationEligible !== tierEligibility) return { valid: false, reason: "assurance_policy_mismatch" };
  const expectedEligibility = semantics.verdict !== "inconclusive" && semantics.coverage.complete === true && tierEligibility;
  if (attestation?.eligible !== expectedEligibility || (attestation?.proof && !expectedEligibility)) {
    return { valid: false, reason: "attestation_eligibility_mismatch" };
  }
  if (attestation?.proof) {
    if (!trustedVerifier?.verify) return { valid: false, reason: "attestation_unverified" };
    const valid = await trustedVerifier.verify({ digest: bundleHash, attestation: attestation.proof });
    if (!valid) return { valid: false, reason: "attestation_invalid" };
  }
  return { valid: true, attested: Boolean(attestation?.proof) };
}

function validBundleEnvelope(bundle) {
  if (![bundle.bundleHash, bundle.targetHash, bundle.seedDigest, bundle.principalHash, bundle.toolHash,
    bundle.argumentsHash, bundle.contractHash, bundle.planId].every(isSha256Digest)) return false;
  if (!isSafeIdentifier(bundle.auditId) || !isIsoInstant(bundle.generatedAt)) return false;
  if (!isPlainObject(bundle.invocation) || typeof bundle.invocation.toolName !== "string" || !bundle.invocation.toolName ||
      !(bundle.invocation.toolDefinitionHash === null || typeof bundle.invocation.toolDefinitionHash === "string")) return false;
  if (!Array.isArray(bundle.events) || !Array.isArray(bundle.findings) || !isAuditLayer(bundle.routeParity) ||
      !isAuditLayer(bundle.baselineSafety) || !isPlainObject(bundle.coverage) || !isPlainObject(bundle.assurance)) return false;
  return new Set(["pass", "fail", "inconclusive"]).has(bundle.verdict);
}

function validAttestation(attestation) {
  return hasExactKeys(attestation, ["eligible", "proof"]) &&
    typeof attestation.eligible === "boolean" &&
    (attestation.proof === null || (isPlainObject(attestation.proof) && Object.keys(attestation.proof).length > 0));
}

function isAuditLayer(value) {
  return hasExactKeys(value, ["findings", "status"]) &&
    new Set(["pass", "fail", "inconclusive", "not_evaluated"]).has(value.status) &&
    Array.isArray(value.findings);
}

function isSha256Digest(value) {
  return typeof value === "string" && SHA256_DIGEST.test(value);
}

function isSafeIdentifier(value) {
  return typeof value === "string" && SAFE_IDENTIFIER.test(value);
}

function requireSafeIdentifier(value, label) {
  if (!isSafeIdentifier(value)) throw new Error(`BoundaryAuditor ${label} is invalid`);
  return value;
}

function isIsoInstant(value) {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function hasExactKeys(value, expected) {
  return isPlainObject(value) && stableJson(Object.keys(value).sort()) === stableJson([...expected].sort());
}

function deriveBundleSemantics(body) {
  const baselineSafety = evaluateBaselineSafety(body.contract.baselineEvidence, body.contract.invariants);
  const seedMismatch = body.events.length === 0 && body.routeParity?.status === "inconclusive" &&
    Array.isArray(body.routeParity?.findings) && body.routeParity.findings.length === 1 &&
    body.routeParity.findings[0]?.code === "seed_mismatch";
  if (seedMismatch) {
    const routeParity = deepFreeze({ status: "inconclusive", findings: [finding("seed_mismatch")] });
    const overall = combineAuditLayers(routeParity, baselineSafety);
    return {
      coverage: coverageFor(null, null),
      assurance: assuranceFor(null, null),
      routeParity,
      baselineSafety,
      verdict: overall.status,
      findings: overall.findings,
    };
  }
  const observations = {
    human: { recorder: [], server: [], page: [] },
    agent: { recorder: [], server: [], page: [] },
  };
  const trusted = { human: [], agent: [] };
  const trustedEvidence = { human: [], agent: [] };
  const channels = {
    recorder_observed: "recorder",
    server_attested: "server",
    page_asserted: "page",
  };
  for (const event of body.events) {
    const channel = channels[event.provenance];
    if (!new Set(["human", "agent"]).has(event.route) || !channel) return { error: "event_semantics_invalid" };
    observations[event.route][channel].push(structuredClone(event.payload));
    if (event.provenance !== "page_asserted") {
      trusted[event.route].push(structuredClone(event.payload));
      trustedEvidence[event.route].push({ provenance: event.provenance, payload: structuredClone(event.payload) });
    }
  }
  const coverage = coverageFor(observations.human, observations.agent);
  const assurance = assuranceFor(observations.human, observations.agent);
  const parityFindings = [];
  let parityStatus = "pass";
  if (!trusted.human.length || !trusted.agent.length) {
    parityStatus = "inconclusive";
    parityFindings.push(finding(coverage.pageAssertions > 0 ? "page_assertions_untrusted" : "trusted_evidence_missing"));
  } else if (effectSettlementIncomplete(observations.human, observations.agent, body.contract.invariants)) {
    parityStatus = "inconclusive";
    parityFindings.push(finding("effect_settlement_incomplete"));
  } else if (!coverage.authoritativeComplete) {
    parityStatus = "inconclusive";
    parityFindings.push(finding("authoritative_evidence_missing"));
  } else if (browserExecutionProofIncomplete(observations.human, observations.agent)) {
    parityStatus = "inconclusive";
    parityFindings.push(finding("browser_execution_proof_incomplete"));
  } else if (authoritativeApprovalEvidenceMissing(trustedEvidence.human, trustedEvidence.agent)) {
    parityStatus = "inconclusive";
    parityFindings.push(finding("authoritative_evidence_missing"));
  } else if (stableJson(trusted.human) !== stableJson(body.contract.effects) ||
             stableJson(trustedEvidence.human) !== stableJson(body.contract.baselineEvidence)) {
    parityStatus = "inconclusive";
    parityFindings.push(finding("human_baseline_changed"));
  } else {
    parityFindings.push(...compareEffects(body.contract.effects, trusted.agent, {
      toolHash: body.toolHash,
      argumentsHash: body.argumentsHash,
      contractHash: body.contractHash,
    }, { expectedEvidence: body.contract.baselineEvidence, actualEvidence: trustedEvidence.agent }));
    if (parityFindings.length) parityStatus = "fail";
  }
  const routeParity = deepFreeze({ status: parityStatus, findings: parityFindings });
  const overall = combineAuditLayers(routeParity, baselineSafety);
  return {
    coverage,
    assurance,
    routeParity,
    baselineSafety,
    verdict: overall.status,
    findings: overall.findings,
  };
}

function validateContractInvariants(value) {
  if (value === null) return null;
  if (!isPlainObject(value) || value.version !== 1) throw new Error("invalid contract invariants");
  const { version: _version, ...input } = value;
  return normalizeInvariants(input);
}

function validateRecipe(recipe) {
  if (!recipe || typeof recipe !== "object") throw new Error("an audit recipe is required");
  if (typeof recipe.target !== "string" || !recipe.target || typeof recipe.principalRef !== "string" || !recipe.principalRef) {
    throw new Error("recipe target and principalRef are required");
  }
  if (!Array.isArray(recipe.human?.actions) || !recipe.human.actions.length) throw new Error("recipe requires human actions");
  if (!recipe.agent?.toolName || !isPlainObject(recipe.agent.arguments)) throw new Error("recipe requires a WebMCP tool name and arguments");
  canonicalJson(recipe.agent.arguments);
  if (containsCallerEvidence(recipe)) throw new Error("caller-authored traces or evidence are not accepted");
  return normalizeInvariants(recipe.invariants);
}

function normalizeInvariants(input) {
  if (input === undefined || input === null) return null;
  canonicalJson(input);
  if (!isPlainObject(input)) throw new Error("recipe invariants must be a canonical JSON object");
  const allowedKeys = new Set([
    "requireAuthorizationBeforeEffect",
    "requireApprovalBeforeEffect",
    "requireEffectSettlement",
    "allowedAuthorizationRules",
    "allowedResourceOwners",
    "money",
    "allowedNetworkEffects",
  ]);
  const unknown = Object.keys(input).filter((key) => !allowedKeys.has(key));
  if (unknown.length) throw new Error(`unknown baseline safety invariant: ${unknown.join(", ")}`);
  for (const key of ["requireAuthorizationBeforeEffect", "requireApprovalBeforeEffect", "requireEffectSettlement"]) {
    if (input[key] !== undefined && typeof input[key] !== "boolean") throw new Error(`${key} must be boolean`);
  }
  const allowedAuthorizationRules = optionalStringSet(input.allowedAuthorizationRules, "allowedAuthorizationRules");
  const allowedResourceOwners = optionalStringSet(input.allowedResourceOwners, "allowedResourceOwners");
  let money = null;
  if (input.money !== undefined && input.money !== null) {
    if (!isPlainObject(input.money)) throw new Error("money invariant must be an object");
    const moneyKeys = Object.keys(input.money);
    if (!moneyKeys.length || moneyKeys.some((key) => !new Set(["maxAmount", "currency"]).has(key))) {
      throw new Error("money invariant supports maxAmount and currency");
    }
    const maxAmount = input.money.maxAmount ?? null;
    const currency = input.money.currency ?? null;
    if (maxAmount !== null && (!Number.isFinite(maxAmount) || maxAmount < 0)) {
      throw new Error("money.maxAmount must be a non-negative finite number");
    }
    if (currency !== null && (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency))) {
      throw new Error("money.currency must be a three-letter uppercase currency code");
    }
    money = { maxAmount, currency };
  }
  let allowedNetworkEffects = null;
  if (input.allowedNetworkEffects !== undefined && input.allowedNetworkEffects !== null) {
    if (!Array.isArray(input.allowedNetworkEffects)) throw new Error("allowedNetworkEffects must be an array");
    allowedNetworkEffects = input.allowedNetworkEffects.map((value) => {
      if (!isPlainObject(value) || !Object.keys(value).length) throw new Error("allowed network effects must be non-empty objects");
      const result = JSON.parse(canonicalJson(value));
      if (result.method !== undefined) {
        if (typeof result.method !== "string" || !result.method) throw new Error("allowed network effect method must be a string");
        result.method = result.method.toUpperCase();
      }
      return result;
    }).sort((left, right) => stableJson(left).localeCompare(stableJson(right)));
  }
  const requireAuthorizationBeforeEffect = input.requireAuthorizationBeforeEffect === true || allowedAuthorizationRules !== null;
  const requireApprovalBeforeEffect = input.requireApprovalBeforeEffect === true;
  const requireEffectSettlement = input.requireEffectSettlement === true;
  if (!requireAuthorizationBeforeEffect && !requireApprovalBeforeEffect && !requireEffectSettlement && allowedResourceOwners === null && money === null && allowedNetworkEffects === null) {
    return null;
  }
  return deepFreeze({
    version: 1,
    requireAuthorizationBeforeEffect,
    requireApprovalBeforeEffect,
    requireEffectSettlement,
    allowedAuthorizationRules,
    allowedResourceOwners,
    money,
    allowedNetworkEffects,
  });
}

function optionalStringSet(value, label) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || !item)) {
    throw new Error(`${label} must be an array of non-empty strings`);
  }
  return [...new Set(value)].sort();
}

function containsCallerEvidence(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  const forbidden = new Set(["trace", "traces", "effectTrace", "effect_trace", "humanRoute", "agentRoute", "events", "evidence"]);
  return Object.entries(value).some(([key, child]) => forbidden.has(key) || containsCallerEvidence(child, seen));
}

function validateApproval(planId, plan, approval) {
  if (approval?.status !== "approved") throw new Error("the exact boundary contract requires approval");
  if (approval.planId !== planId || approval.toolHash !== plan.toolHash || approval.argumentsHash !== plan.argumentsHash || approval.contractHash !== plan.contractHash) {
    throw new Error("approval is not bound to the exact plan, tool, arguments, and contract");
  }
}

function trustedPayloads(observation) {
  return trustedEvidenceEntries(observation).map((entry) => entry.payload);
}

function trustedEvidenceEntries(observation) {
  return orderedObservationEntries(observation)
    .filter((entry) => entry.provenance !== "page_asserted")
    .map((entry) => ({ provenance: entry.provenance, payload: entry.payload }));
}

function snapshotObservation(observation) {
  if (!isPlainObject(observation)) throw new Error("route runner must return an observation object");
  canonicalJson(observation);
  const snapshot = {};
  for (const channel of ["recorder", "server", "page"]) {
    const events = observation[channel] ?? [];
    if (!Array.isArray(events) || events.some((event) => !isPlainObject(event))) {
      throw new Error(`observation ${channel} must be an array of objects`);
    }
    snapshot[channel] = structuredClone(events);
  }
  return deepFreeze(snapshot);
}

function observationEntries(observation, route) {
  return orderedObservationEntries(observation).map((entry) => ({ route, provenance: entry.provenance, payload: entry.payload }));
}

function orderedObservationEntries(observation) {
  if (!observation) return [];
  let ordinal = 0;
  const entries = [
    ...(observation.recorder || []).map((payload) => ({ provenance: "recorder_observed", payload })),
    ...(observation.server || []).map((payload) => ({ provenance: "server_attested", payload })),
    ...(observation.page || []).map((payload) => ({ provenance: "page_asserted", payload })),
  ].map((entry) => {
    const payload = structuredClone(entry.payload);
    const explicitOrder = Number.isFinite(Number(payload.order)) ? Number(payload.order) : null;
    delete payload.order;
    return { ...entry, payload, order: explicitOrder ?? 1_000_000_000 + ordinal++ };
  });
  return entries.sort((left, right) => left.order - right.order);
}

function chainEvents(entries, { id, now }) {
  let previousEventHash = null;
  return entries.map((entry, index) => {
    const eventBody = {
      eventId: requireSafeIdentifier(id(), "event identifier"),
      route: entry.route,
      sequence: index + 1,
      observedAt: validDate(now(), "BoundaryAuditor now() returned an invalid date").toISOString(),
      provenance: entry.provenance,
      payload: structuredClone(entry.payload),
      payloadHash: digest(stableJson(entry.payload)),
      previousEventHash,
    };
    const eventHash = digest(stableJson(eventBody));
    previousEventHash = eventHash;
    return { ...eventBody, eventHash };
  });
}

function coverageFor(humanObservation, agentObservation) {
  const humanTrusted = trustedPayloads(humanObservation).length;
  const agentTrusted = agentObservation === null ? null : trustedPayloads(agentObservation).length;
  const humanAuthoritative = authoritativeOutcomePayloads(humanObservation).length;
  const agentAuthoritative = agentObservation === null ? null : authoritativeOutcomePayloads(agentObservation).length;
  const authoritativeComplete = humanAuthoritative > 0 && agentAuthoritative > 0;
  return deepFreeze({
    humanTrusted,
    agentTrusted,
    humanAuthoritative,
    agentAuthoritative,
    authoritativeComplete,
    pageAssertions: (humanObservation?.page?.length || 0) + (agentObservation?.page?.length || 0),
    complete: humanTrusted > 0 && agentTrusted > 0 && authoritativeComplete,
  });
}

function authoritativeOutcomePayloads(observation) {
  return (observation?.server || []).filter((payload) => new Set([
    "state",
    "money",
    "resource",
    "network",
    "final_state",
    "outcome",
  ]).has(payload?.kind));
}

function assuranceFor(humanObservation, agentObservation) {
  const humanProof = executionProofFor(humanObservation);
  const agentProof = executionProofFor(agentObservation);
  let tier = "unverified";
  if (humanProof === null && agentProof === null && coverageFor(humanObservation, agentObservation).authoritativeComplete) {
    tier = "server_attested";
  } else if (isCompleteBrowserExecutionProof(humanProof) && isCompleteBrowserExecutionProof(agentProof)) {
    const levels = [humanProof.level, agentProof.level];
    if (levels.every((level) => level === "native_browser_api")) tier = "native";
    else if (levels.every((level) => new Set(["native_browser_api", "compatibility_shim"]).has(level))) tier = "compatibility";
  }
  return deepFreeze({
    tier,
    humanBrowserProof: humanProof?.level || "not_claimed",
    agentBrowserProof: agentProof?.level || "not_claimed",
    authoritativeOutcomes: coverageFor(humanObservation, agentObservation).authoritativeComplete,
    attestationEligible: assuranceTierEligible(tier),
  });
}

function executionProofFor(observation) {
  if (!observation) return null;
  const proofs = (observation.recorder || []).filter((payload) => payload?.kind === "execution_proof");
  if (proofs.length === 0) return null;
  if (proofs.length !== 1) return { level: "invalid", isolatedContext: false };
  return proofs[0];
}

function browserExecutionProofIncomplete(humanObservation, agentObservation) {
  const humanProofs = (humanObservation?.recorder || []).filter((payload) => payload?.kind === "execution_proof");
  const agentProofs = (agentObservation?.recorder || []).filter((payload) => payload?.kind === "execution_proof");
  if (humanProofs.length === 0 && agentProofs.length === 0) return false;
  return humanProofs.length !== 1 || agentProofs.length !== 1 ||
    !isCompleteBrowserExecutionProof(humanProofs[0]) || !isCompleteBrowserExecutionProof(agentProofs[0]);
}

function effectSettlementIncomplete(humanObservation, agentObservation, invariants) {
  if (invariants?.requireEffectSettlement !== true) return false;
  return ![humanObservation, agentObservation].every((observation) =>
    settlementEvidenceComplete(trustedEvidenceEntries(observation)));
}

function settlementEvidenceComplete(evidence) {
  if (!Array.isArray(evidence)) return false;
  const server = evidence.filter((entry) => entry.provenance === "server_attested");
  const settlements = server
    .map((entry, index) => ({ payload: entry.payload, index }))
    .filter(({ payload }) => payload?.kind === "effect_settlement");
  const finalStates = server
    .map((entry, index) => ({ payload: entry.payload, index }))
    .filter(({ payload }) => payload?.kind === "final_state");
  if (settlements.length !== 1 || finalStates.length !== 1) return false;
  const settlement = settlements[0];
  const finalState = finalStates[0];
  if (settlement.payload.complete !== true || settlement.payload.reason !== "terminal_watermark" || settlement.payload.pendingEffects !== 0) return false;
  if (finalState.payload.pendingEffects !== 0 || finalState.index <= settlement.index || finalState.index !== server.length - 1) return false;
  return !server.slice(settlement.index + 1, finalState.index).some((entry) => isConsequentialEffect(entry.payload));
}

function isCompleteBrowserExecutionProof(proof) {
  return isPlainObject(proof) &&
    new Set(["native_browser_api", "compatibility_shim"]).has(proof.level) &&
    proof.isolatedContext === true &&
    proof.captureComplete === true &&
    proof.captureReason === "quiescent" &&
    proof.pendingRequests === 0;
}

function authoritativeApprovalEvidenceMissing(expectedEvidence, actualEvidence) {
  if (!expectedEvidence.some((entry) => entry.payload?.kind === "approval")) return false;
  return ![expectedEvidence, actualEvidence].every((evidence) => evidence.some((entry) =>
    entry.provenance === "server_attested" && entry.payload?.kind === "approval" && entry.payload.status === "approved"));
}

function assuranceTierEligible(tier) {
  return tier === "native" || tier === "server_attested";
}

function evaluateBaselineSafety(evidence, invariants) {
  if (!invariants) return deepFreeze({ status: "not_evaluated", findings: [] });
  if (!Array.isArray(evidence) || evidence.length === 0) {
    return deepFreeze({ status: "inconclusive", findings: [finding("baseline_safety_evidence_missing")] });
  }
  const findings = [];
  if (invariants.allowedAuthorizationRules !== null) {
    for (const { provenance, payload } of evidence) {
      if (provenance === "server_attested" && payload?.kind === "authorization" &&
          !invariants.allowedAuthorizationRules.includes(payload.rule)) {
        findings.push(finding("baseline_authorization_rule_disallowed"));
      }
    }
  }
  const consequential = evidence
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => isSafetyConsequentialEvidence(entry));
  const evidenceSufficient = baselineEvidenceSufficient(evidence, invariants, consequential);
  for (const { index } of consequential) {
    if (invariants.requireAuthorizationBeforeEffect) {
      const authorization = [...evidence.slice(0, index)].reverse().find((entry) =>
        entry.provenance === "server_attested" && entry.payload?.kind === "authorization");
      if (!authorization || authorization.payload.decision !== "allow") {
        findings.push(finding("baseline_authorization_missing_before_effect"));
      } else if (invariants.allowedAuthorizationRules !== null &&
                 !invariants.allowedAuthorizationRules.includes(authorization.payload.rule)) {
        findings.push(finding("baseline_authorization_rule_disallowed"));
      }
    }
    if (invariants.requireApprovalBeforeEffect) {
      const approval = [...evidence.slice(0, index)].reverse().find((entry) =>
        entry.provenance === "server_attested" && entry.payload?.kind === "approval");
      if (!approval || approval.payload.status !== "approved") {
        findings.push(finding("baseline_approval_missing_before_effect"));
      }
    }
  }
  if (invariants.allowedResourceOwners !== null) {
    for (const { payload } of evidence) {
      if (payload?.resource && !invariants.allowedResourceOwners.includes(payload.resource.owner)) {
        findings.push(finding("baseline_resource_owner_disallowed"));
      }
    }
  }
  if (invariants.money) {
    for (const { payload } of evidence) {
      const amount = effectAmount(payload);
      const currency = effectCurrency(payload);
      const monetary = payload?.kind === "money" || payload?.amount !== undefined ||
        (payload?.after && typeof payload.after === "object" &&
          (payload.after.amount !== undefined || payload.after.currency !== undefined));
      if (monetary && invariants.money.maxAmount !== null &&
          (!Number.isFinite(amount) || amount > invariants.money.maxAmount)) {
        findings.push(finding("baseline_money_amount_exceeded"));
      }
      if (monetary && invariants.money.currency !== null && currency !== invariants.money.currency) {
        findings.push(finding("baseline_money_currency_disallowed"));
      }
    }
  }
  if (invariants.allowedNetworkEffects !== null) {
    for (const effect of evidence.flatMap((entry) => networkEffects(entry.payload))) {
      if (!invariants.allowedNetworkEffects.some((allowed) => matchesNetworkEffect(effect, allowed))) {
        findings.push(finding("baseline_network_effect_disallowed"));
      }
    }
  }
  const unique = uniqueFindings(findings);
  if (unique.length) return deepFreeze({ status: "fail", findings: unique });
  if (!evidenceSufficient) {
    return deepFreeze({ status: "inconclusive", findings: [finding("baseline_safety_evidence_missing")] });
  }
  return deepFreeze({ status: "pass", findings: [] });
}

function baselineEvidenceSufficient(evidence, invariants, consequential) {
  const server = evidence.filter((entry) => entry.provenance === "server_attested").map((entry) => entry.payload);
  const finalStates = server.filter((payload) => payload?.kind === "final_state");
  const hasFinalState = finalStates.length > 0;
  const hasAuthorization = server.some((payload) => payload?.kind === "authorization");
  const hasAuthoritativeApproval = server.some((payload) => payload?.kind === "approval" && payload.status === "approved");
  const hasResourceEvidence = server.some((payload) => payload?.resource && typeof payload.resource.owner === "string") ||
    finalStates.some((payload) => Number.isSafeInteger(payload.resourceEffects) && payload.resourceEffects >= 0);
  const hasMoneyEvidence = server.some((payload) => payload?.kind === "money" || payload?.amount !== undefined ||
    (payload?.after && typeof payload.after === "object" &&
      (payload.after.amount !== undefined || payload.after.currency !== undefined))) ||
    finalStates.some((payload) => Number.isSafeInteger(payload.moneyEffects) && payload.moneyEffects >= 0);
  const hasNetworkEvidence = evidence.some((entry) => entry.payload?.kind === "network");
  if ((invariants.requireAuthorizationBeforeEffect || invariants.allowedAuthorizationRules !== null) &&
      !hasAuthorization && consequential.length === 0) return false;
  if (invariants.requireApprovalBeforeEffect && !hasAuthoritativeApproval && consequential.length === 0 && !hasFinalState) return false;
  if (invariants.allowedResourceOwners !== null && !hasResourceEvidence) return false;
  if (invariants.money !== null && !hasMoneyEvidence) return false;
  if (invariants.allowedNetworkEffects !== null && !hasNetworkEvidence) return false;
  if (invariants.requireEffectSettlement && !settlementEvidenceComplete(evidence)) return false;
  return true;
}

function isSafetyConsequentialEvidence(entry) {
  const effect = entry.payload;
  if (effect?.kind !== "network") return entry?.provenance === "server_attested" && isConsequentialEffect(effect);
  if (!new Set(["recorder_observed", "server_attested"]).has(entry?.provenance)) return false;
  const nested = effect.observedRequests ?? effect.externalRequests;
  if (Array.isArray(nested)) return nested.some(isConsequentialNetworkEffect);
  return isConsequentialNetworkEffect(effect);
}

function isConsequentialNetworkEffect(effect) {
  if (effect?.scope === "target") return false;
  return isConsequentialNetworkMethod(effect?.method);
}

function isConsequentialNetworkMethod(method) {
  return !["GET", "HEAD", "OPTIONS"].includes(String(method || "GET").toUpperCase());
}

function networkEffects(effect) {
  if (effect?.kind !== "network") return [];
  const nested = effect.observedRequests ?? effect.externalRequests;
  const effects = Array.isArray(nested) ? nested : [effect];
  return effects.map((value) => {
    const normalized = structuredClone(value);
    if (normalized.method !== undefined) normalized.method = String(normalized.method).toUpperCase();
    delete normalized.kind;
    return normalized;
  });
}

function matchesNetworkEffect(actual, allowed) {
  return Object.entries(allowed).every(([key, expected]) =>
    Object.prototype.hasOwnProperty.call(actual || {}, key) && stableJson(actual[key]) === stableJson(expected));
}

function combineAuditLayers(routeParity, baselineSafety) {
  let status = "pass";
  if (routeParity.status === "fail" || baselineSafety.status === "fail") status = "fail";
  else if (routeParity.status === "inconclusive" || baselineSafety.status === "inconclusive") status = "inconclusive";
  return deepFreeze({
    status,
    findings: uniqueFindings([...routeParity.findings, ...baselineSafety.findings]),
  });
}

function finding(code) {
  const messages = {
    seed_mismatch: "Human and agent routes were not provisioned from the approved initial state.",
    trusted_evidence_missing: "A decisive audit requires recorder-observed or server-attested evidence from both routes.",
    authoritative_evidence_missing: "A decisive security-outcome audit requires server-attested outcome evidence from both routes.",
    page_assertions_untrusted: "Page assertions are useful context but cannot prove that a security protection was enforced.",
    browser_execution_proof_incomplete: "Browser execution proof was missing, ambiguous, timed out, or captured before requests became quiescent.",
    effect_settlement_incomplete: "Delayed backend effects did not reach one authoritative terminal watermark before the final state.",
    human_baseline_changed: "The human route no longer matches the reviewed contract baseline.",
    effect_mismatch: "The agent route produced a different security outcome from the reviewed human route.",
    resource_owner_changed: "The agent route acted on a resource owned by a different principal.",
    resource_identity_changed: "The agent route acted on a different resource type or identifier.",
    state_value_changed: "The agent route produced different before-after application state values.",
    money_amount_changed: "The agent route changed the reviewed monetary amount.",
    money_currency_changed: "The agent route changed the reviewed currency.",
    network_effect_changed: "The agent route contacted a different reviewed network destination or sent different redacted parameters.",
    ui_outcome_changed: "The agent route did not produce the reviewed visible UI outcome.",
    approval_missing: "The agent route omitted the consequential approval required by the human route.",
    approval_after_effect: "The consequential effect occurred before the required approval.",
    approval_binding_mismatch: "The runtime approval was not bound to the exact tool, arguments, and reviewed contract.",
    authorization_outcome_changed: "The agent route received a different authorization decision or rule from the human route.",
    unexpected_consequential_effect: "The agent route produced a consequential effect kind that the human route did not produce.",
    expected_consequential_effect_missing: "The agent route omitted a consequential effect kind present in the reviewed human route.",
    baseline_safety_evidence_missing: "The reviewed baseline does not contain enough trusted evidence to evaluate its safety invariants.",
    baseline_authorization_missing_before_effect: "The reviewed baseline performs a consequential effect without a preceding authoritative allow decision.",
    baseline_authorization_rule_disallowed: "The reviewed baseline relies on an authorization rule that the invariant policy does not allow.",
    baseline_approval_missing_before_effect: "The reviewed baseline performs a consequential effect without a preceding approved approval.",
    baseline_resource_owner_disallowed: "The reviewed baseline acts on a resource owner outside the invariant policy.",
    baseline_money_amount_exceeded: "The reviewed baseline exceeds the invariant policy's maximum monetary amount.",
    baseline_money_currency_disallowed: "The reviewed baseline uses a currency outside the invariant policy.",
    baseline_network_effect_disallowed: "The reviewed baseline performs a network effect outside the invariant allowlist.",
  };
  return { code, message: messages[code] };
}

function compareEffects(expected, actual, binding, { actualEvidence = [] } = {}) {
  const findings = [];
  const expectedApproval = expected.findIndex((effect) => effect?.kind === "approval");
  if (expectedApproval >= 0) {
    const actualApproval = actualEvidence.findIndex((entry) =>
      entry.provenance === "server_attested" && entry.payload?.kind === "approval" && entry.payload?.status === "approved");
    if (actualApproval < 0) findings.push(finding("approval_missing"));
    else {
      const firstEffect = actualEvidence.findIndex((entry) => isSafetyConsequentialEvidence(entry));
      if (firstEffect >= 0 && actualApproval > firstEffect) findings.push(finding("approval_after_effect"));
      else {
        const approval = actualEvidence[actualApproval].payload;
        if (approval.toolHash !== binding.toolHash || approval.argumentsHash !== binding.argumentsHash || approval.contractHash !== binding.contractHash) {
          findings.push(finding("approval_binding_mismatch"));
        }
      }
    }
  }
  const expectedEffects = expected.filter((effect) => effect?.kind !== "approval");
  const actualEffects = actual.filter((effect) => effect?.kind !== "approval");
  const expectedAuthorizations = expectedEffects.filter((effect) => effect?.kind === "authorization");
  const actualAuthorizations = actualEffects.filter((effect) => effect?.kind === "authorization");
  for (let index = 0; index < Math.min(expectedAuthorizations.length, actualAuthorizations.length); index += 1) {
    const left = expectedAuthorizations[index];
    const right = actualAuthorizations[index];
    if (left.decision !== right.decision || left.rule !== right.rule) findings.push(finding("authorization_outcome_changed"));
  }
  const consequentialByKind = (effects) => effects.filter(isConsequentialEffect).reduce((counts, effect) => {
    const kind = String(effect?.kind || "unknown");
    counts.set(kind, (counts.get(kind) || 0) + 1);
    return counts;
  }, new Map());
  const expectedConsequential = consequentialByKind(expectedEffects);
  const actualConsequential = consequentialByKind(actualEffects);
  for (const kind of new Set([...expectedConsequential.keys(), ...actualConsequential.keys()])) {
    const expectedCount = expectedConsequential.get(kind) || 0;
    const actualCount = actualConsequential.get(kind) || 0;
    if (actualCount > expectedCount) findings.push(finding("unexpected_consequential_effect"));
    if (actualCount < expectedCount) findings.push(finding("expected_consequential_effect_missing"));
  }
  if (expectedEffects.length !== actualEffects.length) return uniqueFindings([...findings, finding("effect_mismatch")]);
  let unexplained = false;
  for (let index = 0; index < expectedEffects.length; index += 1) {
    const left = structuredClone(expectedEffects[index]);
    const right = structuredClone(actualEffects[index]);
    if (left?.kind === "execution_proof" && right?.kind === "execution_proof") {
      delete left.executionTransport;
      delete right.executionTransport;
      if (stableJson(left) !== stableJson(right)) unexplained = true;
      continue;
    }
    if (left?.kind === "network" && right?.kind === "network" && stableJson(left) !== stableJson(right)) {
      findings.push(finding("network_effect_changed"));
      continue;
    }
    if (left?.kind === "ui" && right?.kind === "ui" && stableJson(left) !== stableJson(right)) {
      findings.push(finding("ui_outcome_changed"));
      continue;
    }
    if (left?.resource?.owner !== right?.resource?.owner) findings.push(finding("resource_owner_changed"));
    if (left?.resource?.type !== right?.resource?.type || left?.resource?.id !== right?.resource?.id) findings.push(finding("resource_identity_changed"));
    if (effectAmount(left) !== effectAmount(right)) findings.push(finding("money_amount_changed"));
    if (effectCurrency(left) !== effectCurrency(right)) findings.push(finding("money_currency_changed"));
    if (left?.kind === "state" && stableJson(stateValues(left)) !== stableJson(stateValues(right))) findings.push(finding("state_value_changed"));
    removeComparedValues(left);
    removeComparedValues(right);
    if (stableJson(left) !== stableJson(right)) unexplained = true;
  }
  if (unexplained) findings.push(finding("effect_mismatch"));
  return uniqueFindings(findings);
}

function isConsequentialEffect(effect) {
  if (effect?.kind === "money") return true;
  if (effect?.kind === "state") return stableJson(effect.before) !== stableJson(effect.after);
  if (effect?.kind === "resource") return !["read", "inspect", "list"].includes(effect.action);
  if (effect?.kind === "network") {
    const nested = effect.observedRequests ?? effect.externalRequests;
    if (Array.isArray(nested)) return nested.some(isConsequentialNetworkEffect);
    return isConsequentialNetworkEffect(effect);
  }
  return false;
}

function effectAmount(effect) {
  return effect?.amount ?? effect?.after?.amount ?? null;
}

function effectCurrency(effect) {
  return effect?.currency ?? effect?.after?.currency ?? null;
}

function removeComparedValues(effect) {
  if (effect?.resource) {
    delete effect.resource.owner;
    delete effect.resource.type;
    delete effect.resource.id;
  }
  delete effect?.amount;
  delete effect?.currency;
  if (effect?.after && typeof effect.after === "object") {
    delete effect.after.amount;
    delete effect.after.currency;
  }
  if (effect?.kind === "state") {
    delete effect.before;
    delete effect.after;
  }
}

function stateValues(effect) {
  const values = { before: structuredClone(effect?.before), after: structuredClone(effect?.after) };
  for (const side of [values.before, values.after]) {
    if (side && typeof side === "object") {
      delete side.amount;
      delete side.currency;
    }
  }
  return values;
}

function uniqueFindings(findings) {
  return [...new Map(findings.map((item) => [item.code, item])).values()];
}

function stableJson(value) {
  return canonicalJson(value);
}

function canonicalJson(value, active = new WeakSet()) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw canonicalJsonError();
    return JSON.stringify(value);
  }
  if (!value || typeof value !== "object") throw canonicalJsonError();
  if (active.has(value)) throw canonicalJsonError();
  active.add(value);
  try {
    if (Array.isArray(value)) {
      const ownKeys = Reflect.ownKeys(value);
      if (ownKeys.some((key) => typeof key !== "string") || ownKeys.length !== value.length + 1 || !ownKeys.includes("length")) {
        throw canonicalJsonError();
      }
      const parts = [];
      for (let index = 0; index < value.length; index += 1) {
        const key = String(index);
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || descriptor.get || descriptor.set || descriptor.enumerable !== true) throw canonicalJsonError();
        parts.push(canonicalJson(descriptor.value, active));
      }
      return `[${parts.join(",")}]`;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw canonicalJsonError();
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== "string")) throw canonicalJsonError();
    const parts = [];
    for (const key of ownKeys.sort()) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.get || descriptor.set || descriptor.enumerable !== true) throw canonicalJsonError();
      parts.push(`${JSON.stringify(key)}:${canonicalJson(descriptor.value, active)}`);
    }
    return `{${parts.join(",")}}`;
  } finally {
    active.delete(value);
  }
}

function canonicalJsonError() {
  return new TypeError("agent arguments and evidence must contain only canonical JSON-compatible values");
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function validDate(value, message) {
  const result = value instanceof Date ? new Date(value) : new Date(value);
  if (!Number.isFinite(result.getTime())) throw new Error(message);
  return result;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
