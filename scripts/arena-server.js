import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";

import { loadArenaConfig } from "../src/arena-config.js";
import { createArenaProof, generateArenaProofKeys } from "../src/arena-proof.js";
import { ARENA_CSS, ARENA_SCRIPT, renderArenaPage } from "../src/arena-page.js";
import { createTrustedIssuerVerifier } from "../src/identity.js";
import { createBehavioralVerifier } from "../src/behavioral-verifier.js";
import { createBoundaryAuditor, verifyAuditBundle } from "../src/boundary-audit.js";
import { createCheckoutAuditAdapter } from "../src/checkout-audit-adapter.js";
import { compareAgentProfiles } from "../src/agent-regression.js";
import { buildCiArtifacts } from "../src/ci-report.js";
import { createIncidentLab } from "../src/incident-lab.js";
import { createMeasuredAuditService } from "../src/measured-audit-service.js";
import { analyzeMcpManifest } from "../src/mcp.js";
import { createMemoryRepository, createSqliteRepository, scopedStateStore } from "../src/state-store.js";
import { openSecret, sealSecret } from "../src/secret-envelope.js";
import { createTrustGateway } from "../src/trust.js";
import { createWebMcpBrowserRunner } from "../src/webmcp-runner.js";

export function createArenaServer({
  config = null,
  secret = config?.signingSecret || process.env.ARENA_SIGNING_SECRET || "arena-local-demo-signing-secret",
  repository = createMemoryRepository(),
  identityVerifier = config?.trustedIssuers?.length ? createTrustedIssuerVerifier({ issuers: config.trustedIssuers }) : null,
  browserRunner = null,
  requireVerifiedAgents = config?.requireVerifiedAgents || false,
  protectHumanRoutes = config?.protectHumanRoutes || false,
  remoteInspectionEnabled = config?.remoteInspectionEnabled || false,
  remoteExecutionEnabled = config?.remoteExecutionEnabled || false,
  operatorToken = config?.operatorToken || "",
  originTrialToken = config?.originTrialToken || "",
  now,
  id,
} = {}) {
  const runner = browserRunner || (remoteInspectionEnabled ? createWebMcpBrowserRunner({
    executablePath: config?.browserExecutable,
    mode: config?.browserMode || "native",
    headless: config?.browserHeadless ?? false,
    allowPrivateTargets: config?.allowPrivateTargets || false,
  }) : null);
  const proof = createPersistedProof(repository, { now, id, secret });
  const checkoutAdapter = createCheckoutAuditAdapter();
  const boundaryAttestor = createBoundaryAttestor(proof);
  const checkoutAuditor = createBoundaryAuditor({
    targetHarness: checkoutAdapter.targetHarness,
    routeRunner: checkoutAdapter.routeRunner,
    attestor: boundaryAttestor,
    ...(now ? { now } : {}),
  });
  const measuredApprovalDecisions = new Map();
  const measuredAudits = createMeasuredAuditService({
    presets: checkoutPresets(),
    repository,
    ...(now ? { clock: now } : {}),
    async prepare({ preset }) {
      const recipe = await checkoutAdapter.createRecipe({ target: preset.target });
      const prepared = await checkoutAuditor.prepare(recipe);
      return {
        execution: {
          planId: prepared.planId,
          approvalBinding: prepared.approvalBinding,
        },
        review: {
          adapterId: checkoutAdapter.manifest.id,
          claimScope: checkoutAdapter.manifest.claimScope[0],
          trustMode: checkoutAdapter.manifest.trustMode,
          targetPreset: preset.label,
          toolName: recipe.agent.toolName,
          argumentKeys: Object.keys(recipe.agent.arguments).sort(),
          contractHash: prepared.contractHash,
          effects: prepared.proposedContract.effects,
          invariants: prepared.proposedContract.invariants,
          baselineSafety: prepared.baselineSafety,
        },
        expiresAt: prepared.expiresAt,
      };
    },
    async run({ execution }) {
      return checkoutAuditor.run({
        planId: execution.planId,
        approval: {
          status: "approved",
          planId: execution.planId,
          ...execution.approvalBinding,
        },
      });
    },
    onApprovalRequired({ audit, decide }) {
      measuredApprovalDecisions.set(audit.id, decide);
    },
  });
  const behavioralVerifier = createBehavioralVerifier({ now, id });
  const incidentLab = createIncidentLab({ verifier: behavioralVerifier, now });
  const gateway = createTrustGateway({
    secret,
    now,
    id,
    requireVerifiedAgents,
    stateStore: scopedStateStore(repository, "trust"),
    proof,
    tools: demoTools(repository, { runner, remoteExecutionEnabled }),
  });

  const server = createServer(async (request, response) => {
    try {
      const route = new URL(request.url, "http://127.0.0.1");
      if (request.method === "GET" && route.pathname === "/") return send(response, 200, "text/html; charset=utf-8", renderArenaPage(), pageHeaders(originTrialToken));
      if (request.method === "GET" && route.pathname === "/arena.js") return send(response, 200, "text/javascript; charset=utf-8", ARENA_SCRIPT, pageHeaders(originTrialToken));
      if (request.method === "GET" && route.pathname === "/arena.css") return send(response, 200, "text/css; charset=utf-8", ARENA_CSS, pageHeaders(originTrialToken));
      if (request.method === "GET" && route.pathname === "/.well-known/arena-proof.json") {
        return json(response, 200, { algorithm: "Ed25519", issuer: proof.issuer, key_id: proof.keyId, public_key_pem: proof.exportPublicKey() });
      }
      if (request.method === "GET" && route.pathname === "/api/state") {
        if (protectHumanRoutes) requireOperator(request, operatorToken);
        return json(response, 200, snapshot(gateway, repository));
      }
      if (request.method === "GET" && route.pathname === "/api/tools") {
        return json(response, 200, { tools: gateway.getTools() });
      }
      if (request.method === "GET" && route.pathname === "/api/scenarios") {
        return json(response, 200, { scenarios: incidentLab.listScenarios() });
      }
      if (request.method === "GET" && route.pathname === "/api/status") {
        return json(response, 200, {
          identity_mode: requireVerifiedAgents ? "trusted_issuer_required" : "local_demo_allowed",
          trusted_issuers: identityVerifier?.trustedIssuers?.() || [],
          persistence: repository.durability,
          remote_browser: {
            inspection_enabled: remoteInspectionEnabled,
            execution_enabled: remoteExecutionEnabled,
            proof_mode: runner?.mode || "disabled",
          },
        });
      }
      if (request.method === "POST" && route.pathname === "/api/passports") {
        if (protectHumanRoutes) requireOperator(request, operatorToken);
        const body = await readJson(request);
        const agentIdentity = body.agentIdentityToken ? await verifyIdentity(identityVerifier, body.agentIdentityToken) : null;
        return json(response, 200, gateway.issuePassport({
          principalId: body.principalId,
          agentId: body.agentId,
          agentIdentity,
          scopes: body.scopes,
          maxAmount: body.maxAmount,
          ttlSeconds: body.ttlSeconds,
        }));
      }
      if (request.method === "POST" && route.pathname === "/api/delegations/revoke") {
        if (protectHumanRoutes) requireOperator(request, operatorToken);
        return json(response, 200, gateway.revoke(await readJson(request)));
      }
      if (request.method === "POST" && route.pathname === "/api/tools/execute") {
        const result = await gateway.requestToolExecution(await readJson(request));
        return json(response, 200, decorateReceipt(result, gateway));
      }
      if (request.method === "POST" && route.pathname.startsWith("/api/approvals/")) {
        if (protectHumanRoutes) requireOperator(request, operatorToken);
        const approvalId = decodeURIComponent(route.pathname.slice("/api/approvals/".length));
        const result = await gateway.resolveApproval({ approvalId, ...await readJson(request) });
        return json(response, 200, decorateReceipt(result, gateway));
      }
      if (request.method === "POST" && route.pathname === "/api/tools/audit") {
        const body = await readJson(request);
        const audit = analyzeMcpManifest({ name: "webmcp-runtime", protocolVersion: "2025-06-18", tools: body.tools || [] });
        return json(response, 200, audit);
      }
      if (request.method === "POST" && route.pathname === "/api/proof/verify") {
        const body = await readJson(request);
        return json(response, 200, { valid: proof.verify(body.attestation), key_id: proof.keyId });
      }
      if (request.method === "POST" && route.pathname === "/api/boundary-bundles/inspect") {
        const body = await readJson(request);
        return json(response, 200, await inspectBoundaryBundle(body.bundle, boundaryAttestor));
      }
      if (request.method === "POST" && route.pathname === "/api/measured-audits") {
        const body = await readJson(request);
        assertServerOwnedMeasuredStart(body);
        const audit = await measuredAudits.start({
          ...body,
          actor: { type: "agent", id: "browser_agent" },
        });
        return json(response, 201, audit);
      }
      const measuredPollMatch = route.pathname.match(/^\/api\/measured-audits\/([^/]+)$/);
      if (request.method === "GET" && measuredPollMatch) {
        const auditId = decodeURIComponent(measuredPollMatch[1]);
        return json(response, 200, await measuredAudits.poll({
          auditId,
          actor: { type: "agent", id: "browser_agent" },
        }));
      }
      const measuredApprovalMatch = route.pathname.match(/^\/api\/measured-audits\/([^/]+)\/approve$/);
      if (request.method === "POST" && measuredApprovalMatch) {
        if (protectHumanRoutes) requireOperator(request, operatorToken);
        const auditId = decodeURIComponent(measuredApprovalMatch[1]);
        const body = await readJson(request);
        assertExactObject(body, ["humanId"], "measured audit approval");
        if (typeof body.humanId !== "string" || !body.humanId) throw httpError(400, "humanId is required");
        const decide = measuredApprovalDecisions.get(auditId);
        if (!decide) throw httpError(404, "measured audit is not awaiting human approval");
        return json(response, 200, await decide({ decision: "approve", humanId: body.humanId }));
      }
      const scenarioMatch = route.pathname.match(/^\/api\/scenarios\/([^/]+)\/run$/);
      if (request.method === "POST" && scenarioMatch) {
        const body = await readJson(request);
        const run = incidentLab.run({ scenarioId: decodeURIComponent(scenarioMatch[1]), version: body.version, mode: body.mode });
        const attestation = proof.issue({
          kind: "arena.synthetic_fixture_receipt",
          version: 1,
          claim_scope: "synthetic_fixture",
          audit_id: run.report.id,
          scenario_id: run.scenario.id,
          scenario_version: run.version,
          enforcement_mode: run.mode,
          verdict: run.report.verdict,
          finding_codes: run.report.findings.map((finding) => finding.code),
          contract_hash: digestJson(run.contract),
          effect_trace_hash: digestJson(run.routes),
        });
        const result = { ...run, attestation, attestation_verified: proof.verify(attestation) };
        recordIncidentRun(repository, result);
        return json(response, 200, result);
      }
      if (request.method === "POST" && route.pathname === "/api/contracts/mine") {
        return json(response, 410, { error: "caller-authored traces are no longer accepted; use the recorder-owned target audit" });
      }
      if (request.method === "POST" && route.pathname === "/api/contracts/approve") {
        if (protectHumanRoutes) requireOperator(request, operatorToken);
        const body = await readJson(request);
        if (!body.principalId) throw new Error("principalId is required");
        if (body.contract?.kind !== "arena.effect_contract" || body.contract?.version !== 1) throw new Error("a version 1 Arena effect contract is required");
        if (body.contract.source !== "synthetic_fixture" || body.contract.claim_scope !== "synthetic_fixture") {
          throw httpError(403, "only a contract produced by Arena's synthetic fixture corpus can be reviewed here");
        }
        const registeredFixture = repository.read("incident_runs", []).some((run) => digestJson(run.contract) === digestJson(body.contract));
        if (!registeredFixture) throw httpError(403, "the synthetic contract was not produced by this Arena instance");
        const contract = { ...body.contract, review_status: "approved", approved_by: body.principalId, approved_at: new Date().toISOString() };
        const attestation = proof.issue({ kind: "arena.synthetic_contract_review", version: 1, claim_scope: "synthetic_fixture", contract_hash: digestJson(contract), approved_by: body.principalId });
        const contracts = repository.read("effect_contracts", []);
        const existing = contracts.findIndex((candidate) => candidate.contract.tool_name === contract.tool_name);
        const record = { contract, attestation };
        if (existing >= 0) contracts[existing] = record;
        else contracts.push(record);
        repository.write("effect_contracts", contracts);
        return json(response, 200, { ...record, attestation_verified: proof.verify(attestation) });
      }
      if (request.method === "POST" && route.pathname === "/api/boundary-audits/run") {
        return json(response, 410, { error: "caller-authored boundary evidence is no longer accepted; use the recorder-owned target audit" });
      }
      if (request.method === "POST" && route.pathname === "/api/ci/artifacts") {
        return json(response, 200, buildCiArtifacts(await readJson(request)));
      }
      if (request.method === "POST" && route.pathname === "/api/agents/compare") {
        const comparison = compareAgentProfiles(await readJson(request));
        const comparisons = repository.read("agent_regressions", []);
        comparisons.push(comparison);
        repository.write("agent_regressions", comparisons.slice(-100));
        return json(response, 200, comparison);
      }
      if (request.method === "POST" && route.pathname === "/api/fix-plan") {
        return json(response, 200, fixPlan(await readJson(request)));
      }
      if (request.method === "POST" && route.pathname === "/api/browser/inspect") {
        requireOperator(request, operatorToken);
        if (!remoteInspectionEnabled || !runner) throw httpError(403, "remote WebMCP inspection is disabled");
        const result = await runner.inspect(await readJson(request));
        recordBrowserRun(repository, { operation: "inspect", ...result });
        return json(response, 200, result);
      }
      if (request.method === "POST" && route.pathname === "/api/browser/execute") {
        requireOperator(request, operatorToken);
        if (!remoteExecutionEnabled || !runner) throw httpError(403, "remote WebMCP execution is disabled");
        const body = await readJson(request);
        const result = await gateway.submit({
          passport: body.passport,
          agentId: body.agentId,
          toolName: "execute_remote_webmcp",
          arguments: { url: body.url, remoteToolName: body.toolName, arguments: body.arguments || {} },
          idempotencyKey: body.idempotencyKey,
        });
        return json(response, 200, decorateReceipt(result, gateway));
      }
      return json(response, 404, { error: "not_found" });
    } catch (error) {
      return json(response, error.statusCode || 400, { error: error.message });
    }
  });
  server.once("close", () => repository.close());
  return server;
}

function createPersistedProof(repository, { now, id, secret }) {
  const keys = withRepositoryWriteLock(repository, () => {
    const stored = repository.read("proof_keys", null);
    if (stored?.privateKeyEnvelope && stored?.publicKey) {
      return { privateKey: openSecret(stored.privateKeyEnvelope, secret, "arena.proof.private-key.v1"), publicKey: stored.publicKey };
    }
    if (stored?.privateKey && stored?.publicKey) {
      repository.write("proof_keys", protectedProofKeys(stored, secret));
      return stored;
    }
    const generated = generateArenaProofKeys();
    repository.write("proof_keys", protectedProofKeys(generated, secret));
    return generated;
  });
  const proof = createArenaProof({ ...keys, issuer: "arena-local", now, id });
  return {
    ...proof,
    issue(evidence) {
      return withRepositoryWriteLock(repository, () => {
        const issuer = createArenaProof({ ...keys, issuer: "arena-local", previousHash: repository.read("proof_chain_head", null), now, id });
        const attestation = issuer.issue(evidence);
        repository.write("proof_chain_head", issuer.getLastHash());
        return attestation;
      });
    },
    getLastHash: () => repository.read("proof_chain_head", null),
  };
}

function createBoundaryAttestor(proof) {
  return Object.freeze({
    async issue({ digest, verdict, planId }) {
      return proof.issue({
        kind: "arena.boundary_bundle_attestation",
        version: 1,
        claim_scope: "owned_fixture:checkout",
        bundle_hash: digest,
        verdict,
        plan_id: planId,
      });
    },
    async verify({ digest, attestation }) {
      return attestation?.kind === "arena.boundary_bundle_attestation" &&
        attestation.bundle_hash === digest &&
        proof.verify(attestation);
    },
  });
}

function checkoutPresets() {
  return Object.freeze({
    checkout_vulnerable: Object.freeze({
      label: "Checkout · vulnerable delayed charge",
      target: "arena-owned://checkout/?version=vulnerable",
    }),
    checkout_fixed: Object.freeze({
      label: "Checkout · fixed preview",
      target: "arena-owned://checkout/?version=fixed",
    }),
  });
}

function assertServerOwnedMeasuredStart(body) {
  try {
    assertExactObject(body, ["presetId", "idempotencyKey"], "measured audit start");
  } catch {
    throw httpError(400, "measured audits accept only server-owned preset fields: presetId and idempotencyKey");
  }
}

function assertExactObject(value, allowed, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw httpError(400, `${label} must be an object`);
  const extra = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extra.length) throw httpError(400, `${label} contains unsupported fields: ${extra.join(", ")}`);
}

function withRepositoryWriteLock(repository, callback) {
  return repository.withWriteLock ? repository.withWriteLock(callback) : callback();
}

function protectedProofKeys(keys, secret) {
  return {
    version: 1,
    publicKey: keys.publicKey,
    privateKeyEnvelope: sealSecret(keys.privateKey, secret, "arena.proof.private-key.v1"),
  };
}

function demoTools(repository, { runner = null, remoteExecutionEnabled = false } = {}) {
  const tools = [
    {
      name: "search_flights",
      description: "Search flights without changing external state.",
      scope: "flights:read",
      risk: "read_only",
      requiresApproval: false,
      execute: async ({ from = "DEL", to = "BOM" }) => ({
        flights: [
          { id: "AI-202", from: cleanCode(from), to: cleanCode(to), price: 12000, duration: "2h 10m" },
          { id: "6E-531", from: cleanCode(from), to: cleanCode(to), price: 13850, duration: "2h 20m" },
        ],
      }),
    },
    {
      name: "book_flight",
      description: "Book a selected flight after spend-limit and human-approval checks.",
      scope: "flights:book",
      risk: "financial",
      requiresApproval: true,
      amount: ({ price }) => price,
      validate: ({ flightId, price }) => !flightId || !Number.isFinite(Number(price)) || Number(price) <= 0 ? "flightId and a positive price are required" : null,
      execute: async ({ flightId, price }) => {
        const bookings = repository.read("bookings", []);
        const booking = { id: `booking_${bookings.length + 1}`, flight_id: String(flightId), price: Number(price), status: "confirmed" };
        bookings.push(booking);
        repository.write("bookings", bookings);
        return booking;
      },
    },
  ];
  if (runner && remoteExecutionEnabled) {
    tools.push({
      name: "execute_remote_webmcp",
      description: "Execute one WebMCP tool on an explicitly authorized target after human approval.",
      scope: "browser:execute",
      risk: "external_write",
      requiresApproval: true,
      validate: ({ url, remoteToolName }) => !url || !remoteToolName ? "url and remoteToolName are required" : null,
      execute: async ({ url, remoteToolName, arguments: args = {} }) => {
        const result = await runner.execute({ url, toolName: remoteToolName, arguments: args });
        recordBrowserRun(repository, { operation: "execute", ...result });
        return result;
      },
    });
  }
  return tools;
}

function snapshot(gateway, repository) {
  const state = gateway.getSnapshot();
  return {
    ...state,
    receipt_verifications: Object.fromEntries(state.receipts.map((receipt) => [receipt.id || receipt.attestation_id, gateway.verifyReceipt(receipt)])),
    bookings: repository.read("bookings", []),
    browser_runs: repository.read("browser_runs", []),
    incident_runs: repository.read("incident_runs", []),
    agent_regressions: repository.read("agent_regressions", []),
    effect_contracts: repository.read("effect_contracts", []),
    tools: gateway.getTools(),
  };
}

async function verifyIdentity(identityVerifier, token) {
  if (!identityVerifier?.verifyAgentToken) throw new Error("trusted agent identity verification is not configured");
  return identityVerifier.verifyAgentToken(token);
}

function requireOperator(request, expectedToken) {
  if (!expectedToken) throw httpError(503, "operator authentication is not configured");
  const authorization = request.headers.authorization || "";
  const suppliedToken = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const supplied = Buffer.from(suppliedToken);
  const expected = Buffer.from(expectedToken);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw httpError(401, "operator authentication failed");
}

function httpError(statusCode, message) {
  return Object.assign(new Error(message), { statusCode });
}

function recordBrowserRun(repository, run) {
  const runs = repository.read("browser_runs", []);
  runs.push({ ...run, recorded_at: new Date().toISOString() });
  repository.write("browser_runs", runs.slice(-100));
}

function recordIncidentRun(repository, run) {
  const runs = repository.read("incident_runs", []);
  runs.push(run);
  repository.write("incident_runs", runs.slice(-100));
}

async function inspectBoundaryBundle(bundle, trustedVerifier = null) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    throw httpError(400, "a boundary evidence bundle is required");
  }
  if (bundle.kind !== "arena.boundary_evidence_bundle" || bundle.version !== 1) {
    throw httpError(400, "only version 1 Arena boundary evidence bundles can be inspected");
  }
  if (bundle.source === "synthetic_fixture" || bundle.claim_scope === "synthetic_fixture" || bundle.contract?.source === "synthetic_fixture") {
    throw httpError(400, "authored incident fixtures are not measured boundary bundles");
  }

  const verifier = bundle.attestation?.proof?.kind === "arena.boundary_bundle_attestation" ? trustedVerifier : null;
  const verified = await verifyAuditBundle(bundle, verifier);
  const semanticValid = verified.valid === true || new Set(["attestation_unverified", "attestation_invalid"]).has(verified.reason);
  const context = createInspectionContext();
  const allEvents = Array.isArray(bundle.events) ? bundle.events : [];
  const events = allEvents.slice(0, 200).map((event) => sanitizeBoundaryEvent(event, context, semanticValid));
  const rows = synchronizeBoundaryEvents(events);
  const findingCodes = semanticValid ? sanitizeFindingCodes(bundle.findings) : [];
  const coverage = sanitizeCoverage(semanticValid ? bundle.coverage : null);
  const assurance = sanitizeAssurance(semanticValid ? bundle.assurance : null);
  const captureGaps = semanticValid ? captureGapsFor({ coverage, assurance, events, eventCount: allEvents.length }) : ["bundle_semantics_unverified"];
  const authenticity = boundaryAuthenticity(bundle, verified);

  return {
    kind: "arena.boundary_bundle_inspection",
    version: 1,
    source: authenticity.authenticated ? "authenticated_boundary_bundle" : semanticValid ? "semantically_consistent_boundary_bundle" : "unverified_boundary_bundle",
    verification: {
      valid: verified.valid === true,
      semantic_valid: semanticValid,
      hash_valid: boundaryHashesValid(verified),
      reason: verified.reason || null,
      attestation_present: Boolean(bundle.attestation?.proof),
      attested: verified.attested === true,
    },
    authenticity,
    summary: {
      verdict: semanticValid ? sanitizeVerdict(bundle.verdict) : "unverified",
      finding_codes: findingCodes,
      coverage,
      assurance,
    },
    layers: {
      route_parity: sanitizeAuditLayer(bundle.routeParity, semanticValid),
      baseline_safety: sanitizeAuditLayer(bundle.baselineSafety, semanticValid, ["not_evaluated"]),
    },
    contract: sanitizeBoundaryContract(bundle, semanticValid),
    capture_gaps: captureGaps,
    timeline: { verified: semanticValid, events, rows },
    differences: semanticValid ? boundaryDifferences(rows, findingCodes) : [],
  };
}

function boundaryAuthenticity(bundle, verification) {
  const proofPresent = Boolean(bundle.attestation?.proof);
  if (!proofPresent) return { status: "unsigned", proof_present: false, authenticated: false };
  if (verification.valid === true && verification.attested === true) {
    return { status: "authenticated", proof_present: true, authenticated: true };
  }
  if (verification.reason === "attestation_invalid") {
    return { status: "invalid_signature", proof_present: true, authenticated: false };
  }
  if (verification.reason === "attestation_unverified") {
    return { status: "signer_untrusted", proof_present: true, authenticated: false };
  }
  return { status: "unverified", proof_present: true, authenticated: false };
}

function sanitizeAuditLayer(layer, semanticValid, extraStatuses = []) {
  return {
    status: semanticValid ? sanitizeVerdict(layer?.status, extraStatuses) : "unverified",
    finding_codes: semanticValid ? sanitizeFindingCodes(layer?.findings) : [],
  };
}

function createInspectionContext() {
  const values = new Map();
  return {
    reference(namespace, value) {
      if (value === null || value === undefined) return null;
      const key = `${namespace}\0${JSON.stringify(value)}`;
      if (!values.has(key)) {
        const count = [...values.keys()].filter((candidate) => candidate.startsWith(`${namespace}\0`)).length + 1;
        values.set(key, `${namespace}_${count}`);
      }
      return values.get(key);
    },
  };
}

function sanitizeBoundaryEvent(event, context, semanticValid) {
  const kind = sanitizeEffectKind(event?.payload?.kind);
  const provenance = new Set(["recorder_observed", "server_attested", "page_asserted"]).has(event?.provenance)
    ? event.provenance
    : "unknown";
  return {
    sequence: Number.isSafeInteger(event?.sequence) && event.sequence > 0 ? event.sequence : null,
    route: new Set(["human", "agent"]).has(event?.route) ? event.route : "unknown",
    provenance,
    trusted_source: semanticValid && (provenance === "recorder_observed" || provenance === "server_attested"),
    kind,
    value: sanitizeEffectValue(kind, event?.payload, provenance, context),
  };
}

function sanitizeEffectValue(kind, payload, provenance, context) {
  if (!payload || typeof payload !== "object") return { details: "unavailable" };
  if (provenance === "page_asserted") {
    return {
      assertion: "redacted",
      protection_count: safeCount(payload.assertedProtectionCount),
      approval_count: safeCount(payload.assertedApprovalCount),
    };
  }
  if (kind === "execution_proof") {
    return {
      level: safeEnum(payload.level, ["native_browser_api", "compatibility_shim", "server_attested"], "unverified"),
      isolated_context: payload.isolatedContext === true,
      capture_complete: payload.captureComplete === true,
      capture_reason: safeEnum(payload.captureReason, ["quiescent", "timeout", "incomplete"], "unknown"),
      pending_requests: safeCount(payload.pendingRequests),
    };
  }
  if (kind === "effect_settlement") {
    return {
      complete: payload.complete === true,
      reason: safeEnum(payload.reason, ["terminal_watermark", "timeout"], "unknown"),
      pending_effects: safeCount(payload.pendingEffects),
      status: safeEnum(payload.status, ["settled", "inconclusive"], "unknown"),
    };
  }
  if (kind === "outcome") {
    return {
      operation: safeIdentifier(payload.operation),
      status: safeEnum(payload.status, ["previewed", "pending", "confirmed", "cancelled", "blocked"], "recorded"),
      confirmation: safeIdentifier(payload.confirmation),
      resource: sanitizeResource(payload.resource, context),
      amount: safeAmount(payload.quote?.amount),
      currency: safeCurrency(payload.quote?.currency),
    };
  }
  if (kind === "final_state") {
    return {
      status: safeEnum(payload.status, ["preview", "pending", "confirmed", "cancelled"], "recorded"),
      pending_effects: safeCount(payload.pendingEffects),
      resource_effects: safeCount(payload.resourceEffects),
      money_effects: safeCount(payload.moneyEffects),
    };
  }
  if (kind === "authorization") {
    return {
      decision: safeEnum(payload.decision, ["allow", "deny"], "unknown"),
      rule_ref: context.reference("rule", payload.rule),
    };
  }
  if (kind === "approval") {
    return {
      status: safeEnum(payload.status, ["approved", "denied", "pending", "expired", "revoked"], "unknown"),
      exact_binding_present: ["toolHash", "argumentsHash", "contractHash"].every((key) => typeof payload[key] === "string" && payload[key].length > 0),
    };
  }
  if (kind === "state") {
    const before = sanitizeStateValue(payload.before);
    const after = sanitizeStateValue(payload.after);
    return {
      resource: sanitizeResource(payload.resource, context),
      before,
      after,
      amount: safeAmount(payload.amount ?? payload.after?.amount),
      currency: safeCurrency(payload.currency ?? payload.after?.currency),
    };
  }
  if (kind === "money") {
    return { amount: safeAmount(payload.amount), currency: safeCurrency(payload.currency) };
  }
  if (kind === "resource") {
    return {
      action: safeEnum(payload.action, ["read", "inspect", "list", "create", "update", "delete", "cancel", "book"], "other"),
      resource: sanitizeResource(payload.resource, context),
    };
  }
  if (kind === "network") {
    return {
      method: safeEnum(String(payload.method || "").toUpperCase(), ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "BOUNDARY"], "OTHER"),
      scope: safeEnum(payload.scope, ["target", "external", "invalid"], "unknown"),
      observed_request_count: Array.isArray(payload.observedRequests) ? Math.min(payload.observedRequests.length, 10_000) : null,
    };
  }
  if (kind === "ui") {
    return {
      target_ref: context.reference("ui", payload.selector),
      outcome: safeEnum(payload.outcome, ["visible", "hidden", "confirmed", "cancelled", "unchanged"], "recorded"),
      value_ref: context.reference("ui_value", payload.valueHash),
    };
  }
  if (kind === "tool_definition") {
    return { tool_name: safeIdentifier(payload.name), definition_hash_present: typeof payload.hash === "string" && payload.hash.length > 0 };
  }
  return { details: "redacted" };
}

function sanitizeStateValue(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "object" || Array.isArray(value)) return { value_ref: "opaque" };
  return {
    status: safeEnum(value.status, ["pending", "confirmed", "cancelled", "approved", "denied", "active", "inactive"], "recorded"),
    amount: safeAmount(value.amount),
    currency: safeCurrency(value.currency),
    field_count: Math.min(Object.keys(value).length, 10_000),
  };
}

function sanitizeResource(resource, context) {
  if (!resource || typeof resource !== "object") return null;
  return {
    type: safeEnum(resource.type, ["booking", "flight_booking", "gym_booking", "reservation", "order", "payment", "cart", "payment_intent"], "other"),
    id_ref: context.reference("resource", resource.id),
    owner_ref: context.reference("principal", resource.owner),
  };
}

function synchronizeBoundaryEvents(events) {
  const pairs = new Map();
  const occurrences = { human: new Map(), agent: new Map() };
  for (const event of events) {
    if (!new Set(["human", "agent"]).has(event.route)) continue;
    const base = `${event.provenance}:${event.kind}`;
    const occurrence = occurrences[event.route].get(base) || 0;
    occurrences[event.route].set(base, occurrence + 1);
    const key = `${base}:${occurrence}`;
    const row = pairs.get(key) || { kind: event.kind, provenance: event.provenance, human: null, agent: null };
    row[event.route] = event;
    pairs.set(key, row);
  }
  return [...pairs.values()]
    .map((row) => ({
      ...row,
      value_changed: !row.human || !row.agent || JSON.stringify(row.human.value) !== JSON.stringify(row.agent.value),
    }))
    .sort((left, right) => Math.min(left.human?.sequence || Infinity, left.agent?.sequence || Infinity) - Math.min(right.human?.sequence || Infinity, right.agent?.sequence || Infinity));
}

function boundaryDifferences(rows, findingCodes) {
  return rows.filter((row) => row.value_changed).map((row) => ({
    kind: row.kind,
    provenance: row.provenance,
    human: row.human,
    agent: row.agent,
    finding_codes: findingCodes.filter((code) => findingAppliesToKind(code, row.kind)),
  }));
}

function findingAppliesToKind(code, kind) {
  const byKind = {
    authorization: ["authorization_outcome_changed", "baseline_authorization_missing_before_effect", "baseline_authorization_rule_disallowed"],
    approval: ["approval_missing", "approval_after_effect", "approval_binding_mismatch", "baseline_approval_missing_before_effect"],
    state: ["resource_owner_changed", "resource_identity_changed", "state_value_changed", "money_amount_changed", "money_currency_changed", "baseline_resource_owner_disallowed", "baseline_money_amount_exceeded", "baseline_money_currency_disallowed"],
    money: ["money_amount_changed", "money_currency_changed", "baseline_money_amount_exceeded", "baseline_money_currency_disallowed"],
    resource: ["resource_owner_changed", "resource_identity_changed", "baseline_resource_owner_disallowed"],
    network: ["network_effect_changed", "baseline_network_effect_disallowed"],
    ui: ["ui_outcome_changed"],
    effect_settlement: ["effect_settlement_incomplete"],
  };
  const universal = new Set(["effect_mismatch", "unexpected_consequential_effect", "expected_consequential_effect_missing"]);
  return universal.has(code) || (byKind[kind] || []).includes(code);
}

function sanitizeBoundaryContract(bundle, semanticValid) {
  const effects = Array.isArray(bundle.contract?.effects) ? bundle.contract.effects : [];
  const invariants = bundle.contract?.invariants && typeof bundle.contract.invariants === "object" ? bundle.contract.invariants : null;
  return {
    kind: semanticValid && bundle.contract?.kind === "arena.effect_contract" ? bundle.contract.kind : "unverified",
    version: semanticValid && Number.isSafeInteger(bundle.contract?.version) ? bundle.contract.version : null,
    hash: semanticValid && typeof bundle.contractHash === "string" ? bundle.contractHash : null,
    tool_name: semanticValid ? safeIdentifier(bundle.invocation?.toolName) : "unverified",
    effect_count: semanticValid ? Math.min(effects.length, 10_000) : 0,
    effect_kinds: semanticValid ? [...new Set(effects.map((effect) => sanitizeEffectKind(effect?.kind)))] : [],
    argument_keys: semanticValid && Array.isArray(bundle.invocation?.argumentKeys) ? bundle.invocation.argumentKeys.slice(0, 50).map(safeIdentifier) : [],
    invariant_count: semanticValid && invariants ? Object.keys(invariants).filter((key) => key !== "version" && invariants[key] !== null && invariants[key] !== false).length : 0,
    baseline_status: semanticValid ? sanitizeVerdict(bundle.baselineSafety?.status, ["not_evaluated"]) : "unverified",
  };
}

function sanitizeCoverage(value) {
  return {
    human_trusted: safeCount(value?.humanTrusted),
    agent_trusted: safeCount(value?.agentTrusted),
    human_authoritative: safeCount(value?.humanAuthoritative),
    agent_authoritative: safeCount(value?.agentAuthoritative),
    authoritative_complete: value?.authoritativeComplete === true,
    page_assertions: safeCount(value?.pageAssertions),
    complete: value?.complete === true,
  };
}

function sanitizeAssurance(value) {
  return {
    tier: safeEnum(value?.tier, ["native", "compatibility", "server_attested", "unverified"], "unverified"),
    human_browser_proof: safeEnum(value?.humanBrowserProof, ["native_browser_api", "compatibility_shim", "not_claimed"], "unverified"),
    agent_browser_proof: safeEnum(value?.agentBrowserProof, ["native_browser_api", "compatibility_shim", "not_claimed"], "unverified"),
    authoritative_outcomes: value?.authoritativeOutcomes === true,
    attestation_eligible: value?.attestationEligible === true,
  };
}

function captureGapsFor({ coverage, assurance, events, eventCount }) {
  const gaps = [];
  if (!coverage.complete) gaps.push("route_coverage_incomplete");
  if (!coverage.authoritative_complete) gaps.push("authoritative_outcome_missing");
  if (assurance.tier === "compatibility") gaps.push("compatibility_browser_api");
  if (assurance.tier === "unverified") gaps.push("browser_execution_unverified");
  if (events.some((event) => event.kind === "execution_proof" && event.value.capture_complete !== true)) gaps.push("effect_capture_incomplete");
  if (events.some((event) => event.kind === "effect_settlement" && event.value.complete !== true)) gaps.push("effect_settlement_incomplete");
  if (eventCount > events.length) gaps.push("timeline_truncated");
  return [...new Set(gaps)];
}

function boundaryHashesValid(verification) {
  if (verification.valid === true) return true;
  if (new Set(["bundle_hash_mismatch", "event_chain_invalid", "event_payload_hash_invalid", "contract_hash_mismatch", "tool_hash_mismatch"]).has(verification.reason)) return false;
  if (new Set(["invalid_bundle", "non_canonical_bundle", "contract_invalid", "argument_binding_invalid"]).has(verification.reason)) return null;
  if (new Set([
    "event_semantics_invalid", "coverage_semantics_mismatch", "assurance_semantics_mismatch", "route_parity_semantics_mismatch",
    "baseline_safety_semantics_mismatch", "verdict_semantics_mismatch", "findings_semantics_mismatch", "assurance_policy_mismatch",
    "attestation_eligibility_mismatch", "attestation_unverified", "attestation_invalid",
  ]).has(verification.reason)) return true;
  return null;
}

function sanitizeFindingCodes(findings) {
  const allowed = new Set([
    "seed_mismatch", "page_assertions_untrusted", "trusted_evidence_missing", "authoritative_evidence_missing", "browser_execution_proof_incomplete", "effect_settlement_incomplete", "human_baseline_changed",
    "effect_mismatch", "resource_owner_changed", "resource_identity_changed", "state_value_changed", "money_amount_changed", "money_currency_changed",
    "network_effect_changed", "ui_outcome_changed", "approval_missing", "approval_after_effect", "approval_binding_mismatch", "authorization_outcome_changed",
    "unexpected_consequential_effect", "expected_consequential_effect_missing", "baseline_safety_evidence_missing",
    "baseline_authorization_missing_before_effect", "baseline_authorization_rule_disallowed", "baseline_approval_missing_before_effect",
    "baseline_resource_owner_disallowed", "baseline_money_amount_exceeded", "baseline_money_currency_disallowed", "baseline_network_effect_disallowed",
  ]);
  return Array.isArray(findings) ? [...new Set(findings.slice(0, 50).map((finding) => finding?.code).filter((code) => allowed.has(code)))] : [];
}

function sanitizeEffectKind(value) {
  return safeEnum(value, ["tool_definition", "execution_proof", "authorization", "approval", "effect_settlement", "outcome", "state", "final_state", "money", "resource", "network", "ui", "page_context", "protection"], "other");
}

function sanitizeVerdict(value, extra = []) {
  return safeEnum(value, ["pass", "fail", "inconclusive", ...extra], "unverified");
}

function safeEnum(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function safeAmount(value) {
  return Number.isFinite(value) && Math.abs(value) <= Number.MAX_SAFE_INTEGER ? value : null;
}

function safeCurrency(value) {
  return typeof value === "string" && /^[A-Z]{3}$/.test(value) ? value : null;
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? Math.min(value, 10_000) : null;
}

function safeIdentifier(value) {
  return typeof value === "string" && /^[A-Za-z0-9_.:-]{1,80}$/.test(value) ? value : "redacted";
}

function digestJson(value) {
  return createHash("sha256").update(JSON.stringify(value)).digest("base64url");
}

function decorateReceipt(result, gateway) {
  if (!result?.receipt) return result;
  return { ...result, receipt_verified: gateway.verifyReceipt(result.receipt) };
}

function fixPlan({ audit, state } = {}) {
  const fixes = [];
  if (!audit?.webmcp_available && !audit?.discovered) fixes.push({ priority: "critical", fix: "Register browser tools through document.modelContext.registerTool()." });
  if (!state?.timeline?.some((event) => event.status === "passport_issued")) fixes.push({ priority: "high", fix: "Require a signed, short-lived delegation before executing tools." });
  if (!state?.timeline?.some((event) => event.status === "approval_required")) fixes.push({ priority: "high", fix: "Demonstrate a consequential tool that pauses for explicit human approval." });
  if (!state?.receipts?.length) fixes.push({ priority: "medium", fix: "Execute an authorized action and retain its signed receipt." });
  return { generated_at: new Date().toISOString(), fixes, ready: fixes.length === 0 };
}

function cleanCode(value) {
  const code = String(value || "").trim().toUpperCase();
  if (!/^[A-Z]{3}$/.test(code)) throw new Error("airport codes must contain exactly three letters");
  return code;
}

function pageHeaders(originTrialToken = "") {
  const headers = {
    "cache-control": "no-store",
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "permissions-policy": "tools=(self)",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=63072000; includeSubDomains",
    "x-content-type-options": "nosniff",
  };
  if (originTrialToken) headers["origin-trial"] = originTrialToken;
  return headers;
}

function send(response, status, contentType, body, headers = {}) {
  response.writeHead(status, { "content-type": contentType, ...headers });
  response.end(body);
}

function json(response, status, value) {
  send(response, status, "application/json; charset=utf-8", JSON.stringify(value), { "cache-control": "no-store", "x-content-type-options": "nosniff" });
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1_000_000) reject(new Error("request body exceeds 1 MB"));
    });
    request.on("end", () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error("request body must be valid JSON"));
      }
    });
    request.on("error", reject);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = loadArenaConfig(process.env);
  const repository = createSqliteRepository({ path: config.dataPath });
  createArenaServer({ config, repository }).listen(config.port, config.host, () => {
    console.log(`arena: http://${config.host}:${config.port}`);
    console.log(`state: ${repository.durability} at ${repository.path}`);
    console.log(`identity: ${config.requireVerifiedAgents ? "trusted issuer required" : "local demo identities allowed"}`);
    console.log(`remote webmcp: ${config.remoteInspectionEnabled ? config.browserMode : "disabled"}`);
  });
}
