import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

import { createBoundaryAuditor } from "./boundary-audit.js";
import { hashWebMcpToolDefinition } from "./webmcp-tool-definition.js";

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const WEBMCP_TOOL_NAME = /^[A-Za-z0-9._-]{1,128}$/;
const RELEASE_VERSION = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const CAPABILITY = /^[A-Za-z0-9_-]{32,128}$/;

export class GeneratedReleaseAuditError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "GeneratedReleaseAuditError";
    this.code = code;
    Object.assign(this, details);
  }
}

export function hashGeneratedRelease(input) {
  const release = normalizeRelease(input);
  return digest(`arena.generated-release.v1\0${canonicalJson(release)}`);
}

export function createGeneratedReleaseAuditor({
  adapter,
  attestor = null,
  now = () => new Date(),
  capability = () => randomBytes(32).toString("base64url"),
  onApprovalRequired,
} = {}) {
  validateAdapter(adapter);
  if (typeof now !== "function" || typeof capability !== "function") {
    throw new Error("generated release audit clock and capability sources must be functions");
  }
  if (typeof onApprovalRequired !== "function") {
    throw new Error("generated release audits require a trusted human approval callback");
  }
  const boundaryAuditor = createBoundaryAuditor({
    targetHarness: adapter.targetHarness,
    routeRunner: adapter.routeRunner,
    attestor,
    now,
  });
  const audits = new Map();

  async function prepare(input = {}) {
    rejectUnexpectedFields(input, ["release", "target", "principalRef", "agent"], "generated release audit");
    const release = normalizeRelease(input.release);
    const requestedAgent = normalizeAgent(input.agent);
    const recipe = await adapter.createRecipe({
      target: input.target,
      principalRef: input.principalRef,
      toolName: requestedAgent.toolName,
      arguments: structuredClone(requestedAgent.arguments),
    });
    const principal = normalizePrincipalDescriptor(recipe.principal);
    assertRecipeMatchesIntent(recipe, requestedAgent);
    const releasedTool = release.tools.find((tool) => tool.name === requestedAgent.toolName);
    if (!releasedTool) throw new Error("generated release does not contain the requested WebMCP tool");
    const releasedToolHash = hashWebMcpToolDefinition(releasedTool);
    if (releasedToolHash !== recipe.agent.toolDefinitionHash) {
      throw new GeneratedReleaseAuditError(
        "tool_definition_mismatch",
        "generated release tool definition does not match the owned target adapter",
        {
          expectedCommitment: recipe.agent.toolDefinitionHash,
          actualCommitment: releasedToolHash,
        },
      );
    }

    const prepared = await boundaryAuditor.prepare(recipe);
    const releaseHash = hashGeneratedRelease(release);
    const targetHash = digest(recipe.target);
    const agentHash = digest(`arena.agent.v1\0${requestedAgent.id}`);
    const principalHash = digest(`arena.principal.v1\0${recipe.principalRef}`);
    const coverage = deepFreeze({
      auditedTools: [requestedAgent.toolName],
      totalTools: release.tools.length,
      complete: release.tools.length === 1,
    });
    const review = deepFreeze({
      adapter: structuredClone(adapter.manifest),
      release: {
        id: release.id,
        version: release.version,
        generator: release.generator,
        artifact: structuredClone(release.artifact),
        hash: releaseHash,
      },
      intent: {
        targetHash,
        principalLabel: principal.label,
        principalScope: principal.scope,
        principalHash,
        agentId: requestedAgent.id,
        agentHash,
        toolName: requestedAgent.toolName,
        toolDefinitionHash: releasedToolHash,
        toolHash: prepared.approvalBinding.toolHash,
        arguments: structuredClone(requestedAgent.arguments),
        argumentsHash: prepared.approvalBinding.argumentsHash,
        contractHash: prepared.approvalBinding.contractHash,
      },
      effects: structuredClone(prepared.proposedContract.effects),
      invariants: structuredClone(prepared.proposedContract.invariants),
      baselineSafety: structuredClone(prepared.baselineSafety),
      coverage: structuredClone(coverage),
    });
    const record = {
      auditId: prepared.planId,
      state: "awaiting_approval",
      expiresAt: prepared.expiresAt,
      prepared,
      releaseHash,
      coverage,
      requestedAgent,
      review,
      capabilityHash: null,
      reviewerHash: null,
    };
    audits.set(record.auditId, record);
    onApprovalRequired({
      audit: publicPrepared(record),
      approve: (decision) => approve(record.auditId, decision),
    });
    return publicPrepared(record);
  }

  function approve(auditId, decision = {}) {
    rejectUnexpectedFields(decision, ["humanId"], "generated release approval");
    if (typeof decision.humanId !== "string" || !SAFE_ID.test(decision.humanId)) {
      throw new Error("generated release approval requires a valid humanId");
    }
    const record = requireAudit(auditId, audits);
    if (record.state !== "awaiting_approval") throw new Error("generated release approval was already resolved");
    if (currentTime(now) >= Date.parse(record.expiresAt)) {
      record.state = "expired";
      throw new Error("generated release approval expired");
    }
    const secret = String(capability());
    if (!CAPABILITY.test(secret)) throw new Error("generated release capability source returned an invalid value");
    record.capabilityHash = digest(`arena.generated-release.capability.v1\0${secret}`);
    record.reviewerHash = digest(`arena.reviewer.v1\0${decision.humanId}`);
    record.state = "approved";
    return deepFreeze({
      auditId: record.auditId,
      capability: secret,
      expiresAt: record.expiresAt,
      commitments: {
        releaseHash: record.releaseHash,
        targetHash: record.review.intent.targetHash,
        principalHash: record.review.intent.principalHash,
        agentHash: record.review.intent.agentHash,
        toolHash: record.review.intent.toolHash,
        argumentsHash: record.review.intent.argumentsHash,
        contractHash: record.review.intent.contractHash,
      },
    });
  }

  async function run(input = {}) {
    rejectUnexpectedFields(input, ["auditId", "capability", "agent"], "generated release execution");
    const record = requireAudit(input.auditId, audits);
    if (new Set(["executing", "completed", "outcome_unknown"]).has(record.state)) {
      return denial(record, "authorization_replayed");
    }
    if (record.state === "expired" || currentTime(now) >= Date.parse(record.expiresAt)) {
      record.state = "expired";
      return denial(record, "authorization_expired");
    }
    if (record.state !== "approved") return denial(record, "human_approval_required");

    let suppliedAgent;
    try {
      suppliedAgent = normalizeAgent(input.agent);
    } catch {
      return denial(record, "exact_intent_invalid");
    }
    if (suppliedAgent.id !== record.requestedAgent.id) {
      return denial(record, "agent_identity_mismatch", {
        expectedCommitment: record.review.intent.agentHash,
        actualCommitment: digest(`arena.agent.v1\0${suppliedAgent.id}`),
      });
    }
    if (suppliedAgent.toolName !== record.requestedAgent.toolName) return denial(record, "tool_binding_mismatch");
    if (canonicalJson(suppliedAgent.arguments) !== canonicalJson(record.requestedAgent.arguments)) {
      return denial(record, "argument_substitution", {
        expectedCommitment: record.review.intent.argumentsHash,
        actualCommitment: digest(canonicalJson(suppliedAgent.arguments)),
      });
    }
    if (!validCapability(record.capabilityHash, input.capability)) return denial(record, "invalid_capability");

    record.state = "executing";
    try {
      const outcome = await boundaryAuditor.run({
        planId: record.prepared.planId,
        approval: {
          status: "approved",
          planId: record.prepared.planId,
          ...record.prepared.approvalBinding,
        },
      });
      if (outcome.bundle.principalHash !== record.review.intent.principalHash) {
        throw new Error("generated release execution principal no longer matches the reviewed account scope");
      }
      record.state = "completed";
      const findings = structuredClone(outcome.findings);
      if (!record.coverage.complete) {
        findings.push({
          code: "release_coverage_incomplete",
          message: `Only ${record.coverage.auditedTools.length} of ${record.coverage.totalTools} generated WebMCP tools were audited.`,
        });
      }
      return deepFreeze({
        state: "completed",
        verdict: outcome.verdict === "fail"
          ? "fail"
          : record.coverage.complete ? outcome.verdict : "inconclusive",
        selectedToolVerdict: outcome.verdict,
        findings,
        coverage: structuredClone(record.coverage),
        selectedToolBundle: structuredClone(outcome.bundle),
        release: structuredClone(record.review.release),
        authorization: {
          status: "consumed",
          agentHash: record.review.intent.agentHash,
          reviewerHash: record.reviewerHash,
        },
      });
    } catch (error) {
      record.state = "outcome_unknown";
      throw error;
    }
  }

  return Object.freeze({ prepare, run });
}

function normalizeRelease(input) {
  rejectUnexpectedFields(input, ["id", "version", "generator", "artifact", "tools"], "generated release");
  if (typeof input.id !== "string" || !SAFE_ID.test(input.id)) throw new Error("generated release id is invalid");
  if (typeof input.version !== "string" || !RELEASE_VERSION.test(input.version)) throw new Error("generated release version is invalid");
  if (typeof input.generator !== "string" || !SAFE_ID.test(input.generator)) throw new Error("generated release generator is invalid");
  const artifact = normalizeArtifact(input.artifact);
  if (!Array.isArray(input.tools) || input.tools.length < 1 || input.tools.length > 100) {
    throw new Error("generated release must contain between one and 100 WebMCP tools");
  }
  const tools = input.tools.map(normalizeTool).sort((left, right) => left.name.localeCompare(right.name));
  if (new Set(tools.map((tool) => tool.name)).size !== tools.length) throw new Error("generated release contains duplicate WebMCP tool names");
  return deepFreeze({ id: input.id, version: input.version, generator: input.generator, artifact, tools });
}

function normalizeArtifact(value) {
  rejectUnexpectedFields(value, ["algorithm", "digest", "subject"], "generated release artifact");
  if (value.algorithm !== "sha256" || typeof value.digest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.digest)) {
    throw new Error("generated release artifact must contain a SHA-256 digest");
  }
  if (typeof value.subject !== "string" || !SAFE_ID.test(value.subject)) {
    throw new Error("generated release artifact subject is invalid");
  }
  return deepFreeze({ algorithm: value.algorithm, digest: value.digest, subject: value.subject });
}

function normalizeTool(tool) {
  rejectUnexpectedFields(tool, ["name", "title", "description", "inputSchema", "annotations"], "generated WebMCP tool");
  if (typeof tool.name !== "string" || !WEBMCP_TOOL_NAME.test(tool.name)) throw new Error("generated WebMCP tool name is invalid");
  if (typeof tool.description !== "string" || !tool.description || tool.description.length > 4_000) {
    throw new Error("generated WebMCP tool description is invalid");
  }
  if (!isPlainObject(tool.inputSchema)) throw new Error("generated WebMCP tool inputSchema must be an object");
  const annotations = normalizeToolAnnotations(tool.annotations);
  const normalized = {
    name: tool.name,
    title: tool.title == null ? null : String(tool.title),
    description: tool.description,
    inputSchema: JSON.parse(canonicalJson(tool.inputSchema)),
    annotations,
  };
  canonicalJson(normalized);
  return normalized;
}

function normalizeAgent(agent) {
  rejectUnexpectedFields(agent, ["id", "toolName", "arguments"], "generated release agent intent");
  if (typeof agent.id !== "string" || !SAFE_ID.test(agent.id)) throw new Error("generated release agent id is invalid");
  if (typeof agent.toolName !== "string" || !WEBMCP_TOOL_NAME.test(agent.toolName)) throw new Error("generated release tool name is invalid");
  if (!isPlainObject(agent.arguments)) throw new Error("generated release arguments must be an object");
  return deepFreeze({
    id: agent.id,
    toolName: agent.toolName,
    arguments: JSON.parse(canonicalJson(agent.arguments)),
  });
}

function normalizeToolAnnotations(value) {
  if (value == null) return null;
  if (!isPlainObject(value)) throw new Error("generated WebMCP tool annotations must be an object");
  rejectUnexpectedFields(value, ["readOnlyHint", "untrustedContentHint"], "generated WebMCP tool annotations");
  for (const field of ["readOnlyHint", "untrustedContentHint"]) {
    if (value[field] !== undefined && typeof value[field] !== "boolean") {
      throw new Error(`generated WebMCP tool annotation ${field} must be a boolean`);
    }
  }
  return deepFreeze({
    readOnlyHint: value.readOnlyHint ?? false,
    untrustedContentHint: value.untrustedContentHint ?? false,
  });
}

function normalizePrincipalDescriptor(value) {
  rejectUnexpectedFields(value, ["label", "scope"], "owned principal descriptor");
  if (typeof value.label !== "string" || !value.label.trim() || value.label.trim().length > 160) {
    throw new Error("the owned target adapter must resolve a principal label");
  }
  if (typeof value.scope !== "string" || !SAFE_ID.test(value.scope)) {
    throw new Error("the owned target adapter must resolve a principal scope");
  }
  return deepFreeze({ label: value.label.trim(), scope: value.scope });
}

function assertRecipeMatchesIntent(recipe, requestedAgent) {
  if (!recipe?.agent || recipe.agent.toolName !== requestedAgent.toolName ||
      canonicalJson(recipe.agent.arguments) !== canonicalJson(requestedAgent.arguments) ||
      !/^[A-Za-z0-9_-]{43}$/.test(recipe.agent.toolDefinitionHash || "")) {
    throw new Error("owned target adapter recipe does not match the requested generated tool intent");
  }
}

function validateAdapter(adapter) {
  if (!adapter?.manifest || typeof adapter.createRecipe !== "function" ||
      !adapter.targetHarness || !adapter.routeRunner) {
    throw new Error("generated release audit requires an owned-target adapter");
  }
}

function publicPrepared(record) {
  return deepFreeze({
    auditId: record.auditId,
    state: record.state,
    expiresAt: record.expiresAt,
    review: structuredClone(record.review),
  });
}

function denial(record, reason, commitments = {}) {
  return deepFreeze({
    auditId: record.auditId,
    releaseHash: record.releaseHash,
    state: "denied",
    reason,
    finding: {
      code: reason,
      message: denialMessage(reason),
      ...commitments,
    },
  });
}

function denialMessage(reason) {
  const messages = {
    authorization_replayed: "The one-use authorization was already consumed or execution already started.",
    authorization_expired: "The exact-intent authorization expired before execution.",
    human_approval_required: "The generated tool intent requires human approval before execution.",
    exact_intent_invalid: "The supplied execution intent is not valid canonical input.",
    agent_identity_mismatch: "A different agent attempted to use the reviewed authorization.",
    tool_binding_mismatch: "A different WebMCP tool attempted to use the reviewed authorization.",
    argument_substitution: "The WebMCP arguments changed after human review.",
    invalid_capability: "The supplied authorization capability is invalid.",
  };
  return messages[reason];
}

function validCapability(expectedHash, value) {
  if (!expectedHash || typeof value !== "string" || !CAPABILITY.test(value)) return false;
  const actualHash = digest(`arena.generated-release.capability.v1\0${value}`);
  const expected = Buffer.from(expectedHash, "base64url");
  const actual = Buffer.from(actualHash, "base64url");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function requireAudit(auditId, audits) {
  const record = audits?.get?.(String(auditId));
  if (!record) throw new Error("unknown generated release audit");
  return record;
}

function rejectUnexpectedFields(value, allowed, label) {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length) throw new Error(`unsupported ${label} field: ${unexpected.join(", ")}`);
}

function currentTime(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("generated release audit clock returned an invalid date");
  return value.getTime();
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("generated release data must contain canonical JSON-compatible values");
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}
