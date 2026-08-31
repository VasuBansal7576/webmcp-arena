import { createHash, createHmac, randomUUID } from "node:crypto";
import { link, mkdir, open, readFile, realpath, stat, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { createBoundaryAuditor } from "./boundary-audit.js";
import { buildCiArtifacts } from "./ci-report.js";
import { createGymAuditAdapters } from "./gym-audit-adapter.js";
import { createIncidentLab } from "./incident-lab.js";
import { scanUrl } from "./scanner.js";
import { createWebMcpBrowserRunner } from "./webmcp-runner.js";
import { verifyPortableProof } from "./proof-gate.js";

const TEST_OPTIONS = new Set([
  "target",
  "fixture_token",
  "browser_executable",
  "browser_mode",
  "approve_contract",
  "write_contract",
  "approved_contract",
  "format",
]);
const DEMO_OPTIONS = new Set(["scenario", "version", "mode", "format"]);
const PREFLIGHT_OPTIONS = new Set(["mcp", "openapi", "agent_skills", "allow_private_targets", "format"]);
const INIT_OPTIONS = new Set(["directory"]);
const VERIFY_OPTIONS = new Set(["require", "format"]);
const CONTRACT_HASH = /^[A-Za-z0-9_-]{43}$/;
const REDACTION_KEY_LABEL = "arena.cli.redaction-key.v1";
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export async function runArenaCli(argv = [], overrides = {}) {
  const outputFormat = requestedFormat(argv);
  const dependencies = {
    createBrowserRunner: createWebMcpBrowserRunner,
    createAdapters: createGymAuditAdapters,
    createAuditor: createBoundaryAuditor,
    createLab: createIncidentLab,
    scanUrl,
    verifyProof: verifyPortableProof,
    now: () => new Date(),
    ...overrides,
  };

  try {
    const [command = "help", ...tokens] = argv;
    if (command === "help" || command === "--help" || command === "-h") return helpResult();
    if (command === "init") return await runInit(tokens);
    if (command === "verify") return await runVerify(tokens, dependencies);
    if (command === "demo") return runDemo(tokens, dependencies);
    if (command === "preflight") return await runPreflight(tokens, dependencies);
    if (command !== "test") return errorResult(`unknown command: ${command}`, outputFormat);
    const options = parseOptions(tokens, TEST_OPTIONS);
    validateTestOptions(options);
    if (options.write_contract) options.write_contract = await externalArtifactPath(options.write_contract);
    if (options.approved_contract) options.approved_contract = await externalArtifactPath(options.approved_contract, { existing: true });
    const approvedArtifact = options.approved_contract
      ? await readApprovedContractArtifact(options.approved_contract, dependencies.now())
      : null;
    const redactionKey = deriveRedactionKey(options.fixture_token);
    const browserRunner = dependencies.createBrowserRunner({
      executablePath: options.browser_executable,
      mode: options.browser_mode,
      headless: options.browser_mode === "compatibility",
      allowPrivateTargets: true,
      redactionKey,
    });
    const adapters = dependencies.createAdapters({
      browserRunner,
      fixtureToken: options.fixture_token,
      redactionKey,
    });
    const recipe = await adapters.createRecipe({ target: options.target, memberId: "human_vasu" });
    const auditor = dependencies.createAuditor({
      targetHarness: adapters.targetHarness,
      routeRunner: adapters.routeRunner,
    });
    const prepared = await auditor.prepare(recipe);
    let contractArtifact = null;
    if (options.write_contract) {
      const artifact = buildReviewableContractArtifact({
        prepared,
        recipe,
        target: options.target,
        createdAt: dependencies.now(),
      });
      if (containsString(artifact, options.fixture_token)) {
        throw new Error("contract artifact cannot be written because prepared evidence contains the fixture credential");
      }
      await writeNewJsonArtifact(options.write_contract, artifact);
      contractArtifact = {
        path: options.write_contract,
        approval_status: artifact.approval.status,
        artifact_hash: artifact.artifact_hash,
      };
    }
    if (!options.approve_contract && !approvedArtifact) {
      return render({
        exitCode: 2,
        format: options.format,
        report: approvalRequiredReport(prepared, contractArtifact),
      });
    }
    if (approvedArtifact) {
      assertArtifactMatchesPreparation(approvedArtifact, { prepared, recipe, target: options.target });
    } else if (options.approve_contract !== prepared.contractHash) {
      return render({
        exitCode: 2,
        format: options.format,
        report: approvalHashMismatchReport(prepared),
      });
    }
    const audit = await auditor.run({
      planId: prepared.planId,
      approval: {
        status: "approved",
        planId: prepared.planId,
        ...prepared.approvalBinding,
      },
    });
    return render({
      exitCode: audit.verdict === "pass" ? 0 : audit.verdict === "fail" ? 1 : 2,
      format: options.format,
      report: completedReport(audit),
    });
  } catch (error) {
    return errorResult(error?.message || String(error), outputFormat);
  }
}

function helpResult() {
  return {
    exitCode: 0,
    stdout: `Arena — behavioral proof for WebMCP releases

Usage:
  arena init [--directory PATH]
  arena preflight URL [--mcp URL] [--openapi URL]
  arena test --target URL --fixture-token TOKEN --browser-executable PATH --browser-mode native
  arena verify PROOF.json [--require pass|fail]
  arena demo [--scenario gym_waitlist] [--version vulnerable|fixed]

Start with “arena init”, then review the generated adapter and workflow.
Docs: https://webmcp-arena.zippy17.chatgpt.site/docs/quickstart
`,
    stderr: "",
  };
}

async function runInit(tokens) {
  const options = parseOptions(tokens, INIT_OPTIONS);
  const root = resolve(options.directory || process.cwd());
  const files = new Map([
    ["arena.config.mjs", `export default {
  version: 1,
  adapters: ["./arena/document-sharing.adapter.ts"],
  proof: { require: "pass", output: "arena-proof.json" },
};
`],
    [join("arena", "document-sharing.adapter.ts"), `import { defineOwnedTargetAdapter } from "webmcp-arena/adapter-sdk";

export default defineOwnedTargetAdapter({
  manifest: {
    id: "example.document-sharing",
    version: "1.0.0",
    claimScope: ["owned_fixture:document-sharing"],
    trustMode: "server_attested",
  },
  targetHarness: {
    async establish() { throw new Error("Connect your owned test surface"); },
    async provision() { throw new Error("Seed an isolated document and recipient"); },
    async release() {},
  },
  routeRunner: {
    async runHuman() { throw new Error("Record the human sharing route"); },
    async runAgent() { throw new Error("Invoke the registered WebMCP sharing tool"); },
  },
  createRecipe() {
    return {
      human: { operation: "share_document", recipient: "reviewed@example.test" },
      agent: { toolName: "share_document", arguments: { recipient: "reviewed@example.test" } },
    };
  },
});
`],
    [join(".github", "workflows", "arena.yml"), `name: Arena boundary proof
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  boundary-proof:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: VasuBansal7576/webmcp-arena@v0.4.0
        with:
          mode: proof
          proof: arena-proof.json
          require: pass
`],
  ]);
  for (const relativePath of files.keys()) {
    try {
      await stat(join(root, relativePath));
      throw new Error(`refusing to overwrite existing file: ${relativePath}`);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  for (const [relativePath, contents] of files) {
    const destination = join(root, relativePath);
    await mkdir(dirname(destination), { recursive: true });
    await writeFile(destination, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
  }
  return {
    exitCode: 0,
    stdout: `${JSON.stringify({ status: "initialized", directory: root, files: [...files.keys()] }, null, 2)}\n`,
    stderr: "",
  };
}

async function runVerify(tokens, dependencies) {
  const [proofPath, ...optionTokens] = tokens;
  if (!proofPath || proofPath.startsWith("--")) throw new Error("arena verify requires a proof JSON path");
  const options = parseOptions(optionTokens, VERIFY_OPTIONS);
  if (options.require && !new Set(["pass", "fail"]).has(options.require)) throw new Error("--require must be pass or fail");
  const format = options.format || "json";
  if (!new Set(["json", "sarif", "junit"]).has(format)) throw new Error("--format must be json, sarif, or junit");
  let proof;
  try {
    proof = JSON.parse(await readFile(resolve(proofPath), "utf8"));
  } catch {
    throw new Error("proof file is not readable JSON");
  }
  const verification = await dependencies.verifyProof(proof);
  const requiredMet = !options.require || verification.verdict === options.require;
  const status = verification.valid && requiredMet ? "verified" : "blocked";
  const report = {
    kind: "arena.proof_gate",
    version: 1,
    status,
    verdict: verification.verdict || "inconclusive",
    valid: verification.valid === true,
    payloadHash: verification.payloadHash || "",
    ...(verification.reason ? { verificationReason: verification.reason } : {}),
    ...(!requiredMet ? { reason: "required_verdict_not_met", required: options.require } : {}),
  };
  return render({
    exitCode: status === "verified" ? 0 : 1,
    format,
    report: {
      ...report,
      findings: status === "verified" ? [] : [{
        code: report.reason || report.verificationReason || "proof_gate_failed",
        message: status === "verified" ? "Proof verified." : "The signed behavioral proof did not satisfy the release gate.",
      }],
    },
  });
}

async function runPreflight(tokens, dependencies) {
  const [target, ...optionTokens] = tokens;
  if (!target || target.startsWith("--")) throw new Error("arena preflight requires an HTTP(S) target URL");
  const options = parseOptions(optionTokens, PREFLIGHT_OPTIONS);
  if ((options.format || "json") !== "json") throw new Error("arena preflight currently supports --format json only");
  if (options.allow_private_targets !== undefined && !new Set(["true", "false"]).has(options.allow_private_targets)) {
    throw new Error("--allow-private-targets must be true or false");
  }
  const report = await dependencies.scanUrl(target, {
    mcp: options.mcp,
    openapi: options.openapi,
    agentSkills: options.agent_skills,
    allowPrivateTargets: options.allow_private_targets === "true",
  });
  const failed = report.source?.status >= 400 || (report.readiness?.critical_gaps?.length || 0) > 0;
  return {
    exitCode: failed ? 1 : 0,
    stdout: `${JSON.stringify(report, null, 2)}\n`,
    stderr: "",
  };
}

function runDemo(tokens, dependencies) {
  const options = parseOptions(tokens, DEMO_OPTIONS);
  const format = options.format || "json";
  if (!new Set(["json", "sarif", "junit"]).has(format)) throw new Error("--format must be json, sarif, or junit");
  const run = dependencies.createLab().run({
    scenarioId: options.scenario || "gym_waitlist",
    version: options.version || "vulnerable",
    mode: options.mode || "enforce",
  });
  const artifacts = buildCiArtifacts({ reports: [run.report] });
  const exitCode = artifacts.summary.passed ? 0 : 1;
  if (format === "json") return { exitCode, stdout: `${JSON.stringify(artifacts.json, null, 2)}\n`, stderr: "" };
  if (format === "sarif") return { exitCode, stdout: `${JSON.stringify(artifacts.sarif, null, 2)}\n`, stderr: "" };
  return { exitCode, stdout: `${artifacts.junit}\n`, stderr: "" };
}

function completedReport(audit) {
  const humanProof = proofLevelFromBundle(audit.bundle, "human");
  const agentProof = proofLevelFromBundle(audit.bundle, "agent");
  return {
    kind: "arena.target_test",
    version: 1,
    status: audit.verdict,
    verdict: audit.verdict,
    proof_level: {
      human: humanProof,
      agent: agentProof,
      native_webmcp: humanProof === "native_browser_api" && agentProof === "native_browser_api",
    },
    claim_scope: {
      target: "owned_loopback_gym_fixture",
      evidence: ["browser_recorder_observed", "fixture_backend_attested"],
      contract: "explicitly_approved_for_this_run",
      agent_executed: true,
      attestation: audit.attestation?.proof ? "signed" : "unsigned_local_bundle",
      proves: "paired security outcome for one seeded Gym fixture run",
      does_not_prove: ["arbitrary website safety", "agent vendor identity", "production enforcement"],
    },
    coverage: audit.coverage,
    routeParity: audit.routeParity,
    baselineSafety: audit.baselineSafety,
    findings: audit.findings,
    bundle: audit.bundle,
  };
}

function approvalRequiredReport(prepared, contractArtifact = null) {
  const report = {
    kind: "arena.target_test",
    version: 1,
    status: "inconclusive",
    verdict: "inconclusive",
    reason: "contract_approval_required",
    proof_level: {
      human: proofLevelFromEffects(prepared.proposedContract?.effects),
      agent: null,
    },
    claim_scope: {
      target: "owned_loopback_gym_fixture",
      evidence: ["browser_recorder_observed", "fixture_backend_attested"],
      contract: "proposed_not_approved",
      agent_executed: false,
      attestation: "not_eligible",
      proves: "human baseline preparation only",
      does_not_prove: ["agent-route parity", "arbitrary website safety", "production enforcement"],
    },
    contract: prepared.proposedContract,
    contract_hash: prepared.contractHash,
    approval_binding: prepared.approvalBinding,
    coverage: prepared.coverage,
    routeParity: { status: "not_evaluated", findings: [] },
    baselineSafety: prepared.baselineSafety || { status: "not_evaluated", findings: [] },
  };
  if (contractArtifact) report.contract_artifact = contractArtifact;
  return report;
}

function approvalHashMismatchReport(prepared) {
  return {
    ...approvalRequiredReport(prepared),
    reason: "contract_approval_hash_mismatch",
    inconclusive_reasons: ["The supplied approval hash does not match the contract prepared from the current target."],
    claim_scope: {
      ...approvalRequiredReport(prepared).claim_scope,
      contract: "approval_hash_mismatch",
    },
  };
}

function proofLevelFromEffects(effects) {
  return effects?.find((effect) => effect?.kind === "execution_proof")?.level || "unknown";
}

function proofLevelFromBundle(bundle, route) {
  return bundle?.events?.find((event) => event?.route === route && event?.payload?.kind === "execution_proof")?.payload?.level || "unknown";
}

function validateTestOptions(options) {
  for (const key of ["target", "fixture_token", "browser_executable", "browser_mode"]) {
    if (!options[key]) throw new Error(`--${key.replaceAll("_", "-")} is required`);
  }
  if (!new Set(["compatibility", "native"]).has(options.browser_mode)) {
    throw new Error("--browser-mode must be compatibility or native");
  }
  if (options.approve_contract !== undefined && !CONTRACT_HASH.test(options.approve_contract)) {
    throw new Error("--approve-contract must be the exact 43-character contract hash emitted by a prior preparation");
  }
  if (options.write_contract && (options.approve_contract || options.approved_contract)) {
    throw new Error("--write-contract cannot be combined with an approval option");
  }
  if (options.approve_contract && options.approved_contract) {
    throw new Error("--approve-contract and --approved-contract are mutually exclusive");
  }
  options.format ||= "json";
  if (!new Set(["json", "sarif", "junit"]).has(options.format)) {
    throw new Error("--format must be json, sarif, or junit");
  }
}

function buildReviewableContractArtifact({ prepared, recipe, target, createdAt }) {
  const created = validDate(createdAt, "contract artifact creation time is invalid");
  const expires = validDate(prepared.expiresAt, "prepared contract expiration is invalid");
  if (expires.getTime() <= created.getTime()) throw new Error("prepared contract already expired");
  const proposedContract = structuredClone(prepared.proposedContract);
  if (proposedContract?.kind !== "arena.effect_contract" || proposedContract?.version !== 2
      || !Array.isArray(proposedContract.effects) || !Array.isArray(proposedContract.baselineEvidence)
      || (proposedContract.invariants !== null && (!proposedContract.invariants || typeof proposedContract.invariants !== "object" || Array.isArray(proposedContract.invariants)))) {
    throw new Error("prepared contract must use the complete version 2 semantic boundary");
  }
  if (digest(canonicalJson(proposedContract)) !== prepared.contractHash) {
    throw new Error("prepared contract hash does not match its semantic effects");
  }
  const invocation = recipe?.agent;
  if (!invocation?.toolName || !CONTRACT_HASH.test(invocation.toolDefinitionHash || "")) {
    throw new Error("prepared invocation requires a hashed WebMCP tool definition");
  }
  for (const hash of [prepared.approvalBinding?.toolHash, prepared.approvalBinding?.argumentsHash, prepared.approvalBinding?.contractHash]) {
    if (!CONTRACT_HASH.test(hash || "")) throw new Error("prepared approval binding is invalid");
  }
  if (prepared.approvalBinding.contractHash !== prepared.contractHash) {
    throw new Error("prepared approval binding does not match the contract hash");
  }
  const body = {
    kind: "arena.reviewable_contract",
    version: 2,
    target: {
      scope: "owned_loopback_gym_fixture",
      hash: digest(`arena.target.v1\0${new URL(target).href}`),
    },
    invocation: {
      tool_name: invocation.toolName,
      tool_definition_hash: invocation.toolDefinitionHash,
      tool_hash: prepared.approvalBinding.toolHash,
      argument_keys: Object.keys(invocation.arguments || {}).sort(),
      arguments_hash: prepared.approvalBinding.argumentsHash,
    },
    expected_effects: structuredClone(proposedContract.effects),
    baseline_evidence: structuredClone(proposedContract.baselineEvidence),
    invariants: structuredClone(proposedContract.invariants),
    assurance: {
      human_proof_level: proofLevelFromEffects(proposedContract.effects),
      baseline_prepared: true,
      agent_route_observed: false,
      reviewer_authentication: "not_provided",
    },
    coverage: structuredClone(prepared.coverage),
    contract_hash: prepared.contractHash,
    created_at: created.toISOString(),
    expires_at: expires.toISOString(),
  };
  return {
    ...body,
    approval: { status: "pending", reviewer: null, approved_at: null },
    artifact_hash: digest(canonicalJson(body)),
  };
}

async function readApprovedContractArtifact(path, nowValue) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size < 2 || metadata.size > 1024 * 1024) {
    throw new Error("approved contract artifact must be a JSON file no larger than 1 MiB");
  }
  let artifact;
  try {
    artifact = JSON.parse(await readFile(path, "utf8"));
  } catch {
    throw new Error("approved contract artifact is not valid JSON");
  }
  validateApprovedArtifact(artifact, validDate(nowValue, "contract approval validation time is invalid"));
  return artifact;
}

function validateApprovedArtifact(artifact, now) {
  assertPlainObject(artifact, "approved contract artifact is malformed");
  assertExactKeys(artifact, ["approval", "artifact_hash", "assurance", "baseline_evidence", "contract_hash", "coverage", "created_at", "expected_effects", "expires_at", "invariants", "invocation", "kind", "target", "version"], "approved contract artifact");
  if (artifact.kind !== "arena.reviewable_contract" || artifact.version !== 2) {
    throw new Error("approved contract artifact kind or version is unsupported");
  }
  assertPlainObject(artifact.target, "approved contract target is malformed");
  assertExactKeys(artifact.target, ["hash", "scope"], "approved contract target");
  if (artifact.target.scope !== "owned_loopback_gym_fixture" || !CONTRACT_HASH.test(artifact.target.hash || "")) {
    throw new Error("approved contract target binding is invalid");
  }
  assertPlainObject(artifact.invocation, "approved contract invocation is malformed");
  assertExactKeys(artifact.invocation, ["argument_keys", "arguments_hash", "tool_definition_hash", "tool_hash", "tool_name"], "approved contract invocation");
  if (typeof artifact.invocation.tool_name !== "string" || !artifact.invocation.tool_name || artifact.invocation.tool_name.length > 128) {
    throw new Error("approved contract tool name is invalid");
  }
  for (const hash of [artifact.invocation.tool_definition_hash, artifact.invocation.tool_hash, artifact.invocation.arguments_hash]) {
    if (!CONTRACT_HASH.test(hash || "")) throw new Error("approved contract invocation hash is invalid");
  }
  if (!Array.isArray(artifact.invocation.argument_keys)
      || artifact.invocation.argument_keys.some((key) => typeof key !== "string" || !key || key.length > 128)
      || canonicalJson(artifact.invocation.argument_keys) !== canonicalJson([...new Set(artifact.invocation.argument_keys)].sort())) {
    throw new Error("approved contract argument keys are invalid");
  }
  if (!Array.isArray(artifact.expected_effects)) throw new Error("approved contract expected effects are invalid");
  if (!Array.isArray(artifact.baseline_evidence)) throw new Error("approved contract baseline evidence is invalid");
  if (artifact.invariants !== null) assertPlainObject(artifact.invariants, "approved contract invariants are malformed");
  assertPlainObject(artifact.assurance, "approved contract assurance is malformed");
  assertExactKeys(artifact.assurance, ["agent_route_observed", "baseline_prepared", "human_proof_level", "reviewer_authentication"], "approved contract assurance");
  if (typeof artifact.assurance.human_proof_level !== "string"
      || artifact.assurance.baseline_prepared !== true
      || artifact.assurance.agent_route_observed !== false
      || artifact.assurance.reviewer_authentication !== "not_provided") {
    throw new Error("approved contract assurance is invalid");
  }
  assertPlainObject(artifact.coverage, "approved contract coverage is malformed");
  assertExactKeys(artifact.coverage, ["agentAuthoritative", "agentTrusted", "authoritativeComplete", "complete", "humanAuthoritative", "humanTrusted", "pageAssertions"], "approved contract coverage");
  for (const key of ["humanAuthoritative", "humanTrusted", "pageAssertions"]) {
    if (!Number.isSafeInteger(artifact.coverage[key]) || artifact.coverage[key] < 0) throw new Error("approved contract coverage is invalid");
  }
  if (artifact.coverage.agentAuthoritative !== null || artifact.coverage.agentTrusted !== null ||
      artifact.coverage.authoritativeComplete !== false || artifact.coverage.complete !== false) {
    throw new Error("approved contract coverage is invalid");
  }
  if (!CONTRACT_HASH.test(artifact.contract_hash || "") || !CONTRACT_HASH.test(artifact.artifact_hash || "")) {
    throw new Error("approved contract artifact hash is invalid");
  }
  const created = validDate(artifact.created_at, "approved contract creation time is invalid");
  const expires = validDate(artifact.expires_at, "approved contract expiration is invalid");
  if (created.getTime() >= expires.getTime()) throw new Error("approved contract validity window is invalid");
  if (now.getTime() > expires.getTime()) throw new Error("approved contract artifact expired before execution");
  assertPlainObject(artifact.approval, "approved contract approval is malformed");
  assertExactKeys(artifact.approval, ["approved_at", "reviewer", "status"], "approved contract approval");
  if (artifact.approval.status !== "approved") throw new Error("contract artifact approval is still pending");
  if (typeof artifact.approval.reviewer !== "string" || !artifact.approval.reviewer.trim() || artifact.approval.reviewer.length > 200) {
    throw new Error("approved contract requires a reviewer name or identifier");
  }
  const approvedAt = validDate(artifact.approval.approved_at, "contract approval time is invalid");
  if (approvedAt.getTime() < created.getTime() || approvedAt.getTime() > now.getTime() || approvedAt.getTime() > expires.getTime()) {
    throw new Error("contract approval time is outside the artifact validity window");
  }
  const { approval: _approval, artifact_hash: _artifactHash, ...body } = artifact;
  if (digest(canonicalJson(body)) !== artifact.artifact_hash) throw new Error("approved contract artifact was tampered with");
  const reconstructedContract = {
    kind: "arena.effect_contract",
    version: 2,
    effects: artifact.expected_effects,
    baselineEvidence: artifact.baseline_evidence,
    invariants: artifact.invariants,
  };
  if (digest(canonicalJson(reconstructedContract)) !== artifact.contract_hash) {
    throw new Error("approved contract semantic effects do not match its contract hash");
  }
}

function assertArtifactMatchesPreparation(artifact, { prepared, recipe, target }) {
  const invocation = recipe.agent;
  const expectedAssurance = {
    human_proof_level: proofLevelFromEffects(prepared.proposedContract?.effects),
    baseline_prepared: true,
    agent_route_observed: false,
    reviewer_authentication: "not_provided",
  };
  const comparisons = [
    [artifact.target.hash, digest(`arena.target.v1\0${new URL(target).href}`), "target"],
    [artifact.invocation.tool_name, invocation.toolName, "tool name"],
    [artifact.invocation.tool_definition_hash, invocation.toolDefinitionHash, "tool definition"],
    [artifact.invocation.tool_hash, prepared.approvalBinding?.toolHash, "tool binding"],
    [artifact.invocation.arguments_hash, prepared.approvalBinding?.argumentsHash, "argument binding"],
    [artifact.contract_hash, prepared.contractHash, "contract hash"],
    [canonicalJson(artifact.invocation.argument_keys), canonicalJson(Object.keys(invocation.arguments || {}).sort()), "argument keys"],
    [canonicalJson(artifact.expected_effects), canonicalJson(prepared.proposedContract?.effects), "semantic effects"],
    [canonicalJson(artifact.baseline_evidence), canonicalJson(prepared.proposedContract?.baselineEvidence), "baseline evidence"],
    [canonicalJson(artifact.invariants), canonicalJson(prepared.proposedContract?.invariants), "invariants"],
    [canonicalJson(artifact.assurance), canonicalJson(expectedAssurance), "assurance"],
    [canonicalJson(artifact.coverage), canonicalJson(prepared.coverage), "coverage"],
  ];
  const mismatch = comparisons.find(([actual, expected]) => actual !== expected);
  if (mismatch) throw new Error(`approved contract ${mismatch[2]} does not match the current target preparation`);
}

async function externalArtifactPath(input, { existing = false } = {}) {
  if (typeof input !== "string" || !input.trim()) throw new Error("contract artifact path is invalid");
  const requested = isAbsolute(input) ? resolve(input) : resolve(process.cwd(), input);
  const resolvedPath = existing
    ? await realpath(requested)
    : join(await realpath(dirname(requested)), basename(requested));
  const pathFromPackage = relative(PACKAGE_ROOT, resolvedPath);
  if (pathFromPackage === "" || (!pathFromPackage.startsWith(`..${sep}`) && pathFromPackage !== ".." && !isAbsolute(pathFromPackage))) {
    throw new Error("contract artifacts must be stored outside the Arena repository");
  }
  return resolvedPath;
}

async function writeNewJsonArtifact(path, artifact) {
  const temporaryPath = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let handle = null;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(artifact, null, 2)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await link(temporaryPath, path);
  } catch (error) {
    if (error?.code === "EEXIST") throw new Error(`contract artifact already exists: ${path}`);
    throw error;
  } finally {
    await handle?.close().catch(() => {});
    await unlink(temporaryPath).catch(() => {});
  }
}

function validDate(value, message) {
  const date = value instanceof Date ? new Date(value) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error(message);
  return date;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error("contract artifact contains non-canonical data");
  }
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
}

function assertPlainObject(value, message) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(message);
  }
}

function assertExactKeys(value, expected, label) {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...expected].sort())) {
    throw new Error(`${label} contains missing or unsupported fields`);
  }
}

function containsString(value, needle) {
  if (typeof value === "string") return value.includes(String(needle));
  if (Array.isArray(value)) return value.some((item) => containsString(item, needle));
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(([key, item]) => key.includes(String(needle)) || containsString(item, needle));
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function deriveRedactionKey(fixtureToken) {
  return createHmac("sha256", String(fixtureToken)).update(REDACTION_KEY_LABEL).digest();
}

function parseOptions(tokens, allowed) {
  const options = {};
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token.startsWith("--")) throw new Error(`unexpected argument: ${token}`);
    const key = token.slice(2).replaceAll("-", "_");
    if (!allowed.has(key)) throw new Error(`unsupported option: ${token}`);
    if (Object.hasOwn(options, key)) throw new Error(`duplicate option: ${token}`);
    const value = tokens[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`missing value for ${token}`);
    options[key] = value;
    index += 1;
  }
  return options;
}

function render({ exitCode, format, report }) {
  if (format === "json") return { exitCode, stdout: `${JSON.stringify(report, null, 2)}\n`, stderr: "" };
  const artifacts = buildCiArtifacts({ reports: [ciReport(report)] });
  if (format === "sarif") return { exitCode, stdout: `${JSON.stringify(artifacts.sarif, null, 2)}\n`, stderr: "" };
  return { exitCode, stdout: `${artifacts.junit}\n`, stderr: "" };
}

function ciReport(report) {
  const findings = report.findings?.length ? report.findings : report.verdict === "pass" ? [] : [{
    code: report.reason || "audit_inconclusive",
    message: report.reason === "contract_approval_required" ? "The inferred contract requires explicit approval before the agent route can execute." : "The target audit did not produce a decisive result.",
  }];
  return {
    id: report.bundle?.auditId || report.contract_hash || "arena-target-test",
    verdict: report.verdict,
    contract: { tool_name: report.bundle?.invocation?.toolName || "book_gym_class" },
    inconclusive_reasons: report.inconclusive_reasons,
    findings: findings.map((finding) => ({
      code: finding.code,
      severity: severityFor(finding.code),
      title: finding.message || finding.code,
      root_cause: finding.message || finding.code,
      recommended_repair: "Review the paired evidence bundle and restore the human-route security outcome.",
    })),
  };
}

function severityFor(code) {
  if (/approval|owner|money|state_value/.test(code)) return "critical";
  if (/effect|network|seed|evidence|contract/.test(code)) return "high";
  return "medium";
}

function requestedFormat(argv) {
  const index = argv.indexOf("--format");
  const format = index >= 0 ? argv[index + 1] : "json";
  return new Set(["json", "sarif", "junit"]).has(format) ? format : "json";
}

function errorResult(message, format = "json") {
  const detail = String(message);
  return render({
    exitCode: 2,
    format,
    report: {
      kind: "arena.target_test",
      version: 1,
      status: "error",
      verdict: "inconclusive",
      reason: "setup_or_execution_error",
      error: detail,
      proof_level: { human: null, agent: null, native_webmcp: false },
      claim_scope: {
        target: "not_established",
        evidence: [],
        contract: "not_approved",
        agent_executed: false,
        attestation: "not_eligible",
        proves: "nothing",
        does_not_prove: ["agent-route parity", "target safety", "production enforcement"],
      },
      inconclusive_reasons: [`setup_or_execution_error: ${detail}`],
      findings: [{ code: "setup_or_execution_error", message: detail }],
    },
  });
}
