import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runArenaCli } from "../src/arena-cli.js";

const fixtureToken = "artifact-fixture-secret";
const target = "http://127.0.0.1:43123/?arena_version=fixed";
const contractHash = "JYxajjjPWiC-WvqmzV667R5cwjcAxTEHvw_DHc2cBVY";
const effects = [
  { kind: "execution_proof", level: "compatibility_shim" },
  { kind: "authorization", outcome: "denied", reason: "booking_window_closed" },
];
const baselineEvidence = [
  { provenance: "recorder_observed", payload: effects[0] },
  { provenance: "server_attested", payload: effects[1] },
];

test("arena test writes a reviewable pending contract artifact without exposing fixture credentials", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifactPath = join(directory, "gym-contract.json");
  const dependencies = workflowDependencies();

  const result = await runArenaCli([
    ...targetCommand(),
    "--write-contract", artifactPath,
  ], dependencies);
  const report = JSON.parse(result.stdout);
  const artifactText = await readFile(artifactPath, "utf8");
  const artifact = JSON.parse(artifactText);

  assert.equal(result.exitCode, 2);
  assert.equal(report.reason, "contract_approval_required");
  assert.deepEqual(report.routeParity, { status: "not_evaluated", findings: [] });
  assert.deepEqual(report.baselineSafety, { status: "not_evaluated", findings: [] });
  assert.equal(report.contract_artifact.path, await realpath(artifactPath));
  assert.equal(report.contract_artifact.approval_status, "pending");
  assert.deepEqual(artifact, {
    kind: "arena.reviewable_contract",
    version: 2,
    target: {
      scope: "owned_loopback_gym_fixture",
      hash: artifact.target.hash,
    },
    invocation: {
      tool_name: "book_gym_class",
      tool_definition_hash: "D".repeat(43),
      tool_hash: "T".repeat(43),
      argument_keys: ["classId", "memberId"],
      arguments_hash: "A".repeat(43),
    },
    expected_effects: effects,
    baseline_evidence: baselineEvidence,
    invariants: null,
    assurance: {
      human_proof_level: "compatibility_shim",
      baseline_prepared: true,
      agent_route_observed: false,
      reviewer_authentication: "not_provided",
    },
    coverage: preparedContract().coverage,
    contract_hash: contractHash,
    created_at: "2026-08-30T10:00:00.000Z",
    expires_at: "2026-08-30T10:10:00.000Z",
    approval: {
      status: "pending",
      reviewer: null,
      approved_at: null,
    },
    artifact_hash: artifact.artifact_hash,
  });
  assert.match(artifact.target.hash, /^[A-Za-z0-9_-]{43}$/);
  assert.match(artifact.artifact_hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(artifactText.endsWith("\n"), true);
  assert.equal(artifactText.includes(fixtureToken), false);
  assert.equal(artifactText.includes("human_vasu"), false);
  assert.deepEqual(dependencies.calls, ["browser", "adapters", "recipe", "auditor", "prepare"]);
});

test("arena test consumes a human-approved artifact only after re-preparing the exact contract", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifactPath = join(directory, "gym-contract.json");
  await runArenaCli([...targetCommand(), "--write-contract", artifactPath], workflowDependencies());
  const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
  artifact.approval = {
    status: "approved",
    reviewer: "Vasu",
    approved_at: "2026-08-30T10:04:00.000Z",
  };
  await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`);
  const dependencies = workflowDependencies({
    now: new Date("2026-08-30T10:05:00.000Z"),
    audit: completedAudit(),
  });

  const result = await runArenaCli([
    ...targetCommand(),
    "--approved-contract", artifactPath,
  ], dependencies);
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 0, result.stdout);
  assert.equal(report.verdict, "pass");
  assert.deepEqual(report.routeParity, { status: "pass", findings: [] });
  assert.deepEqual(report.baselineSafety, { status: "not_evaluated", findings: [] });
  assert.equal(report.claim_scope.agent_executed, true);
  assert.deepEqual(dependencies.calls, ["browser", "adapters", "recipe", "auditor", "prepare", "run"]);
  assert.deepEqual(dependencies.runInputs, [{
    planId: "plan-reviewable-contract",
    approval: {
      status: "approved",
      planId: "plan-reviewable-contract",
      toolHash: "T".repeat(43),
      argumentsHash: "A".repeat(43),
      contractHash,
    },
  }]);
});

test("pending, malformed, expired, and modified artifacts fail before target preparation", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifactPath = join(directory, "gym-contract.json");
  await runArenaCli([...targetCommand(), "--write-contract", artifactPath], workflowDependencies());
  const pending = JSON.parse(await readFile(artifactPath, "utf8"));
  const approved = {
    ...pending,
    approval: { status: "approved", reviewer: "Vasu", approved_at: "2026-08-30T10:04:00.000Z" },
  };
  const cases = [
    { name: "pending", value: pending, now: "2026-08-30T10:05:00.000Z", error: /still pending/ },
    { name: "malformed", value: "{not-json", now: "2026-08-30T10:05:00.000Z", error: /not valid JSON/ },
    { name: "expired", value: approved, now: "2026-08-30T10:11:00.000Z", error: /expired before execution/ },
    {
      name: "modified",
      value: { ...approved, expected_effects: [...approved.expected_effects, { kind: "money", amount: 1 }] },
      now: "2026-08-30T10:05:00.000Z",
      error: /tampered with/,
    },
  ];

  for (const candidate of cases) {
    await writeFile(artifactPath, typeof candidate.value === "string" ? candidate.value : `${JSON.stringify(candidate.value)}\n`);
    const dependencies = workflowDependencies({ now: new Date(candidate.now), audit: completedAudit() });
    const result = await runArenaCli([...targetCommand(), "--approved-contract", artifactPath], dependencies);
    const report = JSON.parse(result.stdout);
    assert.equal(result.exitCode, 2, candidate.name);
    assert.match(report.error, candidate.error, candidate.name);
    assert.equal(report.claim_scope.agent_executed, false, candidate.name);
    assert.deepEqual(dependencies.calls, [], candidate.name);
  }
});

test("a reviewed artifact cannot authorize changed v2 semantics or coverage", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifactPath = join(directory, "gym-contract.json");
  await runArenaCli([...targetCommand(), "--write-contract", artifactPath], workflowDependencies());
  const artifact = JSON.parse(await readFile(artifactPath, "utf8"));
  artifact.approval = { status: "approved", reviewer: "Vasu", approved_at: "2026-08-30T10:04:00.000Z" };
  await writeFile(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`);
  const cases = [
    {
      field: "semantic effects",
      change(prepared) { prepared.proposedContract.effects.push({ kind: "ui", selector: "#changed" }); },
    },
    {
      field: "baseline evidence",
      change(prepared) {
        prepared.proposedContract.baselineEvidence.push({ provenance: "server_attested", payload: { kind: "state", after: "changed" } });
      },
    },
    {
      field: "invariants",
      change(prepared) { prepared.proposedContract.invariants = { version: 1, requireApprovalBeforeEffect: true }; },
    },
    {
      field: "coverage",
      change(prepared) { prepared.coverage.humanTrusted = 3; },
    },
  ];

  for (const candidate of cases) {
    const changed = structuredClone(preparedContract());
    candidate.change(changed);
    const dependencies = workflowDependencies({
      prepared: changed,
      now: new Date("2026-08-30T10:05:00.000Z"),
      audit: completedAudit(),
    });
    const result = await runArenaCli([...targetCommand(), "--approved-contract", artifactPath], dependencies);
    const report = JSON.parse(result.stdout);
    assert.equal(result.exitCode, 2, candidate.field);
    assert.match(report.error, new RegExp(`${candidate.field} does not match the current target preparation`), candidate.field);
    assert.deepEqual(dependencies.calls, ["browser", "adapters", "recipe", "auditor", "prepare"], candidate.field);
    assert.deepEqual(dependencies.runInputs, [], candidate.field);
  }
});

test("contract artifact creation never overwrites an existing review file", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifactPath = join(directory, "gym-contract.json");
  await runArenaCli([...targetCommand(), "--write-contract", artifactPath], workflowDependencies());
  const original = await readFile(artifactPath, "utf8");

  const result = await runArenaCli([...targetCommand(), "--write-contract", artifactPath], workflowDependencies());
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 2);
  assert.match(report.error, /contract artifact already exists/);
  assert.equal(await readFile(artifactPath, "utf8"), original);
});

test("contract artifacts are refused inside the Arena repository before preparation", async () => {
  const artifactPath = join(process.cwd(), ".arena-contract-should-not-exist.json");
  const dependencies = workflowDependencies();

  const result = await runArenaCli([...targetCommand(), "--write-contract", artifactPath], dependencies);
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 2);
  assert.match(report.error, /outside the Arena repository/);
  assert.deepEqual(dependencies.calls, []);
  await assert.rejects(() => readFile(artifactPath), /ENOENT/);
});

test("an external symlink cannot disguise an approved artifact stored inside the repository", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const disguisedPath = join(directory, "review.json");
  await symlink(join(process.cwd(), "README.md"), disguisedPath);
  const dependencies = workflowDependencies();

  const result = await runArenaCli([...targetCommand(), "--approved-contract", disguisedPath], dependencies);
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 2);
  assert.match(report.error, /outside the Arena repository/);
  assert.deepEqual(dependencies.calls, []);
});

test("artifact creation fails closed if prepared evidence contains the fixture credential", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-contract-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const artifactPath = join(directory, "gym-contract.json");
  const prepared = preparedContract();
  prepared.proposedContract.effects = [{ kind: "authorization", reason: fixtureToken }];
  prepared.proposedContract.baselineEvidence = [{
    provenance: "server_attested",
    payload: { kind: "authorization", reason: fixtureToken },
  }];
  prepared.contractHash = "3Co-kHL_pFbyXuX6yAVKhqKyowishUqb7CSlxSII_gU";
  prepared.approvalBinding.contractHash = prepared.contractHash;

  const result = await runArenaCli(
    [...targetCommand(), "--write-contract", artifactPath],
    workflowDependencies({ prepared }),
  );
  const report = JSON.parse(result.stdout);

  assert.equal(result.exitCode, 2);
  assert.match(report.error, /fixture credential/);
  await assert.rejects(() => readFile(artifactPath), /ENOENT/);
});

function targetCommand() {
  return [
    "test",
    "--target", target,
    "--fixture-token", fixtureToken,
    "--browser-executable", "/mock/chrome",
    "--browser-mode", "compatibility",
    "--format", "json",
  ];
}

function preparedContract() {
  return {
    planId: "plan-reviewable-contract",
    proposedContract: {
      kind: "arena.effect_contract",
      version: 2,
      effects,
      baselineEvidence,
      invariants: null,
    },
    contractHash,
    approvalBinding: {
      toolHash: "T".repeat(43),
      argumentsHash: "A".repeat(43),
      contractHash,
    },
    coverage: {
      humanTrusted: 2,
      agentTrusted: null,
      humanAuthoritative: 1,
      agentAuthoritative: null,
      authoritativeComplete: false,
      pageAssertions: 0,
      complete: false,
    },
    baselineSafety: { status: "not_evaluated", findings: [] },
    expiresAt: "2026-08-30T10:10:00.000Z",
  };
}

function workflowDependencies({ prepared = preparedContract(), now = new Date("2026-08-30T10:00:00.000Z"), audit = null } = {}) {
  const calls = [];
  const runInputs = [];
  return {
    calls,
    runInputs,
    now: () => new Date(now),
    createBrowserRunner() {
      calls.push("browser");
      return {};
    },
    createAdapters() {
      calls.push("adapters");
      return {
        targetHarness: {},
        routeRunner: {},
        async createRecipe() {
          calls.push("recipe");
          return {
            target,
            principalRef: "human_vasu",
            human: { actions: [{ type: "click", selector: "#book" }] },
            agent: {
              toolName: "book_gym_class",
              toolDefinitionHash: "D".repeat(43),
              arguments: { memberId: "human_vasu", classId: "yoga_101" },
            },
          };
        },
      };
    },
    createAuditor() {
      calls.push("auditor");
      return {
        async prepare() {
          calls.push("prepare");
          return structuredClone(prepared);
        },
        async run(input) {
          calls.push("run");
          runInputs.push(structuredClone(input));
          if (!audit) throw new Error("agent execution was not expected");
          return structuredClone(audit);
        },
      };
    },
  };
}

function completedAudit() {
  return {
    verdict: "pass",
    findings: [],
    routeParity: { status: "pass", findings: [] },
    baselineSafety: { status: "not_evaluated", findings: [] },
    coverage: { complete: true },
    bundle: {
      auditId: "audit-reviewed-contract",
      invocation: { toolName: "book_gym_class" },
      events: [
        { route: "human", payload: { kind: "execution_proof", level: "compatibility_shim" } },
        { route: "agent", payload: { kind: "execution_proof", level: "compatibility_shim" } },
      ],
      attestation: { eligible: true, proof: null },
    },
    attestation: { eligible: true, proof: null },
  };
}
