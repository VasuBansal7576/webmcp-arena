import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { runArenaCli } from "../src/arena-cli.js";
import { createGymAuditAdapters } from "../src/gym-audit-adapter.js";
import { createGymFixtureServer } from "../src/gym-fixture.js";
import { hashWebMcpToolDefinition } from "../src/webmcp-runner.js";

const fixtureToken = "arena-cli-fixture-token";

test("bare Arena and --help expose the same usable command surface", async () => {
  for (const argv of [[], ["--help"], ["help"]]) {
    const result = await runArenaCli(argv);
    assert.equal(result.exitCode, 0);
    assert.match(result.stdout, /arena init/);
    assert.match(result.stdout, /arena verify/);
    assert.match(result.stdout, /arena test/);
    assert.equal(result.stderr, "");
  }
});

test("arena init creates a typed adapter, explicit config, and behavioral proof workflow without overwriting", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-init-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const result = await runArenaCli(["init", "--directory", directory]);
  assert.equal(result.exitCode, 0, result.stderr);
  assert.match(await readFile(join(directory, "arena.config.mjs"), "utf8"), /document-sharing/);
  assert.match(await readFile(join(directory, "arena", "document-sharing.adapter.ts"), "utf8"), /defineOwnedTargetAdapter/);
  const workflow = await readFile(join(directory, ".github", "workflows", "arena.yml"), "utf8");
  assert.match(workflow, /webmcp-arena@v0\.5\.0/);
  assert.match(workflow, /mode: proof/);

  const repeated = await runArenaCli(["init", "--directory", directory]);
  assert.equal(repeated.exitCode, 2);
  assert.match(JSON.parse(repeated.stdout).error, /refusing to overwrite/);
});

test("arena verify gates a portable proof by cryptographic and semantic verdict", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "arena-verify-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const proofPath = join(directory, "proof.json");
  const proof = { kind: "arena.portable_hosted_audit_proof", evidence: { releaseVerdict: "pass" } };
  await import("node:fs/promises").then(({ writeFile }) => writeFile(proofPath, JSON.stringify(proof)));
  const calls = [];
  const passed = await runArenaCli(["verify", proofPath, "--require", "pass"], {
    async verifyProof(value) { calls.push(value); return { valid: true, verdict: "pass", payloadHash: "P".repeat(43) }; },
  });
  assert.equal(passed.exitCode, 0);
  assert.equal(JSON.parse(passed.stdout).status, "verified");
  assert.deepEqual(calls, [proof]);

  const blocked = await runArenaCli(["verify", proofPath, "--require", "pass"], {
    async verifyProof() { return { valid: true, verdict: "fail", payloadHash: "P".repeat(43) }; },
  });
  assert.equal(blocked.exitCode, 1);
  assert.equal(JSON.parse(blocked.stdout).reason, "required_verdict_not_met");
});

test("arena test prepares the real target contract but does not execute the agent without approval", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const target = `http://127.0.0.1:${fixture.server.address().port}/?arena_version=vulnerable`;
  const browserRunner = fixtureBrowserRunner();
  const browserOptions = [];
  const adapterOptions = [];

  const command = [
    "test",
    "--target", target,
    "--fixture-token", fixtureToken,
    "--browser-executable", "/test/google-chrome",
    "--browser-mode", "compatibility",
    "--format", "json",
  ];
  const overrides = {
    createBrowserRunner(options) {
      browserOptions.push(options);
      return browserRunner;
    },
    createAdapters(options) {
      adapterOptions.push(options);
      return createGymAuditAdapters(options);
    },
  };
  const result = await runArenaCli(command, overrides);
  const repeated = await runArenaCli(command, overrides);
  const report = JSON.parse(result.stdout);
  const repeatedReport = JSON.parse(repeated.stdout);

  assert.equal(result.exitCode, 2);
  assert.equal(result.stderr, "");
  assert.equal(report.status, "inconclusive", result.stdout);
  assert.equal(report.reason, "contract_approval_required");
  assert.equal(report.proof_level.human, "compatibility_shim");
  assert.equal(report.proof_level.agent, null);
  assert.equal(report.claim_scope.target, "owned_loopback_gym_fixture");
  assert.equal(report.claim_scope.agent_executed, false);
  assert.match(report.contract_hash, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(repeatedReport.contract_hash, report.contract_hash);
  assert.doesNotMatch(result.stdout, new RegExp(fixtureToken));
  assert.doesNotMatch(result.stdout, /yoga_101|human_vasu/);
  assert.deepEqual(browserRunner.calls, ["inspect", "human", "inspect", "human"]);
  assert.equal(browserOptions.length, 2);
  assert.equal(adapterOptions.length, 2);
  for (let index = 0; index < 2; index += 1) {
    assert.deepEqual(browserOptions[index].redactionKey, adapterOptions[index].redactionKey);
    assert.deepEqual(browserOptions[index].redactionKey, createHmac("sha256", fixtureToken).update("arena.cli.redaction-key.v1").digest());
  }
});

test("approved arena test returns pass and boundary-fail exit codes from real Gym routes", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;

  for (const expectation of [
    { version: "fixed", exitCode: 0, verdict: "pass" },
    { version: "vulnerable", exitCode: 1, verdict: "fail" },
  ]) {
    const browserRunner = fixtureBrowserRunner();
    const target = `${origin}/?arena_version=${expectation.version}`;
    const proposed = await runArenaCli(targetCommand(target, "json"), { createBrowserRunner: () => browserRunner });
    const contractHash = JSON.parse(proposed.stdout).contract_hash;
    const result = await runArenaCli(approvedTargetCommand(target, "json", contractHash), { createBrowserRunner: () => browserRunner });
    const report = JSON.parse(result.stdout);

    assert.equal(result.exitCode, expectation.exitCode, result.stdout || result.stderr);
    assert.equal(report.status, expectation.verdict);
    assert.equal(report.verdict, expectation.verdict);
    assert.equal(report.proof_level.human, "compatibility_shim");
    assert.equal(report.proof_level.agent, "compatibility_shim");
    assert.equal(report.proof_level.native_webmcp, false);
    assert.equal(report.claim_scope.target, "owned_loopback_gym_fixture");
    assert.equal(report.claim_scope.agent_executed, true);
    assert.equal(report.claim_scope.attestation, "unsigned_local_bundle");
    assert.equal(report.coverage.complete, true);
    assert.deepEqual(browserRunner.calls, ["inspect", "human", "inspect", "human", "human", "agent"]);
  }
});

test("arena test emits SARIF and JUnit for real target audits", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;

  const vulnerableTarget = `${origin}/?arena_version=vulnerable`;
  const vulnerableRunner = fixtureBrowserRunner();
  const vulnerableProposal = await runArenaCli(targetCommand(vulnerableTarget, "json"), { createBrowserRunner: () => vulnerableRunner });
  const sarif = await runArenaCli(approvedTargetCommand(vulnerableTarget, "sarif", JSON.parse(vulnerableProposal.stdout).contract_hash), { createBrowserRunner: () => vulnerableRunner });
  const sarifDocument = JSON.parse(sarif.stdout);
  assert.equal(sarif.exitCode, 1, sarif.stdout || sarif.stderr);
  assert.ok(sarifDocument.runs[0].results.some((finding) => finding.ruleId === "effect_mismatch"));

  const fixedTarget = `${origin}/?arena_version=fixed`;
  const fixedRunner = fixtureBrowserRunner();
  const fixedProposal = await runArenaCli(targetCommand(fixedTarget, "json"), { createBrowserRunner: () => fixedRunner });
  const junit = await runArenaCli(approvedTargetCommand(fixedTarget, "junit", JSON.parse(fixedProposal.stdout).contract_hash), { createBrowserRunner: () => fixedRunner });
  assert.equal(junit.exitCode, 0);
  assert.match(junit.stdout, /<testsuite name="Arena Boundary Audits" tests="1" failures="0"/);
  assert.doesNotMatch(junit.stdout, /<failure/);
});

test("synthetic scenarios remain available only through the explicit arena demo command", async () => {
  const demo = await runArenaCli([
    "demo",
    "--scenario", "gym_waitlist",
    "--version", "fixed",
    "--mode", "enforce",
    "--format", "json",
  ]);
  const demoReport = JSON.parse(demo.stdout);
  assert.equal(demo.exitCode, 0);
  assert.equal(demoReport.summary.passed, true);
  assert.equal(demoReport.reports[0].verdict, "pass");

  const oldTestShape = await runArenaCli([
    "test",
    "--scenario", "gym_waitlist",
    "--version", "fixed",
    "--format", "json",
  ]);
  const error = JSON.parse(oldTestShape.stdout);
  assert.equal(oldTestShape.exitCode, 2);
  assert.equal(error.status, "error");
  assert.match(error.error, /unsupported option: --scenario/);
});

test("arena preflight exposes static evidence without claiming runtime verification", async () => {
  const calls = [];
  const result = await runArenaCli([
    "preflight",
    "https://shop.example/checkout",
    "--mcp", "https://shop.example/.well-known/mcp.json",
    "--format", "json",
  ], {
    async scanUrl(target, options) {
      calls.push({ target, options });
      return {
        kind: "arena.webmcp_preflight",
        version: 1,
        source: { requested_url: target, status: 200 },
        page: {
          webmcp_evidence: {
            level: "static_marker",
            runtime_discovered: false,
            behavior_verified: false,
          },
        },
        readiness: { level: "silver", critical_gaps: [] },
      };
    },
  });

  assert.equal(result.exitCode, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.kind, "arena.webmcp_preflight");
  assert.equal(report.page.webmcp_evidence.runtime_discovered, false);
  assert.deepEqual(calls, [{
    target: "https://shop.example/checkout",
    options: {
      mcp: "https://shop.example/.well-known/mcp.json",
      openapi: undefined,
      agentSkills: undefined,
      allowPrivateTargets: false,
    },
  }]);
});

test("setup errors preserve the requested SARIF and JUnit machine formats", async () => {
  const sarif = await runArenaCli(["test", "--format", "sarif"]);
  const sarifDocument = JSON.parse(sarif.stdout);
  assert.equal(sarif.exitCode, 2);
  assert.equal(sarif.stderr, "");
  assert.equal(sarifDocument.version, "2.1.0");
  assert.ok(sarifDocument.runs[0].results.some((finding) => finding.ruleId === "setup_or_execution_error"));

  const junit = await runArenaCli(["test", "--format", "junit"]);
  assert.equal(junit.exitCode, 2);
  assert.equal(junit.stderr, "");
  assert.match(junit.stdout, /<testsuite name="Arena Boundary Audits"/);
  assert.match(junit.stdout, /setup_or_execution_error/);
});

test("arena test rejects blanket, malformed, and mismatched approvals before agent execution", async (t) => {
  const fixture = createGymFixtureServer({ fixtureToken });
  await listen(fixture.server);
  t.after(() => close(fixture.server));
  const target = `http://127.0.0.1:${fixture.server.address().port}/?arena_version=fixed`;
  const browserRunner = fixtureBrowserRunner();
  const overrides = { createBrowserRunner: () => browserRunner };

  for (const invalidApproval of ["true", "short"] ) {
    const result = await runArenaCli(approvedTargetCommand(target, "json", invalidApproval), overrides);
    const report = JSON.parse(result.stdout);
    assert.equal(result.exitCode, 2);
    assert.equal(report.reason, "setup_or_execution_error");
    assert.match(report.error, /exact 43-character contract hash/);
  }
  assert.deepEqual(browserRunner.calls, []);

  const mismatched = await runArenaCli(approvedTargetCommand(target, "json", "A".repeat(43)), overrides);
  const mismatchReport = JSON.parse(mismatched.stdout);
  assert.equal(mismatched.exitCode, 2);
  assert.equal(mismatchReport.status, "inconclusive");
  assert.equal(mismatchReport.reason, "contract_approval_hash_mismatch");
  assert.equal(mismatchReport.claim_scope.agent_executed, false);
  assert.deepEqual(browserRunner.calls, ["inspect", "human"]);
});

function targetCommand(target, format) {
  return [
    "test",
    "--target", target,
    "--fixture-token", fixtureToken,
    "--browser-executable", "/test/google-chrome",
    "--browser-mode", "compatibility",
    "--format", format,
  ];
}

function approvedTargetCommand(target, format, contractHash) {
  return [...targetCommand(target, format), "--approve-contract", contractHash];
}

function fixtureBrowserRunner() {
  const definition = {
    name: "book_gym_class",
    title: "Book gym class",
    description: "Attempt to book a gym class for a member.",
    inputSchema: {
      type: "object",
      properties: { classId: { type: "string" }, memberId: { type: "string" } },
      required: ["classId", "memberId"],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, untrustedContentHint: false },
    origin: null,
  };
  const calls = [];

  return {
    calls,
    async inspect({ url }) {
      calls.push("inspect");
      const target = new URL(url);
      return { proof_level: "compatibility_shim", tools: [{ ...definition, origin: target.origin }] };
    },
    async recordHumanRoute({ url }) {
      calls.push("human");
      return runRoute({ url, path: "/api/human/book", body: { classId: "yoga_101" } });
    },
    async execute({ url, arguments: args, expectedToolHash }) {
      calls.push("agent");
      const target = new URL(url);
      assert.equal(expectedToolHash, hashWebMcpToolDefinition({ ...definition, origin: target.origin }));
      const result = await runRoute({ url, path: "/api/agent/book", body: args });
      return { ...result, tool_definition_hash: expectedToolHash };
    },
  };

  async function runRoute({ url, path, body }) {
    const target = new URL(url);
    const trialId = target.searchParams.get("arena_trial");
    const runId = target.searchParams.get("arena_run_id");
    const response = await fetch(`${target.origin}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-arena-trial-id": trialId,
        "x-arena-run-id": runId,
      },
      body: JSON.stringify(body),
    });
    const routeResult = await response.json();
    const visible = routeResult.status === "booked" ? "Booking confirmed" : `Booking blocked: ${routeResult.reason}`;
    const definitionHash = hashWebMcpToolDefinition({ ...definition, origin: target.origin });
    return {
      url: target.href,
      proof_level: "compatibility_shim",
      execution_transport: "object",
      isolated_context: true,
      effect_trace: {
        proof_level: "compatibility_shim",
        capture: {
          complete: true,
          reason: "quiescent",
          waited_ms: 0,
          pending_requests: 0,
        },
        network: [{ method: "POST", url: `${target.origin}${path}`, status: response.status, query: [], body: null }],
        ui: { changed: ["#status"], after_value_hashes: { "#status": digest(visible) } },
        tool_definitions: [{ name: definition.name, hash: definitionHash }],
        page_assertions: { provenance: "page_asserted", protections: [], approvals: [] },
      },
    };
  }
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("base64url");
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function close(server) {
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
