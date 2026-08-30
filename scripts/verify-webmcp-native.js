import assert from "node:assert/strict";

import { runArenaCli } from "../src/arena-cli.js";
import { verifyAuditBundle } from "../src/boundary-audit.js";
import { createGymFixtureServer } from "../src/gym-fixture.js";

if (process.env.ARENA_RUN_EXTERNAL_BROWSER_TESTS !== "1" || process.env.ARENA_RUN_NATIVE_WEBMCP_TESTS !== "1") {
  throw new Error("Native external-browser verification is opt-in. Run npm run verify:webmcp:native.");
}

const executablePath = process.env.ARENA_BROWSER_EXECUTABLE || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const fixtureToken = "arena-native-fixture-token-2026";
const fixture = createGymFixtureServer({ fixtureToken });

try {
  await listen(fixture.server);
  const origin = `http://127.0.0.1:${fixture.server.address().port}`;
  const results = {};
  for (const version of ["vulnerable", "fixed"]) {
    const args = [
      "test",
      "--target", `${origin}/?arena_version=${version}`,
      "--fixture-token", fixtureToken,
      "--browser-executable", executablePath,
      "--browser-mode", "native",
      "--format", "json",
    ];
    const preparation = await runArenaCli(args);
    const prepared = JSON.parse(preparation.stdout);
    assert.equal(preparation.exitCode, 2);
    assert.equal(prepared.reason, "contract_approval_required");
    assert.equal(prepared.claim_scope.agent_executed, false);
    assert.match(prepared.contract_hash, /^[A-Za-z0-9_-]{43}$/);
    const execution = await runArenaCli([...args, "--approve-contract", prepared.contract_hash]);
    const audit = JSON.parse(execution.stdout);
    const verification = await verifyAuditBundle(audit.bundle);
    const proofLevels = audit.bundle.events
      .filter((event) => event.payload?.kind === "execution_proof")
      .map((event) => ({ route: event.route, level: event.payload.level }));
    results[version] = {
      verdict: audit.verdict,
      finding_codes: audit.findings.map((finding) => finding.code),
      coverage: audit.coverage,
      preparation_contract_hash: prepared.contract_hash,
      approved_contract_hash: audit.bundle.contractHash,
      execution_transport: audit.bundle.events
        .filter((event) => event.payload?.kind === "execution_proof")
        .map((event) => ({ route: event.route, transport: event.payload.executionTransport || null })),
      proof_levels: proofLevels,
      bundle_hash: audit.bundle.bundleHash,
      bundle_verified: verification.valid,
      attested: verification.attested,
    };
    assert.equal(results[version].preparation_contract_hash, results[version].approved_contract_hash);
    assert.equal(execution.exitCode, version === "fixed" ? 0 : 1);
  }

  assert.equal(results.vulnerable.verdict, "fail");
  assert.ok(results.vulnerable.finding_codes.includes("authorization_outcome_changed"));
  assert.ok(results.vulnerable.finding_codes.includes("unexpected_consequential_effect"));
  assert.equal(results.fixed.verdict, "pass");
  assert.equal(results.vulnerable.bundle_verified, true);
  assert.equal(results.fixed.bundle_verified, true);
  for (const result of Object.values(results)) {
    assert.ok(result.proof_levels.length >= 2);
    assert.ok(result.proof_levels.every((entry) => entry.level === "native_browser_api"));
    assert.equal(result.execution_transport.find((entry) => entry.route === "human")?.transport, null);
    assert.equal(result.execution_transport.find((entry) => entry.route === "agent")?.transport, "cdp_browser_agent");
  }

  process.stdout.write(`${JSON.stringify({
    kind: "arena.native_webmcp_verification",
    version: 1,
    browser: executablePath,
    claim_scope: "paired seeded runs against the owned Arena Gym fixture",
    results,
  }, null, 2)}\n`);
} finally {
  if (fixture.server.listening) await close(fixture.server);
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
