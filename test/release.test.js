import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import { runReleaseCheck } from "../src/release.js";

test("runReleaseCheck accepts the current Arena release contract", async (t) => {
  const root = await createReleaseFixture();
  t.after(() => rm(root, { recursive: true, force: true }));

  const result = await runReleaseCheck({ root });

  assert.equal(result.status, "passed", JSON.stringify(result.checks, null, 2));
  assert.deepEqual(
    result.checks.map((check) => check.id),
    [
      "package_identity",
      "package_publishable",
      "package_metadata",
      "arena_cli",
      "legacy_surface_absent",
      "retired_sources_absent",
      "package_files",
      "package_scripts",
      "start_script",
      "release_script",
      "arena_script",
      "webmcp_registration",
      "action_uses_arena",
      "action_runtime_safe",
      "github_action_example",
      "release_documents",
      "obsolete_docs_absent",
      "dead_guard_absent",
    ],
  );
});

test("runReleaseCheck rejects obsolete docs, spec files, and the unused WebMCP guard", async (t) => {
  const root = await createReleaseFixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  await write(root, "docs/positioning-post.md", "obsolete\n");
  await write(root, "spec/README.md", "obsolete\n");
  await write(root, "src/webmcp-guard.js", "export {};\n");
  await write(root, "test/webmcp-guard.test.js", "export {};\n");

  const result = await runReleaseCheck({ root });

  assert.equal(result.status, "failed");
  assert.deepEqual(
    result.checks.find((check) => check.id === "obsolete_docs_absent"),
    {
      id: "obsolete_docs_absent",
      status: "failed",
      message: "obsolete docs and spec files must not ship",
    },
  );
  assert.equal(result.checks.find((check) => check.id === "dead_guard_absent").status, "failed");
});

test("runReleaseCheck rejects a broad scripts package entry and the obsolete check alias", async (t) => {
  const root = await createReleaseFixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  pkg.files = pkg.files.filter((entry) => !entry.startsWith("scripts/"));
  pkg.files.push("scripts/", "scripts/smoke-local.js");
  pkg.scripts.check = "npm test";
  await write(root, "package.json", `${JSON.stringify(pkg, null, 2)}\n`);

  const result = await runReleaseCheck({ root });

  assert.equal(result.checks.find((check) => check.id === "package_files").status, "failed");
  assert.equal(result.checks.find((check) => check.id === "package_scripts").status, "failed");
});

test("runReleaseCheck rejects a default test command that can inherit external-browser flags", async (t) => {
  const root = await createReleaseFixture();
  t.after(() => rm(root, { recursive: true, force: true }));
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  pkg.scripts.test = "node --test";
  await write(root, "package.json", `${JSON.stringify(pkg, null, 2)}\n`);

  const result = await runReleaseCheck({ root });

  assert.deepEqual(result.checks.find((check) => check.id === "package_scripts"), {
    id: "package_scripts",
    status: "failed",
    message: "package scripts must keep default tests browser-free, make external-browser checks explicit, and omit the redundant check alias",
  });
});

test("the repository satisfies the current Arena release contract", async () => {
  const result = await runReleaseCheck({ root: process.cwd() });

  assert.equal(result.status, "passed", JSON.stringify(result.checks, null, 2));
  assert.equal(result.checks.every((check) => check.status === "passed"), true);
});

async function createReleaseFixture() {
  const root = await mkdtemp(join(tmpdir(), "arena-release-"));
  const pkg = {
    name: "webmcp-arena",
    version: "0.2.0",
    license: "MIT",
    repository: { type: "git", url: "git+https://github.com/VasuBansal7576/webmcp-arena.git" },
    homepage: "https://github.com/VasuBansal7576/webmcp-arena#readme",
    bugs: { url: "https://github.com/VasuBansal7576/webmcp-arena/issues" },
    bin: {
      arena: "./bin/arena.js",
    },
    files: [
      "README.md",
      "CONTRIBUTING.md",
      "LICENSE",
      "action.yml",
      "bin/",
      "examples/",
      "scripts/arena-server.js",
      "scripts/release-check.js",
      "scripts/verify-webmcp-native.js",
      ...releaseSources(),
    ],
    scripts: {
      start: "node scripts/arena-server.js",
      test: "ARENA_RUN_EXTERNAL_BROWSER_TESTS=0 ARENA_RUN_NATIVE_WEBMCP_TESTS=0 node --test",
      "test:external-browser": "ARENA_RUN_EXTERNAL_BROWSER_TESTS=1 node --test test/webmcp-runner.test.js",
      "test:external-browser:native": "ARENA_RUN_EXTERNAL_BROWSER_TESTS=1 ARENA_RUN_NATIVE_WEBMCP_TESTS=1 node --test test/webmcp-runner.test.js",
      "verify:webmcp:native": "ARENA_RUN_EXTERNAL_BROWSER_TESTS=1 ARENA_RUN_NATIVE_WEBMCP_TESTS=1 node scripts/verify-webmcp-native.js",
      arena: "node scripts/arena-server.js",
      "release:check": "node scripts/release-check.js",
    },
  };

  await write(root, "package.json", JSON.stringify(pkg));
  await write(root, "README.md", "# Arena\n\nHuman-vs-Agent Boundary Audit for WebMCP. The Human-vs-Agent Checkout Proof uses an owned Checkout fixture and `document.modelContext.registerTool`. Run `arena preflight <url>` or `arena test --target`. Static preflight does not prove runtime behavior.\n\n## Current limitations\n");
  await write(root, "CONTRIBUTING.md", "# Contributing\n\nRequire the exact contract hash. Run `npm test` and `npm run release:check`.\n");
  await write(root, "LICENSE", "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy.\n");
  await write(root, "action.yml", 'Arena WebMCP Preflight bin/arena.js preflight actions/setup-node@v4 node-version: "22" npm ci --ignore-scripts --omit=dev set -euo pipefail ARENA_INPUT_URL\n');
  await write(root, "bin/arena.js", "#!/usr/bin/env node\n");
  await write(root, "scripts/arena-server.js", "export {};\n");
  await write(root, "scripts/verify-webmcp-native.js", "export {};\n");
  await write(root, "scripts/release-check.js", "export {};\n");
  await write(root, "examples/github-action.yml", "name: Arena\nuses: VasuBansal7576/webmcp-arena@v0.2.0\nif: always()\n");
  await write(root, "src/arena-page.js", "document.modelContext.registerTool({ name: 'inspect_boundary_bundle' });\n");
  await write(root, "src/release.js", "export {};\n");
  return root;
}

function releaseSources() {
  return [
    "src/adapter-sdk.js", "src/agent-regression.js", "src/approval-envelope.js", "src/arena-cli.js",
    "src/arena-config.js", "src/arena-page.js", "src/arena-proof.js", "src/behavioral-verifier.js",
    "src/boundary-audit.js", "src/checkout-audit-adapter.js", "src/checkout-fixture.js", "src/ci-report.js",
    "src/effect-settlement.js", "src/gym-audit-adapter.js", "src/gym-fixture.js", "src/identity.js",
    "src/incident-lab.js", "src/mcp.js", "src/measured-audit-service.js", "src/passkey-authenticator.js",
    "src/release.js", "src/safe-fetch.js", "src/scanner.js", "src/secret-envelope.js", "src/skills.js",
    "src/state-store.js", "src/trust.js", "src/util.js", "src/webmcp-tool-definition.js", "src/webmcp-runner.js",
  ];
}

async function write(root, path, contents) {
  const destination = join(root, path);
  await mkdir(dirname(destination), { recursive: true });
  await writeFile(destination, contents);
}
