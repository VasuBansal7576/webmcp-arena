import { access, readFile } from "node:fs/promises";
import { join } from "node:path";

const RELEASE_SOURCES = [
  "src/adapter-sdk.js",
  "src/agent-regression.js",
  "src/approval-envelope.js",
  "src/arena-cli.js",
  "src/arena-config.js",
  "src/arena-page.js",
  "src/arena-proof.js",
  "src/behavioral-verifier.js",
  "src/boundary-audit.js",
  "src/checkout-audit-adapter.js",
  "src/checkout-fixture.js",
  "src/ci-report.js",
  "src/effect-settlement.js",
  "src/gym-audit-adapter.js",
  "src/gym-fixture.js",
  "src/identity.js",
  "src/incident-lab.js",
  "src/mcp.js",
  "src/measured-audit-service.js",
  "src/passkey-authenticator.js",
  "src/release.js",
  "src/safe-fetch.js",
  "src/scanner.js",
  "src/secret-envelope.js",
  "src/skills.js",
  "src/state-store.js",
  "src/trust.js",
  "src/util.js",
  "src/webmcp-tool-definition.js",
  "src/webmcp-runner.js",
];

const RETIRED_SOURCES = [
  "src/abr.js", "src/auth.js", "src/cli.js", "src/contract.js", "src/drift.js", "src/fixpack.js",
  "src/llmfix.js", "src/logs.js", "src/membrane.js", "src/missions.js", "src/monitor.js", "src/policy.js",
  "src/pr.js", "src/repo.js", "src/report.js", "src/telemetry.js",
];

export async function runReleaseCheck({ root = process.cwd() } = {}) {
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const [action, readme, contributing, license, arenaPage, ciWorkflow] = await Promise.all([
    text(root, "action.yml"),
    text(root, "README.md"),
    text(root, "CONTRIBUTING.md"),
    text(root, "LICENSE"),
    text(root, "src/arena-page.js"),
    text(root, ".github/workflows/ci.yml"),
  ]);
  const packagedScripts = [
    "scripts/arena-server.js",
    "scripts/release-check.js",
    "scripts/verify-webmcp-native.js",
  ];
  const requiredPackageFiles = ["README.md", "CONTRIBUTING.md", "LICENSE", "action.yml", "bin/", "examples/", ...packagedScripts, ...RELEASE_SOURCES];
  const requiredTestScripts = {
    test: "ARENA_RUN_EXTERNAL_BROWSER_TESTS=0 ARENA_RUN_NATIVE_WEBMCP_TESTS=0 node --test",
    "test:external-browser": "ARENA_RUN_EXTERNAL_BROWSER_TESTS=1 node --test test/webmcp-runner.test.js",
    "test:external-browser:native": "ARENA_RUN_EXTERNAL_BROWSER_TESTS=1 ARENA_RUN_NATIVE_WEBMCP_TESTS=1 node --test test/webmcp-runner.test.js",
    "verify:webmcp:native": "ARENA_RUN_EXTERNAL_BROWSER_TESTS=1 ARENA_RUN_NATIVE_WEBMCP_TESTS=1 node scripts/verify-webmcp-native.js",
  };
  const obsoleteDocuments = [
    "architecture_v3.md",
    "context.md",
    "schema/contract.schema.json",
    "docs/agent-contract-schema.md",
    "docs/positioning-post.md",
    "docs/pr-slices.md",
    "spec/README.md",
  ];
  const obsoleteDocumentPresent = (await Promise.all(obsoleteDocuments.map((path) => exists(root, path)))).some(Boolean);
  const legacySurfacePresent = (await Promise.all([
    exists(root, "bin/agent-contract.js"),
    exists(root, "bin/agent-traffic-parser.js"),
    exists(root, "scripts/solo-server.js"),
  ])).some(Boolean);
  const retiredSourcePresent = (await Promise.all(RETIRED_SOURCES.map((path) => exists(root, path)))).some(Boolean);
  const packageFilesExact = JSON.stringify([...(pkg.files || [])].sort()) === JSON.stringify([...requiredPackageFiles].sort());
  const checks = [
    check("package_identity", pkg.name === "webmcp-arena" && pkg.version === "0.2.0", "package must use the WebMCP Arena release identity"),
    check("package_publishable", pkg.private !== true && pkg.license && pkg.license !== "UNLICENSED", "package must be publishable and licensed"),
    check("package_metadata", pkg.repository?.url === "git+https://github.com/VasuBansal7576/webmcp-arena.git" && pkg.homepage === "https://github.com/VasuBansal7576/webmcp-arena#readme" && pkg.bugs?.url === "https://github.com/VasuBansal7576/webmcp-arena/issues", "package must point to the public WebMCP Arena repository, homepage, and issue tracker"),
    check("arena_cli", pkg.bin?.arena === "./bin/arena.js" && await exists(root, "bin/arena.js"), "package bin must expose the Arena CLI"),
    check("legacy_surface_absent", Object.keys(pkg.bin || {}).join(",") === "arena" && !legacySurfacePresent, "release must expose Arena only and omit retired Agent Contract entry points"),
    check("retired_sources_absent", !retiredSourcePresent, "retired Agent Contract modules must not remain in the focused repository"),
    check("package_files", packageFilesExact, "package files must exactly match the reviewed Arena source and artifact allowlist"),
    check("package_scripts", pkg.scripts?.check === undefined && Object.entries(requiredTestScripts).every(([name, command]) => pkg.scripts?.[name] === command), "package scripts must keep default tests browser-free, make external-browser checks explicit, and omit the redundant check alias"),
    check("start_script", pkg.scripts?.start === "node scripts/arena-server.js", "package start script must launch the Arena server"),
    check("release_script", pkg.scripts?.["release:check"] === "node scripts/release-check.js", "release check script must be wired"),
    check("arena_script", pkg.scripts?.arena === "node scripts/arena-server.js" && await exists(root, "scripts/arena-server.js"), "Arena server script must be wired"),
    check("webmcp_registration", arenaPage.includes("document.modelContext") && arenaPage.includes("registerTool"), "Arena web UI must register real document.modelContext tools"),
    check("action_uses_arena", action.includes("Arena WebMCP Preflight") && action.includes("bin/arena.js") && action.includes("preflight") && !action.includes("bin/agent-contract.js"), "composite action must run the Arena WebMCP preflight CLI"),
    check("action_runtime_safe", action.includes("actions/setup-node@v4") && action.includes('node-version: "22"') && action.includes("npm ci --ignore-scripts --omit=dev") && action.includes("set -euo pipefail") && action.includes("ARENA_INPUT_URL") && !action.includes('args=("${{ inputs.url }}"'), "composite action must select Node 22, install runtime dependencies, preserve pipeline failures, and pass inputs through the environment"),
    check("github_action_example", await exists(root, "examples/github-action.yml") && (await text(root, "examples/github-action.yml")).includes("uses: VasuBansal7576/webmcp-arena@v0.2.0") && (await text(root, "examples/github-action.yml")).includes("if: always()"), "example workflow must use the versioned Arena action and retain reports when inspection fails"),
    check(
      "ci_workflow",
      ciWorkflow.includes("actions/checkout@v4")
        && ciWorkflow.includes("actions/setup-node@v4")
        && (ciWorkflow.includes("node-version: 22") || ciWorkflow.includes('node-version: "22"'))
        && ciWorkflow.includes("run: npm ci")
        && ciWorkflow.includes("run: npm test")
        && ciWorkflow.includes("run: npm run release:check")
        && ciWorkflow.includes("run: npx tsc --noEmit --incremental false")
        && ciWorkflow.includes("run: npm run build:site")
        && ciWorkflow.includes("run: npm pack --dry-run")
        && ciWorkflow.includes("run: git diff --check")
        && !ciWorkflow.includes("test:external-browser"),
      "CI must run the browser-free tests, release contract, type-check, production build, package dry run, and whitespace gate on Node 22",
    ),
    check("release_documents", readme.includes("# Arena") && readme.includes("Human-vs-Agent Boundary Audit") && readme.includes("## Current limitations") && readme.includes("arena preflight") && readme.includes("arena test --target") && readme.includes("Human-vs-Agent Checkout Proof") && readme.includes("owned Checkout fixture") && readme.includes("Static preflight") && readme.includes("document.modelContext.registerTool") && !readme.includes("This command is not implemented") && !readme.includes("Legacy Agent Contract") && contributing.includes("exact contract hash") && contributing.includes("npm test") && contributing.includes("npm run release:check") && license.includes("MIT License") && license.includes("Permission is hereby granted"), "README, CONTRIBUTING, and LICENSE must describe the focused Arena release without overstating static evidence"),
    check("obsolete_docs_absent", !obsoleteDocumentPresent, "obsolete docs and spec files must not ship"),
    check("dead_guard_absent", !await exists(root, "src/webmcp-guard.js") && !await exists(root, "test/webmcp-guard.test.js"), "the unused standalone WebMCP guard must not ship"),
  ];
  return {
    status: checks.every((item) => item.status === "passed") ? "passed" : "failed",
    checks,
  };
}

function check(id, passed, message) {
  return { id, status: passed ? "passed" : "failed", message };
}

async function exists(root, path) {
  try {
    await access(join(root, path));
    return true;
  } catch {
    return false;
  }
}

function text(root, path) {
  return readFile(join(root, path), "utf8").catch(() => "");
}
