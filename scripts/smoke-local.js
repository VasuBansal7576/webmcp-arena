import { spawn } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { createServer } from "node:http";
import { join } from "node:path";

const outDir = ".tmp/smoke";
rmSync(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });
const repoDir = join(outDir, "repo");
await mkdir(repoDir, { recursive: true });
await run("git", ["init", "-b", "main"], { cwd: repoDir });
await run("git", ["config", "user.email", "smoke@example.com"], { cwd: repoDir });
await run("git", ["config", "user.name", "Agent Contract Smoke"], { cwd: repoDir });
await mkdir(join(repoDir, ".agent"), { recursive: true });
await mkdir(join(repoDir, ".github", "workflows"), { recursive: true });
writeFileSync(join(repoDir, "README.md"), "# Smoke repo\n");
writeFileSync(join(repoDir, "llms.txt"), "# Smoke repo\n");
writeFileSync(join(repoDir, "openapi.json"), JSON.stringify({ openapi: "3.1.0", info: { title: "Smoke", version: "1.0.0" }, paths: {} }, null, 2));
writeFileSync(join(repoDir, ".agent", "contract.json"), JSON.stringify({ version: "1.0.0" }, null, 2));
writeFileSync(join(repoDir, ".github", "workflows", "agent-contract.yml"), "steps:\n  - run: npx agent-contract gate https://example.com\n");
await run("git", ["add", "README.md", "llms.txt", "openapi.json", ".agent/contract.json", ".github/workflows/agent-contract.yml"], { cwd: repoDir });
await run("git", ["commit", "-m", "Initial commit"], { cwd: repoDir });

const server = createServer((request, response) => {
  const path = new URL(request.url, "http://127.0.0.1").pathname;
  const send = (status, body, type = "text/plain") => {
    response.writeHead(status, { "content-type": type });
    response.end(body);
  };
  if (path === "/") return send(200, html(), "text/html");
  if (path === "/pricing") return send(200, pricing(), "text/html");
  if (path === "/docs/quickstart") return send(200, quickstart(), "text/html");
  if (path === "/robots.txt") return send(200, "User-agent: *\nAllow: /\n");
  if (path === "/sitemap.xml") return send(200, "<urlset><url><loc>/</loc></url></urlset>", "application/xml");
  if (path === "/llms.txt") return send(200, "# Agent Contract OS\nAgent-readable product summary.\n");
  if (path === "/.agent/agent-skills/index.json") return send(200, JSON.stringify(agentSkills()), "application/json");
  if (path === "/openapi.json") return send(200, JSON.stringify(openapi()), "application/json");
  if (path === "/weak") return send(200, weakHtml(), "text/html");
  if (path === "/private") {
    if (request.headers.authorization !== "Bearer smoke-secret") return send(401, "auth required", "text/plain");
    return send(200, privateHtml(), "text/html");
  }
  if (path === "/weak-openapi.json") return send(200, JSON.stringify(weakOpenapi()), "application/json");
  if (path === "/responses" && request.method === "POST") return responsesApi(request, response);
  if (path === "/ok") return send(200, "ok");
  return send(404, "missing");
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const logPath = join(outDir, "access.log");
const authProfilePath = join(outDir, "auth-profile.json");
const mcpPath = join(outDir, "mcp.json");
writeFileSync(logPath, [
  `203.0.113.1 - - [21/Jun/2026:12:00:00 +0000] "GET /pricing HTTP/1.1" 200 120 "-" "ClaudeBot/1.0"`,
  `203.0.113.2 - - [21/Jun/2026:12:00:01 +0000] "GET /pricing HTTP/1.1" 200 110 "-" "GPTBot/1.0"`,
  `203.0.113.3 - - [21/Jun/2026:12:00:02 +0000] "GET /pricing HTTP/1.1" 200 100 "-" "ChatGPT-User/1.0"`,
].join("\n"));
writeFileSync(authProfilePath, JSON.stringify({
  name: "private-smoke",
  headers: { authorization: { env: "PRIVATE_TOKEN", prefix: "Bearer " } },
}, null, 2));
writeFileSync(mcpPath, JSON.stringify({
  name: "smoke-mcp",
  protocolVersion: "2025-06-18",
  tools: [
    { name: "list_contracts", description: "Read existing agent contracts" },
    { name: "deploy_contract", description: "Deploy an agent contract", requires_human_approval: true },
  ],
}, null, 2));

const result = await run(process.execPath, [
  "./bin/agent-contract.js",
  "gate",
  `${baseUrl}/`,
  "--logs", logPath,
  "--openapi", `${baseUrl}/openapi.json`,
  "--mcp", mcpPath,
  "--missions",
  "--browser-executable", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "--mode", "report",
  "--contract-dir", join(outDir, ".agent"),
  "--report", join(outDir, "report.html"),
  "--markdown", join(outDir, "report.md"),
  "--json-out", join(outDir, "report.json"),
  "--otel-file", join(outDir, "otel.json"),
]);
const privateScan = await run(process.execPath, [
  "./bin/agent-contract.js",
  "scan",
  `${baseUrl}/private`,
  "--auth-profile", authProfilePath,
  "--out", join(outDir, "private-scan.json"),
], { env: { ...process.env, PRIVATE_TOKEN: "smoke-secret" } });
const monitorFirst = await run(process.execPath, [
  "./bin/agent-contract.js",
  "monitor",
  `${baseUrl}/`,
  `${baseUrl}/pricing`,
  "--missions",
  "--browser-executable", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "--contract-dir", join(outDir, ".agent"),
  "--out", join(outDir, "monitor-first.json"),
]);
const monitorSecond = await run(process.execPath, [
  "./bin/agent-contract.js",
  "monitor",
  `${baseUrl}/`,
  `${baseUrl}/pricing`,
  "--missions",
  "--browser-executable", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "--contract-dir", join(outDir, ".agent"),
  "--out", join(outDir, "monitor-second.json"),
]);
const fixPack = await run(process.execPath, [
  "./bin/agent-contract.js",
  "fixpack",
  `${baseUrl}/weak`,
  "--openapi", `${baseUrl}/weak-openapi.json`,
  "--out", join(outDir, "fix-pack"),
  "--llm-explain",
  "--llm-endpoint", baseUrl,
  "--llm-api-key", "smoke-key",
  "--llm-model", "smoke-model",
]);
const prPrep = await run(process.execPath, [
  "./bin/agent-contract.js",
  "pr-prep",
  join(outDir, "fix-pack"),
  "--repo", repoDir,
  "--branch", "agent-contract/smoke-fix-pack",
  "--commit-message", "Add smoke agent contract fix pack",
]);
const policyAudit = await run(process.execPath, [
  "./bin/agent-contract.js",
  "policy-audit",
  join(outDir, ".agent", "contract.json"),
  "--out", join(outDir, ".agent", "audit", "policy"),
]);
const repoScan = await run(process.execPath, [
  "./bin/agent-contract.js",
  "repo-scan",
  repoDir,
  "--out", join(outDir, "repo-scan.json"),
]);
const releaseCheck = await run("npm", ["run", "release:check"]);

await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
if (result !== 0) process.exit(result);
if (privateScan !== 0) process.exit(privateScan);
if (monitorFirst !== 0) process.exit(monitorFirst);
if (monitorSecond !== 0) process.exit(monitorSecond);
if (fixPack !== 0) process.exit(fixPack);
if (prPrep !== 0) process.exit(prPrep);
if (policyAudit !== 0) process.exit(policyAudit);
if (repoScan !== 0) process.exit(repoScan);
if (releaseCheck !== 0) process.exit(releaseCheck);

for (const path of [
  join(outDir, ".agent", "contract.json"),
  join(outDir, ".agent", "missions.yml"),
  join(outDir, ".agent", "llms-full.txt"),
  join(outDir, ".agent", "agent-skills", "index.json"),
  join(outDir, ".agent", "policy-pack.enterprise.json"),
  join(outDir, "report.html"),
  join(outDir, "report.md"),
  join(outDir, "report.json"),
  join(outDir, "otel.json"),
  join(outDir, "private-scan.json"),
  join(outDir, "monitor-first.json"),
  join(outDir, "monitor-second.json"),
  join(outDir, "repo-scan.json"),
  join(outDir, "fix-pack", "README.md"),
  join(outDir, "fix-pack", "schema-org.jsonld"),
  join(outDir, "fix-pack", "openapi-patches.json"),
  join(outDir, "fix-pack", "problem-details-example.json"),
  join(outDir, "fix-pack", "llm-explanation.md"),
  join(repoDir, ".agent", "audit", "pr-prep.json"),
  join(repoDir, ".agent", "fix-pack", "llm-explanation.md"),
  join(repoDir, ".agent", "openapi-patches.json"),
  join(outDir, ".agent", "audit", "policy", "policy-audit.json"),
  join(outDir, ".agent", "audit", "policy", "compliance-report.md"),
]) {
  if (!existsSync(path)) throw new Error(`Missing smoke artifact: ${path}`);
}

const contract = JSON.parse(readFileSync(join(outDir, ".agent", "contract.json"), "utf8"));
const skills = JSON.parse(readFileSync(join(outDir, ".agent", "agent-skills", "index.json"), "utf8"));
if (contract.passive_traffic.total_agent_requests !== 3) throw new Error("Passive traffic was not included in contract");
if (contract.missions.tested !== 3 || contract.missions.failed !== 0) throw new Error("Synthetic missions did not pass in smoke");
if (!contract.missions.results.every((mission) => mission.screenshot_path && existsSync(mission.screenshot_path))) throw new Error("Synthetic mission screenshots were not captured");
if (contract.surface.mcp.tool_count !== 2 || contract.surface.mcp.unapproved_dangerous_tool_count !== 0) throw new Error("MCP manifest audit was not included in contract");
if (skills.skills.length !== 3 || !skills.skills.every((skill) => skill.evidence.status === "passed")) throw new Error("Agent skills index did not include passed mission evidence");
const firstMonitor = JSON.parse(readFileSync(join(outDir, "monitor-first.json"), "utf8"));
const secondMonitor = JSON.parse(readFileSync(join(outDir, "monitor-second.json"), "utf8"));
const repoScanJson = JSON.parse(readFileSync(join(outDir, "repo-scan.json"), "utf8"));
const privateScanJson = JSON.parse(readFileSync(join(outDir, "private-scan.json"), "utf8"));
if (firstMonitor.changed.length !== 2 || firstMonitor.missionReport.tested !== 3) throw new Error("Monitor first run did not detect changed pages");
if (secondMonitor.changed.length !== 0 || secondMonitor.missionReport !== null) throw new Error("Monitor second run did not skip unchanged pages");
if (repoScanJson.readiness.score !== 100) throw new Error("Repo scan did not verify repository readiness");
if (privateScanJson.auth_profile.name !== "private-smoke") throw new Error("Private auth scan did not record redacted profile");
if (JSON.stringify(privateScanJson).includes("smoke-secret")) throw new Error("Private auth scan leaked secret");
if (readFileSync(join(repoDir, ".git", "HEAD"), "utf8").trim() !== "ref: refs/heads/agent-contract/smoke-fix-pack") {
  throw new Error("PR prep did not leave repo on fix-pack branch");
}
console.log(`smoke: wrote ${outDir}`);

function html() {
  return `<!doctype html>
<html>
  <head>
    <title>Agent Contract OS</title>
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Agent Contract OS"}</script>
  </head>
  <body>
    <main>
      <h1>Agent Contract OS</h1>
      <p>Agent Contract OS creates machine-readable contracts for products so autonomous agents can discover docs, APIs, policies, and operational constraints without brittle browser guessing. It emits evidence reports and CI gate signals for engineering teams.</p>
      <a href="/pricing">Pricing</a>
      <a href="/docs/quickstart">API quickstart</a>
      <a href="/ok">OK</a>
    </main>
  </body>
</html>`;
}

function pricing() {
  return `<!doctype html>
<html><body>
  <h1>Pricing</h1>
  <p>Solo Free</p>
  <p>Startup $49 per repo</p>
  <p>Enterprise $30000 per year</p>
</body></html>`;
}

function quickstart() {
  return `<!doctype html>
<html><body>
  <h1>API Quickstart</h1>
  <p>Make the first request with GET /v1/contracts.</p>
  <code>curl https://api.example.test/v1/contracts</code>
</body></html>`;
}

function weakHtml() {
  return `<!doctype html>
<html><body>
  <h1>Weak Agent Surface</h1>
  <p>Agent Contract OS creates contracts for autonomous agents and exports fix packs.</p>
</body></html>`;
}

function privateHtml() {
  return `<!doctype html>
<html><head>
  <title>Private Agent Contract OS</title>
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication"}</script>
</head><body>
  <h1>Private Agent Contract OS</h1>
  <p>Private authenticated surface for enterprise runner verification with stable server-rendered content.</p>
</body></html>`;
}

function openapi() {
  return {
    openapi: "3.1.0",
    info: { title: "Agent Contract API", version: "1.0.0" },
    security: [{ bearerAuth: [] }],
    components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer" } } },
    paths: {
      "/contracts": {
        get: {
          summary: "List contracts",
          description: "Returns contracts.",
          responses: {
            200: { description: "OK", content: { "application/json": { examples: { ok: { value: [] } } } } },
            401: { description: "Unauthorized" },
          },
        },
      },
    },
  };
}

function weakOpenapi() {
  return {
    openapi: "3.1.0",
    info: { title: "Weak API", version: "1.0.0" },
    paths: {
      "/contracts": {
        get: {
          responses: {
            200: { description: "OK" },
          },
        },
      },
    },
  };
}

function agentSkills() {
  return {
    version: "1.0.0",
    skills: [
      { id: "understand_company", description: "Summarize Agent Contract OS" },
      { id: "find_pricing", description: "Find pricing tiers" },
    ],
  };
}

function responsesApi(request, response) {
  let body = "";
  request.on("data", (chunk) => { body += chunk; });
  request.on("end", () => {
    const parsed = JSON.parse(body);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      id: "resp_smoke",
      output_text: `Review ${parsed.model} fix pack files in order: README, JSON-LD, OpenAPI patches. Do not auto-commit.`,
    }));
  });
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", ...options });
    child.on("error", reject);
    child.on("close", resolve);
  });
}
