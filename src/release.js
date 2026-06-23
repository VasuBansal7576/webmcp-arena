import { access, readFile } from "node:fs/promises";
import { join } from "node:path";

export async function runReleaseCheck({ root = process.cwd() } = {}) {
  const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const action = await readFile(join(root, "action.yml"), "utf8").catch(() => "");
  const readme = await readFile(join(root, "README.md"), "utf8").catch(() => "");
  const schema = JSON.parse(await readFile(join(root, "schema", "contract.schema.json"), "utf8"));
  const checks = [
    check("package_publishable", pkg.private !== true && pkg.license && pkg.license !== "UNLICENSED", "package must be publishable and licensed"),
    check("package_bin", pkg.bin?.["agent-contract"] === "./bin/agent-contract.js" && pkg.bin?.["agent-traffic-parser"] === "./bin/agent-traffic-parser.js" && await exists(root, "bin/agent-contract.js") && await exists(root, "bin/agent-traffic-parser.js"), "package bin must point to CLIs"),
    check("package_files", ["README.md", "action.yml", "bin/", "schema/", "scripts/", "spec/", "src/", "docs/", "examples/"].every((item) => pkg.files?.includes(item)), "package files must include runtime docs/examples/spec"),
    check("release_script", pkg.scripts?.["release:check"] === "node scripts/release-check.js", "release check script must be wired"),
    check("solo_script", pkg.scripts?.solo === "node scripts/solo-server.js" && await exists(root, "scripts/solo-server.js"), "solo web shell script must be wired"),
    check("action_uses_cli", action.includes("bin/agent-contract.js") && action.includes("auth-profile") && action.includes("gh pr comment"), "composite action must call CLI, expose auth profile, and support PR comments"),
    check("github_action_example", await exists(root, "examples/github-action.yml"), "example GitHub workflow must exist"),
    check("schema_docs", await exists(root, "docs/agent-contract-schema.md") && await exists(root, "spec/README.md") && schema.$id === "https://agentcontract.dev/schema/v1", "schema docs/spec and schema id must exist"),
    check("readme_current", readme.includes("LLM fix explanations are opt-in") && readme.includes("agent-skills/index.json") && !readme.includes("Skipped: LLM-based ambiguous fixes"), "README must match implemented features"),
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
