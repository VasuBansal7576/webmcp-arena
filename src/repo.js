import { access, readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { clamp, nowIso } from "./util.js";

export async function scanRepo(input = process.cwd()) {
  const root = resolve(input);
  const files = await listFiles(root);
  const workflowFiles = files.filter((file) => file.startsWith(".github/workflows/") && /\.ya?ml$/i.test(file));
  const workflowUsesGate = await anyFileIncludes(root, workflowFiles, ["agent-contract", "gate"]);
  const checks = [
    check("repo_readme", await exists(join(root, "README.md")), "README.md present", "medium"),
    check("repo_agent_contract", await exists(join(root, ".agent", "contract.json")), ".agent/contract.json present", "high"),
    check("repo_llms_txt", await exists(join(root, "llms.txt")) || await exists(join(root, ".agent", "llms.txt")), "llms.txt present", "medium"),
    check("repo_openapi", files.some((file) => /(^|\/)openapi\.(json|ya?ml)$/i.test(file)), "OpenAPI file present", "low"),
    check("repo_ci_gate", workflowUsesGate, "GitHub workflow runs agent-contract gate", "high"),
  ];
  const score = scoreChecks(checks);
  return {
    generated_at: nowIso(),
    source: { type: "repo", path: root },
    files: {
      total: files.length,
      workflows: workflowFiles,
    },
    checks,
    readiness: {
      score,
      level: score >= 85 ? "gold" : score >= 70 ? "silver" : score >= 50 ? "bronze" : "blocked",
      critical_gaps: checks.filter((item) => !item.pass && item.severity === "critical").map((item) => item.message),
    },
  };
}

async function listFiles(root, prefix = "") {
  const entries = await readdir(join(root, prefix), { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if ([".git", "node_modules", ".tmp", "dist", "build"].includes(entry.name)) continue;
      files.push(...await listFiles(root, relative));
    } else if (entry.isFile()) {
      files.push(relative);
    }
  }
  return files;
}

async function anyFileIncludes(root, files, needles) {
  for (const file of files) {
    const text = await readFile(join(root, file), "utf8").catch(() => "");
    if (needles.every((needle) => text.includes(needle))) return true;
  }
  return false;
}

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function check(id, pass, message, severity) {
  return { id, pass: Boolean(pass), severity, message };
}

function scoreChecks(checks) {
  const weight = { critical: 30, high: 15, medium: 8, low: 3 };
  const lost = checks.filter((item) => !item.pass).reduce((sum, item) => sum + (weight[item.severity] || 5), 0);
  return clamp(100 - lost, 0, 100);
}
