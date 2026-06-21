import { execFile } from "node:child_process";
import { copyFile, mkdir, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { nowIso, writeJson } from "./util.js";

const run = promisify(execFile);

export async function prepareFixPackPr(options = {}) {
  const repoDir = options.repoDir || process.cwd();
  const fixPackDir = options.fixPackDir;
  if (!fixPackDir) throw new Error("prepareFixPackPr requires fixPackDir.");
  await git(repoDir, "rev-parse", "--show-toplevel");

  const files = await mappedFiles(fixPackDir);
  if (options.dryRun) return { dryRun: true, repoDir, branch: options.branch || "agent-contract/fix-pack", files };

  if (!options.allowDirty) {
    const status = await git(repoDir, "status", "--porcelain");
    if (status) throw new Error("Refusing to apply fix pack to a dirty git worktree. Commit/stash changes or pass --allow-dirty.");
  }

  const branch = options.branch || `agent-contract/fix-pack-${Date.now()}`;
  await git(repoDir, "checkout", "-B", branch);
  for (const file of files) {
    const target = join(repoDir, file.target);
    await mkdir(dirname(target), { recursive: true });
    await copyFile(file.source, target);
  }
  await git(repoDir, "add", ...files.map((file) => file.target));
  const commitMessage = options.commitMessage || "Add agent contract fix pack";
  await git(repoDir, "commit", "-m", commitMessage);
  const commit = await git(repoDir, "rev-parse", "HEAD");
  const audit = {
    generated_at: nowIso(),
    branch,
    commit,
    commitMessage,
    files,
    remote_pr: null,
  };

  if (options.createPr) {
    audit.remote_pr = await createRemotePr(repoDir, branch, options);
  }

  const auditPath = ".agent/audit/pr-prep.json";
  await writeJson(join(repoDir, auditPath), audit);
  await git(repoDir, "add", auditPath);
  await git(repoDir, "commit", "-m", "Record agent contract PR prep audit");

  return { dryRun: false, repoDir, branch, commit, audit_path: auditPath, files, remote_pr: audit.remote_pr };
}

async function mappedFiles(fixPackDir) {
  const names = await readdir(fixPackDir);
  const files = [];
  for (const name of names.sort()) {
    const target = targetPath(name);
    if (target) files.push({ source: join(fixPackDir, name), target });
  }
  return files;
}

function targetPath(name) {
  if (name === "llms.txt") return "llms.txt";
  if (name === "README.md") return ".agent/fix-pack/README.md";
  if (name === "schema-org.jsonld") return ".agent/fix-pack/schema-org.jsonld";
  if (name === "openapi-patches.json") return ".agent/openapi-patches.json";
  if (name === "problem-details-example.json") return ".agent/problem-details-example.json";
  if (name === "llm-explanation.md") return ".agent/fix-pack/llm-explanation.md";
  return null;
}

async function createRemotePr(repoDir, branch, options) {
  if (!options.confirmRemote) throw new Error("Remote PR creation requires --confirm-remote.");
  const title = options.title || "Add agent contract fix pack";
  const body = options.body || "Reviewable Agent Contract OS fix pack. Generated locally; verify before merge.";
  const { stdout } = await run("gh", ["pr", "create", "--title", title, "--body", body, "--head", branch], { cwd: repoDir });
  return stdout.trim();
}

async function git(cwd, ...args) {
  const { stdout } = await run("git", args, { cwd });
  return stdout.trim();
}
