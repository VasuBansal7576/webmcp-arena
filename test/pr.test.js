import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { prepareFixPackPr } from "../src/pr.js";

test("prepareFixPackPr dry-run reports mapped files without touching git", async (t) => {
  const { root, repo, fixPack } = await fixture(t);
  const result = await prepareFixPackPr({ repoDir: repo, fixPackDir: fixPack, branch: "agent-contract/fix-pack", dryRun: true });

  assert.equal(result.dryRun, true);
  assert.equal(git(repo, "branch", "--show-current"), "main");
  assert.equal(git(repo, "status", "--porcelain"), "");
  assert.ok(result.files.some((file) => file.target === "llms.txt"));
  assert.ok(result.files.some((file) => file.target === ".agent/fix-pack/schema-org.jsonld"));
  assert.equal(existsSync(join(root, "audit")), false);
});

test("prepareFixPackPr creates a local branch, commit, mapped files, and audit evidence", async (t) => {
  const { repo, fixPack } = await fixture(t);
  const result = await prepareFixPackPr({
    repoDir: repo,
    fixPackDir: fixPack,
    branch: "agent-contract/fix-pack",
    commitMessage: "Add agent contract fix pack",
  });

  assert.equal(result.dryRun, false);
  assert.equal(result.branch, "agent-contract/fix-pack");
  assert.match(result.commit, /^[0-9a-f]{40}$/);
  assert.equal(git(repo, "branch", "--show-current"), "agent-contract/fix-pack");
  assert.equal(await readFile(join(repo, "llms.txt"), "utf8"), "# Agent guidance\n");
  assert.equal(await readFile(join(repo, ".agent", "fix-pack", "schema-org.jsonld"), "utf8"), "{}\n");
  assert.ok(result.audit_path.endsWith(".agent/audit/pr-prep.json"));
  assert.match(await readFile(join(repo, ".agent", "audit", "pr-prep.json"), "utf8"), /Add agent contract fix pack/);
});

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "agent-contract-pr-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = join(root, "repo");
  const fixPack = join(root, "fix-pack");
  await mkdir(repo, { recursive: true });
  await mkdir(fixPack, { recursive: true });
  git(repo, "init", "-b", "main");
  git(repo, "config", "user.email", "test@example.com");
  git(repo, "config", "user.name", "Agent Contract Test");
  writeFileSync(join(repo, "README.md"), "# App\n");
  git(repo, "add", "README.md");
  git(repo, "commit", "-m", "Initial commit");

  writeFileSync(join(fixPack, "README.md"), "# Fix Pack\n");
  writeFileSync(join(fixPack, "llms.txt"), "# Agent guidance\n");
  writeFileSync(join(fixPack, "schema-org.jsonld"), "{}\n");
  writeFileSync(join(fixPack, "openapi-patches.json"), "{\"patches\":[]}\n");
  writeFileSync(join(fixPack, "problem-details-example.json"), "{}\n");
  return { root, repo, fixPack };
}

function git(cwd, ...args) {
  return execFileSync("git", args, { cwd, encoding: "utf8" }).trim();
}
