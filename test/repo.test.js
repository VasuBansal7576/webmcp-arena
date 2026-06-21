import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { scanRepo } from "../src/repo.js";

test("scanRepo audits a local checkout for agent contract readiness", async (t) => {
  const repo = await mkdtemp(join(tmpdir(), "agent-contract-repo-"));
  t.after(() => import("node:fs/promises").then(({ rm }) => rm(repo, { recursive: true, force: true })));

  await mkdir(join(repo, ".agent"), { recursive: true });
  await mkdir(join(repo, ".github", "workflows"), { recursive: true });
  await writeFile(join(repo, "README.md"), "# Product\n");
  await writeFile(join(repo, "llms.txt"), "# Product\n");
  await writeFile(join(repo, "openapi.json"), JSON.stringify({ openapi: "3.1.0" }));
  await writeFile(join(repo, ".agent", "contract.json"), JSON.stringify({ version: "1.0.0" }));
  await writeFile(join(repo, ".github", "workflows", "agent-contract.yml"), "steps:\n  - run: npx agent-contract gate\n");

  const report = await scanRepo(repo);

  assert.equal(report.source.type, "repo");
  assert.equal(report.readiness.score, 100);
  assert.equal(report.checks.every((check) => check.pass), true);
});
