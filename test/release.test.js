import assert from "node:assert/strict";
import test from "node:test";

import { runReleaseCheck } from "../src/release.js";

test("runReleaseCheck verifies package, action, docs, examples, and schema are release-ready", async () => {
  const result = await runReleaseCheck({ root: process.cwd() });
  assert.equal(result.status, "passed");
  assert.equal(result.checks.every((check) => check.status === "passed"), true);
  assert.ok(result.checks.find((check) => check.id === "package_publishable"));
  assert.ok(result.checks.find((check) => check.id === "package_bin"));
  assert.ok(result.checks.find((check) => check.id === "github_action_example"));
  assert.ok(result.checks.find((check) => check.id === "schema_docs"));
});
