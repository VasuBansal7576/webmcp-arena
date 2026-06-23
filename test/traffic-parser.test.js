import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import assert from "node:assert/strict";
import test from "node:test";

const run = promisify(execFile);

test("agent-traffic-parser reuses logs command with --output json", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-traffic-parser-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const log = join(dir, "access.log");
  await writeFile(log, '203.0.113.7 - - [21/Jun/2026:12:00:00 +0000] "GET /pricing HTTP/1.1" 200 512 "-" "GPTBot/1.0"\n');

  const { stdout } = await run(process.execPath, ["./bin/agent-traffic-parser.js", log, "--output", "json"]);
  const report = JSON.parse(stdout);

  assert.equal(report.total_agent_requests, 1);
  assert.equal(report.bots.gptbot.agentRequests, 1);
});
