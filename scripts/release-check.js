#!/usr/bin/env node
import { runReleaseCheck } from "../src/release.js";

const result = await runReleaseCheck();
for (const check of result.checks) {
  console.log(`${check.status.toUpperCase()} ${check.id} - ${check.message}`);
}
if (result.status !== "passed") process.exitCode = 1;
