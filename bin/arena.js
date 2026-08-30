#!/usr/bin/env node
import { runArenaCli } from "../src/arena-cli.js";

const result = await runArenaCli(process.argv.slice(2));

if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
