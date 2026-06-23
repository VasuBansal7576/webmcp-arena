#!/usr/bin/env node
import { main } from "../src/cli.js";

const args = [];
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] === "--output") {
    const value = process.argv[++index];
    if (value === "json") args.push("--json");
    else args.push("--out", value);
  } else {
    args.push(process.argv[index]);
  }
}

main(["logs", ...args]).catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
