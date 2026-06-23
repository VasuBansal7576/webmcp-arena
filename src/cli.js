import { analyzeLogs } from "./logs.js";
import { scanUrl } from "./scanner.js";
import { writeAgentFolder } from "./contract.js";
import { buildReport, renderHtml, renderMarkdown } from "./report.js";
import { buildOtlpTrace, sendTelemetry, writeTelemetry } from "./telemetry.js";
import { runSyntheticMissions } from "./missions.js";
import { runMonitor } from "./monitor.js";
import { writeFixPack } from "./fixpack.js";
import { writeLlmFixExplanation } from "./llmfix.js";
import { prepareFixPackPr } from "./pr.js";
import { ENTERPRISE_POLICY_PACK, writePolicyAudit } from "./policy.js";
import { loadAuthProfile } from "./auth.js";
import { scanRepo } from "./repo.js";
import { number, readText, writeJson, writeText } from "./util.js";

export async function main(argv) {
  const [command, ...rest] = argv;
  if (!command || command === "help" || command === "--help") return help();
  if (command === "logs") return logsCommand(rest);
  if (command === "scan") return scanCommand(rest);
  if (command === "contract") return contractCommand(rest);
  if (command === "gate") return gateCommand(rest);
  if (command === "monitor") return monitorCommand(rest);
  if (command === "fixpack") return fixPackCommand(rest);
  if (command === "pr-prep") return prPrepCommand(rest);
  if (command === "policy-audit") return policyAuditCommand(rest);
  if (command === "repo-scan") return repoScanCommand(rest);
  throw new Error(`Unknown command: ${command}\n\n${usage()}`);
}

async function repoScanCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const report = await scanRepo(positional[0] || flags.repo || process.cwd());
  await output(report, flags);
}

async function policyAuditCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const contractPath = positional[0] || flags.contract || ".agent/contract.json";
  const policy = flags.policy ? JSON.parse(await readText(flags.policy)) : ENTERPRISE_POLICY_PACK;
  const contract = JSON.parse(await readText(contractPath));
  const result = await writePolicyAudit(flags.out || ".agent/audit/policy", contract, policy);
  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`agent-contract policy-audit: ${result.status} controls=${result.controls.length} out=${result.outDir}`);
  if (flags.failOnViolation && result.status !== "passed") process.exitCode = 1;
}

async function prPrepCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const fixPackDir = positional[0] || flags.fixPack;
  if (!fixPackDir) throw new Error(`pr-prep requires a fix-pack directory\n\n${usage()}`);
  const result = await prepareFixPackPr({
    repoDir: flags.repo || process.cwd(),
    fixPackDir,
    branch: flags.branch,
    commitMessage: flags.commitMessage,
    dryRun: Boolean(flags.dryRun),
    allowDirty: Boolean(flags.allowDirty),
    createPr: Boolean(flags.createPr),
    confirmRemote: Boolean(flags.confirmRemote),
    title: flags.title,
    body: flags.body,
  });
  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`agent-contract pr-prep: ${result.dryRun ? "dry-run" : "committed"} branch=${result.branch} files=${result.files.length}`);
}

async function fixPackCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const url = positional[0] || flags.url;
  if (!url) throw new Error(`fixpack requires a URL\n\n${usage()}`);
  const options = await scanOptions(flags);
  const scan = await scanUrl(url, options);
  const logReport = flags.logs ? analyzeLogs(await readText(flags.logs), { emptyHtmlBytes: number(flags.emptyHtmlBytes, 800) }) : null;
  const manifest = await writeFixPack(flags.out || "fix-pack", { scan, logReport });
  if (flags.llmExplain) {
    const findings = scan.checks.filter((item) => !item.pass);
    const explanation = await writeLlmFixExplanation(`${manifest.outDir.replace(/\/$/, "")}/llm-explanation.md`, {
      findings,
      fixPackFiles: manifest.files,
    }, {
      endpoint: flags.llmEndpoint,
      apiKey: flags.llmApiKey,
      model: flags.llmModel,
      maxOutputTokens: number(flags.llmMaxOutputTokens, 900),
    });
    manifest.files.push("llm-explanation.md");
    manifest.llm = { model: explanation.model, response_id: explanation.response_id };
  }
  if (flags.json) console.log(JSON.stringify(manifest, null, 2));
  else console.log(`agent-contract fixpack: wrote ${manifest.files.length} files to ${manifest.outDir}`);
}

async function monitorCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const urls = positional.length ? positional : String(flags.urls || "").split(",").filter(Boolean);
  if (!urls.length) throw new Error(`monitor requires at least one URL\n\n${usage()}`);
  const options = await scanOptions(flags);
  const result = await runMonitor({
    urls,
    statePath: flags.state || `${(flags.contractDir || ".agent").replace(/\/$/, "")}/state/pages.json`,
    contractDir: flags.contractDir || ".agent",
    browserExecutablePath: flags.browserExecutable || flags.browser,
    auth: options.auth,
    missions: Boolean(flags.missions),
    timeoutMs: number(flags.timeoutMs, 15000),
    scanOptions: options,
  });
  if (flags.out) await writeJson(flags.out, result);
  if (flags.json) console.log(JSON.stringify(result, null, 2));
  else console.log(`agent-contract monitor: checked=${result.checked.length} changed=${result.changed.length} unchanged=${result.unchanged.length} missions=${result.missionReport?.tested || 0}`);
}

async function logsCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const file = positional[0] || flags.file;
  if (!file) throw new Error(`logs requires a log file\n\n${usage()}`);
  const report = analyzeLogs(await readText(file), { emptyHtmlBytes: number(flags.emptyHtmlBytes, 800) });
  await output(report, flags);
}

async function scanCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const url = positional[0] || flags.url;
  if (!url) throw new Error(`scan requires a URL\n\n${usage()}`);
  const scan = await scanUrl(url, await scanOptions(flags));
  await output(scan, flags);
}

async function contractCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const url = positional[0] || flags.url;
  if (!url) throw new Error(`contract requires --url or positional URL\n\n${usage()}`);
  const options = await scanOptions(flags);
  const scan = await scanUrl(url, options);
  const logReport = flags.logs ? analyzeLogs(await readText(flags.logs), { emptyHtmlBytes: number(flags.emptyHtmlBytes, 800) }) : null;
  const outDir = flags.out || ".agent";
  const missionReport = flags.missions ? await runSyntheticMissions(url, missionOptions(flags, scan, outDir, options.auth)) : null;
  const contract = await writeAgentFolder(outDir, { scan, logReport, missionReport });
  if (flags.json) console.log(JSON.stringify({ outDir, contract }, null, 2));
  else console.log(`agent-contract contract: wrote ${outDir}`);
}

async function gateCommand(argv) {
  const { positional, flags } = parseArgs(argv);
  const url = positional[0] || flags.url;
  if (!url) throw new Error(`gate requires --url or positional URL\n\n${usage()}`);

  const mode = flags.mode || "report";
  if (!["report", "warning", "blocking"].includes(mode)) throw new Error("--mode must be report, warning, or blocking");

  const options = await scanOptions(flags);
  const scan = await scanUrl(url, options);
  const logReport = flags.logs ? analyzeLogs(await readText(flags.logs), { emptyHtmlBytes: number(flags.emptyHtmlBytes, 800) }) : null;
  const contractDir = flags.contractDir || ".agent";
  const missionReport = flags.missions ? await runSyntheticMissions(url, missionOptions(flags, scan, contractDir, options.auth)) : null;
  await writeAgentFolder(contractDir, { scan, logReport, missionReport });

  const report = buildReport({ scan, logReport, missionReport, contractDir });
  if (flags.report) await writeText(flags.report, renderHtml(report));
  if (flags.markdown) await writeText(flags.markdown, renderMarkdown(report));
  if (flags.jsonOut) await writeJson(flags.jsonOut, report);

  const status = gateStatus(scan, logReport, missionReport, number(flags.minScore, 70));
  const telemetry = buildOtlpTrace({ command: "gate", scan, logReport, missionReport, status: status.ok ? "ok" : "failed" });
  if (flags.otelFile) await writeTelemetry(flags.otelFile, telemetry);
  if (flags.otelEndpoint) await sendTelemetry(flags.otelEndpoint, telemetry);

  const verdict = mode === "report" ? "REPORT" : status.ok ? "PASS" : mode === "warning" ? "WARN" : "FAIL";
  const line = `agent-contract gate: ${verdict} score=${scan.readiness.score} findings=${status.findingCount} mode=${mode} contract=${contractDir}`;
  if (flags.json) console.log(JSON.stringify({ ...status, mode, score: scan.readiness.score, report }, null, 2));
  else console.log(line);

  if (mode === "blocking" && !status.ok) process.exitCode = 1;
}

function gateStatus(scan, logReport, missionReport, minScore) {
  const critical = [
    ...scan.checks.filter((item) => !item.pass && item.severity === "critical").map((item) => item.message),
    ...(logReport?.findings || []).filter((item) => item.severity === "critical").map((item) => item.message),
  ];
  const missionFailures = (missionReport?.results || []).filter((item) => item.status !== "passed").map((item) => item.summary);
  const scoreOk = scan.readiness.score >= minScore;
  return {
    ok: scoreOk && critical.length === 0 && missionFailures.length === 0,
    minScore,
    findingCount: scan.checks.filter((item) => !item.pass).length + (logReport?.findings?.length || 0) + missionFailures.length,
    critical,
    missionFailures,
    reason: scoreOk ? critical[0] || missionFailures[0] || null : `score ${scan.readiness.score} below ${minScore}`,
  };
}

async function scanOptions(flags) {
  return {
    openapi: flags.openapi,
    mcp: flags.mcp,
    agentSkills: flags.agentSkills,
    linkLimit: number(flags.linkLimit, 12),
    timeoutMs: number(flags.timeoutMs, 15000),
    auth: flags.authProfile ? await loadAuthProfile(flags.authProfile) : null,
  };
}

function missionOptions(flags, scan, contractDir, auth) {
  const normalizedContractDir = contractDir.replace(/\/$/, "");
  return {
    browserExecutablePath: flags.browserExecutable || flags.browser,
    cacheDir: flags.missionCache || `${normalizedContractDir}/cache/missions`,
    evidenceDir: flags.missionEvidence || `${normalizedContractDir}/evidence/mission-artifacts`,
    contentHash: scan.source.content_hash,
    missionIds: flags.missionIds ? String(flags.missionIds).split(",").map((item) => item.trim()).filter(Boolean) : undefined,
    auth,
  };
}

async function output(value, flags) {
  if (flags.out) await writeJson(flags.out, value);
  if (flags.json || !flags.out) console.log(JSON.stringify(value, null, 2));
}

function parseArgs(argv) {
  const flags = {};
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const [rawKey, inline] = arg.slice(2).split("=");
    const key = rawKey.replace(/-([a-z])/g, (_, char) => char.toUpperCase());
    if (inline !== undefined) flags[key] = inline;
    else if (argv[index + 1] && !argv[index + 1].startsWith("--")) flags[key] = argv[++index];
    else flags[key] = true;
  }
  return { positional, flags };
}

function help() {
  console.log(usage());
}

function usage() {
  return `Usage:
  agent-contract logs <access.log> [--json] [--out logs.json]
  agent-contract scan <url> [--openapi openapi.json] [--mcp mcp.json] [--agent-skills index.json] [--auth-profile auth.json] [--json] [--out scan.json]
  agent-contract contract <url> [--logs access.log] [--mcp mcp.json] [--agent-skills index.json] [--auth-profile auth.json] [--missions --mission-ids find_pricing,find_refund_policy --browser-executable /path/to/chrome] [--out .agent]
  agent-contract gate <url> [--logs access.log] [--mcp mcp.json] [--agent-skills index.json] [--auth-profile auth.json] [--missions --mission-ids find_pricing,find_refund_policy --browser-executable /path/to/chrome] [--mode report|warning|blocking] [--min-score 70] [--report report.html] [--otel-file trace.json]
  agent-contract monitor <url...> [--auth-profile auth.json] [--missions --browser-executable /path/to/chrome] [--state .agent/state/pages.json] [--json]
  agent-contract fixpack <url> [--openapi openapi.json] [--auth-profile auth.json] [--out fix-pack] [--llm-explain --llm-model model]
  agent-contract pr-prep <fix-pack-dir> [--repo /path/to/repo] [--dry-run] [--branch agent-contract/fix-pack]
  agent-contract policy-audit [.agent/contract.json] [--policy policy.json] [--out .agent/audit/policy] [--fail-on-violation]
  agent-contract repo-scan [/path/to/repo] [--json] [--out repo-scan.json]
`;
}
