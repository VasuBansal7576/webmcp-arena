import { join } from "node:path";
import { nowIso, writeJson, writeText } from "./util.js";
import { ENTERPRISE_POLICY_PACK } from "./policy.js";

export function buildContract({ scan, logReport, missionReport }) {
  const bots = Object.fromEntries(Object.entries(logReport?.bots || {}).map(([bot, stats]) => [
    bot,
    {
      requests: stats.agentRequests,
      empty_html_rate: round(stats.emptyHtmlRate),
      auth_wall_rate: round(stats.authWallRate),
      rate_limit_rate: round(stats.rateLimitRate),
    },
  ]));

  return {
    $schema: "https://agentcontract.dev/schema/v1",
    version: "1.0.0",
    awi_compliance: "1.0",
    generated_at: nowIso(),
    source: {
      type: "website",
      url: scan.source.url,
      content_hash: scan.source.content_hash,
      ingested_at: scan.generated_at,
    },
    auth_profile: scan.auth_profile || null,
    passive_traffic: logReport ? {
      total_agent_requests: logReport.total_agent_requests,
      bots,
    } : null,
    surface: {
      website: {
        url: scan.source.url,
        has_sitemap: scan.sitemap.ok,
        has_robots_txt: scan.robots.ok,
        has_llms_txt: scan.llms.ok,
        render_mode: scan.page.looksJsOnly ? "client_side_or_empty_html" : "server_readable_html",
        agent_blockers: scan.checks.filter((item) => !item.pass).map((item) => item.id),
      },
      api: scan.openapi?.ok ? {
        openapi_url: scan.openapi.url,
        quality_score: Math.round(((scan.openapi.described_operation_rate + scan.openapi.example_rate) / 2) * 100),
        has_error_examples: scan.openapi.has_error_responses,
        has_rate_limit_docs: JSON.stringify(scan.openapi).toLowerCase().includes("rate"),
        auth_methods: scan.openapi.has_security ? ["documented"] : [],
      } : null,
      mcp: scan.mcp ? {
        source: scan.mcp.source,
        discovered: scan.mcp.discovered,
        name: scan.mcp.name || "",
        tool_count: scan.mcp.tool_count || 0,
        spec_version: scan.mcp.spec_version || "",
        spec_version_compliant: scan.mcp.spec_version_compliant !== false,
        tool_description_hash: scan.mcp.tool_description_hash || "",
        dangerous_tool_count: scan.mcp.dangerous_tools?.length || 0,
        unapproved_dangerous_tool_count: scan.mcp.unapproved_dangerous_tools?.length || 0,
        dangerous_tools: (scan.mcp.dangerous_tools || []).map((tool) => ({
          name: tool.name,
          categories: tool.categories,
          requires_approval: tool.requires_approval,
        })),
      } : { source: null, discovered: false, spec_version_compliant: true },
      agent_skills: scan.agent_skills?.discovered ? {
        source: scan.agent_skills.source,
        discovered: true,
        skill_count: scan.agent_skills.skill_count,
      } : { source: scan.agent_skills?.source || null, discovered: false, skill_count: 0 },
    },
    readiness: scan.readiness,
    cup: cup(scan, missionReport),
    missions: missionReport || {
      tested: 0,
      passed: 0,
      failed: 0,
      results: [],
      status: "not_run_static_gate_only",
    },
    telemetry: {
      otel_schema: "gen_ai.1.42.0",
    },
  };
}

export async function writeAgentFolder(outDir, { scan, logReport, missionReport }) {
  const contract = buildContract({ scan, logReport, missionReport });
  const stamp = compactDate(contract.generated_at);
  await writeJson(join(outDir, "contract.json"), contract);
  await writeText(join(outDir, "missions.yml"), missionsYml());
  await writeText(join(outDir, "policies.yml"), policiesYml());
  await writeJson(join(outDir, "policy-pack.enterprise.json"), ENTERPRISE_POLICY_PACK);
  await writeText(join(outDir, "llms.txt"), llmsTxt(scan, contract));
  await writeText(join(outDir, "llms-full.txt"), llmsFullTxt(scan, logReport, missionReport));
  await writeJson(join(outDir, "agent-skills", "index.json"), agentSkillsIndex(scan, missionReport));
  await writeJson(join(outDir, "openapi-patches.json"), openApiPatches(scan));
  await writeJson(join(outDir, "evidence", stamp, "scan.json"), scan);
  if (logReport) await writeJson(join(outDir, "evidence", stamp, "passive-traffic.json"), logReport);
  if (missionReport) await writeJson(join(outDir, "evidence", stamp, "missions.json"), missionReport);
  return contract;
}

function missionsYml() {
  return `version: "1.0.0"

missions:
  - id: understand_company
    description: "Understand what this company does from its homepage"
    expected_outcome: "A clear summary of the company's primary product and value proposition"
    max_steps: 10
    max_tokens: 2000
    token_strategy: hybrid

  - id: find_pricing
    description: "Find the pricing page and extract the pricing tiers"
    expected_outcome: "A structured list of pricing tiers with features and costs"
    max_steps: 15
    max_tokens: 1500
    token_strategy: prune4web
    critical: true

  - id: find_api_quickstart
    description: "Find the API quickstart and identify the first request to make"
    expected_outcome: "The endpoint, method, and minimal example for the first API call"
    max_steps: 12
    max_tokens: 1200
    token_strategy: a11y_tree
    critical: true

  - id: create_first_api_request
    description: "Create the first API request from the docs alone"
    expected_outcome: "The method, endpoint, and minimal first request"
    max_steps: 12
    max_tokens: 800
    token_strategy: openapi_or_a11y_tree

  - id: find_refund_policy
    description: "Find the refund or cancellation policy"
    expected_outcome: "A browser-readable refund, return, or cancellation policy summary"
    max_steps: 12
    max_tokens: 1200
    token_strategy: a11y_tree

  - id: use_mcp_tool_if_available
    description: "Discover MCP tools if the site publishes a manifest"
    expected_outcome: "A list of available MCP tools or a clear no-manifest failure"
    max_steps: 8
    max_tokens: 1000
    token_strategy: mcp_manifest
`;
}

function policiesYml() {
  return `version: "1.0.0"

ci_gate:
  default_mode: report
  blocking_allowed_after_calibration_days: 30

security:
  no_destructive_mcp_tools_without_human_approval: true
  no_auto_pr_without_human_review: true
`;
}

function llmsTxt(scan, contract) {
  const failed = scan.checks.filter((item) => !item.pass).map((item) => `- ${item.id}: ${item.message}`).join("\n") || "- No static gaps found.";
  return `# Agent Contract

Source: ${scan.source.url}
Readiness: ${contract.readiness.score} (${contract.readiness.level})

## Agent-readable summary

${scan.page.sampleText || "No readable homepage text was found in static HTML."}

## Known agent gaps

${failed}
`;
}

function llmsFullTxt(scan, logReport, missionReport) {
  const checks = scan.checks.map((item) => `- ${item.pass ? "PASS" : "FAIL"} ${item.id} (${item.severity}): ${item.message}`).join("\n");
  const missions = missionReport?.results?.length
    ? missionReport.results.map((item) => `- ${item.status.toUpperCase()} ${item.mission}: ${item.summary}${item.screenshot_path ? ` [screenshot: ${item.screenshot_path}]` : ""}`).join("\n")
    : "- Synthetic missions not run for this contract.";
  const bots = logReport?.findings?.length
    ? logReport.findings.map((item) => `- ${item.severity.toUpperCase()} ${item.id}: ${item.message}`).join("\n")
    : "- No passive traffic findings supplied.";
  const mcp = scan.mcp?.discovered
    ? `- MCP manifest: ${scan.mcp.source}\n- Tools: ${scan.mcp.tool_count}\n- Unapproved dangerous tools: ${scan.mcp.unapproved_dangerous_tools.length}`
    : "- MCP manifest not supplied.";

  return `# Agent Contract Full Context

Source: ${scan.source.url}
Generated: ${scan.generated_at}
Readiness: ${scan.readiness.score} (${scan.readiness.level})

## Browser-Readable Summary

${scan.page.sampleText || "No readable homepage text was found in static HTML."}

## Static Checks

${checks}

## Synthetic Mission Evidence

${missions}

## Passive Agent Traffic Evidence

${bots}

## API Surface

${scan.openapi?.ok ? `- OpenAPI: ${scan.openapi.url}\n- Operations: ${scan.openapi.operation_count}\n- Described operation rate: ${Math.round(scan.openapi.described_operation_rate * 100)}%\n- Example rate: ${Math.round(scan.openapi.example_rate * 100)}%` : "- OpenAPI not supplied or not parseable."}

## MCP Surface

${mcp}
`;
}

function agentSkillsIndex(scan, missionReport) {
  const missionResults = new Map((missionReport?.results || []).map((item) => [item.mission, item]));
  return {
    version: "1.0.0",
    source: scan.source.url,
    generated_at: nowIso(),
    skills: [
      {
        id: "understand_company",
        description: "Use browser-readable content to summarize what the product does.",
        evidence: missionStatus("understand_company", missionResults),
      },
      {
        id: "find_pricing",
        description: "Find pricing information from links or browser-readable page text.",
        evidence: missionStatus("find_pricing", missionResults),
      },
      {
        id: "find_api_quickstart",
        description: "Find the first documented API request from docs or quickstart content.",
        evidence: missionStatus("find_api_quickstart", missionResults),
      },
    ],
    mcp: scan.mcp?.discovered ? {
      source: scan.mcp.source,
      tool_count: scan.mcp.tool_count,
      unapproved_dangerous_tool_count: scan.mcp.unapproved_dangerous_tools.length,
    } : null,
  };
}

function cup(scan, missionReport) {
  const tested = missionReport?.tested || 0;
  const userConsentOk = (scan.mcp?.unapproved_dangerous_tools?.length || 0) === 0;
  return {
    user_consent: {
      tested,
      passed: userConsentOk ? (missionReport?.passed || 0) : 0,
      score: tested ? round((userConsentOk ? (missionReport?.passed || 0) : 0) / tested) : null,
      violations: userConsentOk ? [] : ["unapproved_dangerous_mcp_tools"],
    },
  };
}

function missionStatus(id, results) {
  const result = results.get(id);
  if (!result) return { status: "not_run" };
  return {
    status: result.status,
    summary: result.summary,
    screenshot_path: result.screenshot_path || null,
  };
}

function openApiPatches(scan) {
  if (!scan.openapi) return { patches: [] };
  if (!scan.openapi.ok) return { patches: [], warnings: [scan.openapi.error] };
  const patches = [];
  if (scan.openapi.example_rate < 0.5) patches.push({ op: "add_examples", reason: "Less than 50% of operations include examples." });
  if (!scan.openapi.has_error_responses) patches.push({ op: "add_error_responses", reason: "No 4xx/5xx responses documented." });
  if (!scan.openapi.has_security) patches.push({ op: "add_security_schemes", reason: "No security scheme documented." });
  return { patches };
}

function compactDate(value) {
  return value.replace(/[-:]/g, "").slice(0, 15);
}

function round(value) {
  return Math.round((value || 0) * 1000) / 1000;
}
