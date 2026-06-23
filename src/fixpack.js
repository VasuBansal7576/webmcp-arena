import { join } from "node:path";
import { nowIso, writeJson, writeText } from "./util.js";

const SONNET_INPUT_USD_PER_MTOK = 3;
const BASELINE_AGENT_VISITS_PER_DAY = 500;

export async function writeFixPack(outDir, { scan, logReport, missionReport }) {
  const files = [];
  const addText = async (name, value) => {
    await writeText(join(outDir, name), value);
    files.push(name);
  };
  const addJson = async (name, value) => {
    await writeJson(join(outDir, name), value);
    files.push(name);
  };

  await addText("README.md", readme(scan, logReport, missionReport));
  if (!checkPassed(scan, "llms_txt")) await addText("llms.txt", llmsTxt(scan));
  if (!checkPassed(scan, "json_ld")) await addJson("schema-org.jsonld", jsonLd(scan));
  if (checkFailed(scan, "agent_auth_undeclared")) await addJson("agent-auth-template.json", agentAuthTemplate(scan));
  if (checkFailed(scan, "a2a_card_absent") || checkFailed(scan, "a2a_card_invalid")) await addJson("agent.json", a2aCardTemplate(scan));
  if (scan.openapi) {
    await addJson("openapi-patches.json", openApiPatches(scan));
    if (!scan.openapi.has_error_responses) await addJson("problem-details-example.json", problemDetailsExample(scan));
  }
  if (scan.mcp?.discovered) await addText("mcp-security-checklist.md", mcpSecurityChecklist(scan));

  return { generated_at: nowIso(), outDir, files };
}

function readme(scan, logReport, missionReport) {
  const failed = scan.checks.filter((item) => !item.pass);
  const list = failed.length
    ? failed.map((item) => `- ${item.id}: ${item.message}`).join("\n")
    : "- No static gaps required deterministic fix files.";
  return `# Agent Contract Fix Pack

Source: ${scan.source.url}
Generated: ${nowIso()}

Review these files before committing them. This pack does not open PRs or mutate production.

## Evidence-backed gaps

${list}
${cpiAdvice(scan)}
${costAtScale(scan, logReport, missionReport)}
`;
}

function cpiAdvice(scan) {
  const risky = (scan.page?.critical_elements || []).filter((item) => item.structural_risk);
  if (!risky.length) return "";
  return `
## Content Position Index

${risky.map((item) => `- ${item.id}: CPI ${item.cpi} sits in the middle-context risk zone. Move this content earlier in SSR HTML or declare it in llms.txt.`).join("\n")}
`;
}

function costAtScale(scan, logReport, missionReport) {
  const missionTokens = (missionReport?.results || []).reduce((sum, item) => sum + (item.tokens_consumed || 0), 0);
  const tokensPerVisit = missionTokens || scan.page?.dom_tokens;
  if (!tokensPerVisit) return "";
  const visits = logReport?.total_agent_requests || BASELINE_AGENT_VISITS_PER_DAY;
  const monthlyInputTokens = visits * tokensPerVisit * (logReport ? 1 : 30);
  const monthlyUsd = (monthlyInputTokens / 1_000_000) * SONNET_INPUT_USD_PER_MTOK;
  const source = logReport ? "observed agent requests" : "baseline estimate without logs";
  return `
## Cost at scale

Traffic basis: ${visits.toLocaleString()} ${source}
Tokens per visit: ${tokensPerVisit.toLocaleString()}
Projected monthly input load: ${Math.round(monthlyInputTokens).toLocaleString()} tokens
Estimated monthly Sonnet input cost: $${monthlyUsd.toFixed(2)} at $${SONNET_INPUT_USD_PER_MTOK}/MTok input.
`;
}

function llmsTxt(scan) {
  return `# ${scan.page.title || new URL(scan.source.url).hostname}

Source: ${scan.source.url}

## Summary

${scan.page.sampleText || "No readable static summary was found. Add a concise product summary here before publishing."}

## Agent Guidance

- Prefer documented API and docs links over brittle UI automation.
- Respect robots.txt and published rate limits.
- Do not perform destructive actions without explicit user confirmation.
`;
}

function jsonLd(scan) {
  const url = new URL(scan.source.url);
  return {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: scan.page.title || url.hostname,
    url: scan.source.url,
    description: scan.page.sampleText || "Agent-readable product description.",
    applicationCategory: "DeveloperApplication",
  };
}

function agentAuthTemplate(scan) {
  return {
    agent_auth: {
      supported_schemes: ["mastercard_agent_pay", "visa_tap", "ap2_vc"],
      consent_flow_url: new URL("/agent/consent", scan.source.url).pathname,
      delegation_scope: ["read_catalog", "initiate_checkout"],
      identity_required_for: ["checkout", "account_creation"],
    },
  };
}

function a2aCardTemplate(scan) {
  const url = new URL(scan.source.url);
  return {
    name: scan.page?.title || url.hostname,
    endpoint: new URL("/agent", scan.source.url).href,
    capabilities: [
      {
        id: "answer_product_questions",
        description: "Answer product, pricing, documentation, and policy questions from published agent-readable content.",
      },
    ],
  };
}

function openApiPatches(scan) {
  if (!scan.openapi?.ok) return { patches: [], warnings: [scan.openapi?.error || "OpenAPI unavailable"] };
  const patches = [];
  if (scan.openapi.example_rate < 0.5) {
    patches.push({
      op: "add_examples",
      reason: "Less than 50% of operations include examples.",
      template: {
        responses: {
          "200": {
            content: {
              "application/json": {
                examples: {
                  ok: { summary: "Successful response", value: {} },
                },
              },
            },
          },
        },
      },
    });
  }
  if (!scan.openapi.has_error_responses) {
    patches.push({
      op: "add_error_responses",
      reason: "No 4xx/5xx responses documented.",
      template: {
        responses: {
          "400": {
            description: "Invalid request",
            content: {
              "application/problem+json": {
                examples: {
                  invalid_request: { value: problemDetailsExample(scan) },
                },
              },
            },
          },
        },
      },
    });
  }
  if (!scan.openapi.has_security) {
    patches.push({
      op: "add_security_schemes",
      reason: "No security scheme documented.",
      template: {
        security: [{ bearerAuth: [] }],
        components: {
          securitySchemes: {
            bearerAuth: { type: "http", scheme: "bearer" },
          },
        },
      },
    });
  }
  return { openapi_url: scan.openapi.url, patches };
}

function problemDetailsExample(scan) {
  return {
    type: "https://example.com/problems/agent-contract-error",
    title: "Invalid request",
    status: 400,
    detail: "The request could not be completed. Include a stable machine-readable error code in production.",
    instance: new URL("/errors/example", scan.source.url).href,
  };
}

function mcpSecurityChecklist(scan) {
  const mcp = scan.mcp;
  const dangerous = (mcp.unapproved_dangerous_tools || []).map((tool) => `- [ ] Review \`${tool.name}\` (${tool.categories.join(", ")}) and add explicit human approval metadata.`).join("\n") || "- [x] No unapproved dangerous tools detected.";
  return `# MCP Security Checklist

Source: ${mcp.source}

Reference: NSA U/OO/6030316-26, Model Context Protocol (MCP): Security Design.

- [${mcp.spec_version_compliant ? "x" : " "}] MCP spec version is 2025-06-18.
- [ ] Protected Resource Metadata is documented for authenticated MCP resources.
- [ ] Tool annotations mark destructive, idempotent, and read-only behavior.
- [ ] Tool descriptions are reviewed for prompt injection and poisoning.
- [ ] Tool description hashes are monitored for rug-pull changes.

## Tool approval review

${dangerous}
`;
}

function checkPassed(scan, id) {
  return scan.checks.find((item) => item.id === id)?.pass === true;
}

function checkFailed(scan, id) {
  return scan.checks.find((item) => item.id === id)?.pass === false;
}
