import { join } from "node:path";
import { nowIso, writeJson, writeText } from "./util.js";

export async function writeFixPack(outDir, { scan, logReport }) {
  const files = [];
  const addText = async (name, value) => {
    await writeText(join(outDir, name), value);
    files.push(name);
  };
  const addJson = async (name, value) => {
    await writeJson(join(outDir, name), value);
    files.push(name);
  };

  await addText("README.md", readme(scan, logReport));
  if (!checkPassed(scan, "llms_txt")) await addText("llms.txt", llmsTxt(scan));
  if (!checkPassed(scan, "json_ld")) await addJson("schema-org.jsonld", jsonLd(scan));
  if (scan.openapi) {
    await addJson("openapi-patches.json", openApiPatches(scan));
    if (!scan.openapi.has_error_responses) await addJson("problem-details-example.json", problemDetailsExample(scan));
  }
  if (scan.mcp?.discovered) await addText("mcp-security-checklist.md", mcpSecurityChecklist(scan));

  return { generated_at: nowIso(), outDir, files };
}

function readme(scan, logReport) {
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
${costAtScale(scan, logReport)}
`;
}

function costAtScale(scan, logReport) {
  if (!logReport?.total_agent_requests || !scan.page?.dom_tokens) return "";
  const dailyInputTokens = logReport.total_agent_requests * scan.page.dom_tokens;
  return `
## Cost at scale

Observed agent requests: ${logReport.total_agent_requests}
Readable DOM tokens per request: ${scan.page.dom_tokens}
Projected repeated navigation load: ${dailyInputTokens.toLocaleString()} input tokens per matching traffic window.
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
