import { readText, sha256 } from "./util.js";
import { fetchTextSafely } from "./safe-fetch.js";

const DANGER_RULES = [
  { category: "destructive", pattern: /\b(delete|remove|destroy|drop|truncate|purge|wipe|erase|revoke|disable|deactivate)\b/i },
  { category: "financial", pattern: /\b(charge|refund|transfer|payout|debit|withdraw|capture[_ -]?payment|void[_ -]?payment|settle[_ -]?payment)\b/i },
  { category: "command_execution", pattern: /\b(shell|exec|execute|command|terminal|subprocess|bash|run[_ -]?(script|shell|command))\b/i },
  { category: "write_side_effect", pattern: /\b(write|update|modify|mutate|commit|push|deploy|publish|send|approve)\b/i },
];

export async function loadMcpManifest(input, options = {}) {
  const result = await readManifest(input, options);
  if (!result.ok) {
    return {
      discovered: false,
      source: input,
      error: result.error || `MCP manifest fetch failed with ${result.status}`,
      tool_count: 0,
      dangerous_tools: [],
      unapproved_dangerous_tools: [],
    };
  }
  try {
    return analyzeMcpManifest(JSON.parse(result.text), result.url, result.text);
  } catch (error) {
    return {
      discovered: false,
      source: result.url,
      error: `MCP manifest is not valid JSON: ${error.message}`,
      tool_count: 0,
      dangerous_tools: [],
      unapproved_dangerous_tools: [],
    };
  }
}

export function analyzeMcpManifest(manifest, source = "inline", rawText = JSON.stringify(manifest)) {
  const tools = extractTools(manifest);
  const specVersion = String(manifest.protocolVersion || manifest.protocol_version || manifest.spec_version || manifest.specVersion || manifest.mcp?.version || "");
  const dangerousTools = tools.flatMap((tool) => {
    const reasons = dangerReasons(tool);
    if (!reasons.length) return [];
    return [{
      name: tool.name,
      description: tool.description || "",
      categories: reasons,
      requires_approval: requiresApproval(tool),
    }];
  });

  return {
    discovered: true,
    source,
    name: manifest?.name || manifest?.server?.name || "",
    spec_version: specVersion,
    spec_version_compliant: specVersion === "2025-06-18",
    content_hash: sha256(rawText || JSON.stringify(manifest)),
    tool_description_hash: sha256(tools.map((tool) => `${tool.name}:${tool.description || ""}`).join("\n")),
    tool_count: tools.length,
    tools: tools.map((tool) => ({ name: tool.name, description: tool.description || "", description_hash: sha256(tool.description || "") })),
    dangerous_tools: dangerousTools,
    unapproved_dangerous_tools: dangerousTools.filter((tool) => !tool.requires_approval),
  };
}

async function readManifest(input, options) {
  if (/^https?:\/\//i.test(input)) return fetchManifest(input, options);
  try {
    return { ok: true, url: input, status: 200, text: await readText(input) };
  } catch (error) {
    return { ok: false, url: input, status: 0, text: "", error: error.message };
  }
}

async function fetchManifest(input, options) {
  try {
    return await fetchTextSafely(input, { ...options, accept: "application/json,*/*" });
  } catch (error) {
    return { ok: false, url: input, status: 0, text: "", error: error.message };
  }
}

function extractTools(manifest) {
  if (!manifest || typeof manifest !== "object") return [];
  const candidates = [
    manifest.tools,
    manifest.server?.tools,
    manifest.capabilities?.tools,
    manifest.mcp?.tools,
  ].filter(Array.isArray);
  const tools = candidates.flat();
  return tools.map(normalizeTool).filter((tool) => tool.name);
}

function normalizeTool(tool) {
  if (typeof tool === "string") return { name: tool, description: "" };
  if (!tool || typeof tool !== "object") return { name: "", description: "" };
  return {
    ...tool,
    name: String(tool.name || tool.id || tool.title || ""),
    description: String(tool.description || tool.summary || ""),
  };
}

function dangerReasons(tool) {
  const haystack = `${tool.name} ${tool.description}`.replace(/[_-]/g, " ");
  // ponytail: static MCP manifests cannot prove runtime side effects; fail on obvious risky verbs and let teams annotate approval.
  return DANGER_RULES.filter((rule) => rule.pattern.test(haystack)).map((rule) => rule.category);
}

function requiresApproval(tool) {
  const candidates = [
    tool.requires_human_approval,
    tool.requiresHumanApproval,
    tool.human_approval,
    tool.humanApproval,
    tool.confirmation_required,
    tool.confirmationRequired,
    tool.requires_confirmation,
    tool.requiresConfirmation,
    tool.annotations?.requires_human_approval,
    tool.annotations?.humanApproval,
  ];
  return candidates.some((value) => value === true || String(value).toLowerCase() === "true");
}
