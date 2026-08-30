import { createHash } from "node:crypto";

export function hashWebMcpToolDefinition(tool) {
  const definition = {
    name: String(tool?.name || ""),
    title: tool?.title ? String(tool.title) : null,
    description: String(tool?.description || ""),
    inputSchema: tool?.inputSchema && typeof tool.inputSchema === "object" ? structuredClone(tool.inputSchema) : null,
    annotations: tool?.annotations && typeof tool.annotations === "object" ? structuredClone(tool.annotations) : null,
    origin: tool?.origin ? String(tool.origin) : null,
  };
  return createHash("sha256").update(canonicalJson(definition)).digest("base64url");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}
