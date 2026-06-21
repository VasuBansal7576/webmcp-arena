import { nowIso, writeText } from "./util.js";

export async function explainFixesWithLlm(context, provider = {}) {
  const endpoint = (provider.endpoint || process.env.OPENAI_BASE_URL || "https://api.openai.com/v1").replace(/\/$/, "");
  const apiKey = provider.apiKey || process.env.OPENAI_API_KEY;
  const model = provider.model || process.env.AGENT_CONTRACT_LLM_MODEL;
  if (!apiKey || !model) {
    throw new Error("LLM fix explanations require --llm-api-key or OPENAI_API_KEY and --llm-model or AGENT_CONTRACT_LLM_MODEL.");
  }

  const response = await fetch(`${endpoint}/responses`, {
    method: "POST",
    headers: {
      "authorization": `Bearer ${apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model,
      store: false,
      max_output_tokens: provider.maxOutputTokens || 900,
      input: [
        {
          role: "developer",
          content: "You explain agent-readiness fix packs. Use only the provided evidence. Do not invent files, URLs, scan results, or production claims.",
        },
        {
          role: "user",
          content: prompt(context),
        },
      ],
    }),
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`LLM provider failed: ${response.status} ${body.error?.message || JSON.stringify(body)}`);
  const text = extractText(body);
  if (!text) throw new Error("LLM provider returned no text output.");
  return {
    generated_at: nowIso(),
    provider: endpoint,
    model,
    response_id: body.id || null,
    text,
  };
}

export async function writeLlmFixExplanation(path, context, provider) {
  const result = await explainFixesWithLlm(context, provider);
  await writeText(path, `# LLM Fix Explanation

Generated: ${result.generated_at}
Model: ${result.model}
Response: ${result.response_id || "n/a"}

${result.text}
`);
  return result;
}

function prompt(context) {
  return JSON.stringify({
    task: "Explain the safest review order for this Agent Contract fix pack and call out any risk before a human commits it.",
    findings: context.findings || [],
    fixPackFiles: context.fixPackFiles || [],
  }, null, 2);
}

function extractText(body) {
  if (body.output_text) return body.output_text;
  return (body.output || [])
    .flatMap((item) => item.content || [])
    .map((content) => content.text || "")
    .filter(Boolean)
    .join("\n")
    .trim();
}
