import { attr, nowIso, spanId, traceId, writeJson } from "./util.js";

export function buildOtlpTrace({ command, scan, logReport, missionReport, status = "ok", genAi }) {
  const start = Date.now() * 1_000_000;
  const trace = traceId();
  return {
    resourceSpans: [{
      resource: {
        attributes: [
          attr("service.name", "agent-contract"),
          attr("service.version", "0.1.0"),
        ],
      },
      scopeSpans: [{
        scope: { name: "agent-contract-cli" },
        spans: [{
          traceId: trace,
          spanId: spanId(),
          name: `agent_contract.${command}`,
          kind: 2,
          startTimeUnixNano: String(start),
          endTimeUnixNano: String(Date.now() * 1_000_000),
          attributes: [
            attr("gen_ai.operation.name", "web_agent_mission"),
            attr("gen_ai.system", "agent_contract"),
            attr("gen_ai.agent.name", "agent_contract_scanner"),
            attr("gen_ai.workflow.name", "agent_contract_cli"),
            ...genAiAttributes(genAi),
            attr("agent_contract.command", command),
            attr("agent_contract.status", status),
            attr("agent_contract.url", scan?.source?.url || ""),
            attr("agent_contract.readiness.score", scan?.readiness?.score ?? 0),
            attr("agent_contract.passive.total_agent_requests", logReport?.total_agent_requests ?? 0),
            attr("agent_contract.missions.tested", missionReport?.tested ?? 0),
            attr("agent_contract.missions.failed", missionReport?.failed ?? 0),
            attr("agent_contract.semconv", "gen_ai.1.42.0"),
            attr("agent_contract.otel.semconv_opt_in", "OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental"),
          ],
        }],
      }],
    }],
    exported_at: nowIso(),
  };
}

function genAiAttributes(genAi) {
  if (!genAi) return [];
  return [
    genAi.model ? attr("gen_ai.request.model", genAi.model) : null,
    genAi.provider ? attr("gen_ai.provider.name", genAi.provider) : null,
    Number.isFinite(genAi.inputTokens) ? attr("gen_ai.usage.input_tokens", genAi.inputTokens) : null,
    Number.isFinite(genAi.outputTokens) ? attr("gen_ai.usage.output_tokens", genAi.outputTokens) : null,
  ].filter(Boolean);
}

export async function writeTelemetry(path, payload) {
  await writeJson(path, payload);
}

export async function sendTelemetry(endpoint, payload) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`OTLP export failed: ${response.status} ${await response.text()}`);
  return response.status;
}
