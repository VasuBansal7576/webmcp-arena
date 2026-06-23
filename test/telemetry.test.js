import assert from "node:assert/strict";
import test from "node:test";

import { buildOtlpTrace } from "../src/telemetry.js";

test("OTLP trace carries GenAI agent and workflow attributes", () => {
  const trace = buildOtlpTrace({ command: "gate", scan: { source: { url: "https://example.test" }, readiness: { score: 88 } } });
  const attrs = Object.fromEntries(trace.resourceSpans[0].scopeSpans[0].spans[0].attributes.map((item) => [item.key, item.value.stringValue ?? item.value.doubleValue]));

  assert.equal(attrs["gen_ai.operation.name"], "web_agent_mission");
  assert.equal(attrs["gen_ai.agent.name"], "agent_contract_scanner");
  assert.equal(attrs["gen_ai.workflow.name"], "agent_contract_cli");
  assert.equal(attrs["gen_ai.request.model"], undefined);
  assert.equal(attrs["agent_contract.semconv"], "gen_ai.1.42.0");
  assert.match(attrs["agent_contract.otel.semconv_opt_in"], /gen_ai_latest_experimental/);
});

test("OTLP trace emits v1.37 GenAI model and usage names only when supplied", () => {
  const trace = buildOtlpTrace({
    command: "gate",
    scan: { source: { url: "https://example.test" }, readiness: { score: 88 } },
    genAi: { provider: "anthropic", model: "claude-sonnet-4-5", inputTokens: 1200, outputTokens: 24 },
  });
  const attrs = Object.fromEntries(trace.resourceSpans[0].scopeSpans[0].spans[0].attributes.map((item) => [item.key, item.value.stringValue ?? item.value.doubleValue]));

  assert.equal(attrs["gen_ai.provider.name"], "anthropic");
  assert.equal(attrs["gen_ai.request.model"], "claude-sonnet-4-5");
  assert.equal(attrs["gen_ai.usage.input_tokens"], 1200);
  assert.equal(attrs["gen_ai.usage.output_tokens"], 24);
});
