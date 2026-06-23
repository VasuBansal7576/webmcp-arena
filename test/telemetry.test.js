import assert from "node:assert/strict";
import test from "node:test";

import { buildOtlpTrace } from "../src/telemetry.js";

test("OTLP trace carries GenAI agent and workflow attributes", () => {
  const trace = buildOtlpTrace({ command: "gate", scan: { source: { url: "https://example.test" }, readiness: { score: 88 } } });
  const attrs = Object.fromEntries(trace.resourceSpans[0].scopeSpans[0].spans[0].attributes.map((item) => [item.key, item.value.stringValue ?? item.value.doubleValue]));

  assert.equal(attrs["gen_ai.operation.name"], "execute_tool");
  assert.equal(attrs["gen_ai.agent.name"], "agent_contract_scanner");
  assert.equal(attrs["gen_ai.workflow.name"], "agent_contract_cli");
  assert.equal(attrs["agent_contract.semconv"], "gen_ai.1.42.0");
});
