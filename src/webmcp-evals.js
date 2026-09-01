const CASE_FIELDS = new Set(["name", "messages", "expectedCall"]);
const CALL_FIELDS = new Set(["functionName", "arguments", "result", "mockOutput", "optional"]);
const CONSTRAINTS = new Set(["$pattern", "$contains", "$gt", "$gte", "$lt", "$lte", "$type", "$any"]);
const CONSTRAINT_TYPES = new Set(["string", "number", "boolean", "array", "object", "null"]);
const WRITE_KINDS = new Set(["write", "create", "update", "delete", "charge", "purchase", "booking"]);
const BUDGETS = Object.freeze({ toolName: 30, parameterName: 30, toolDescription: 500, parameterDescription: 150, output: 1_500 });

export function createWebMcpEvalBridge({ verifyProof } = {}) {
  if (typeof verifyProof !== "function") throw new TypeError("WebMCP eval bridge requires a proof verifier");

  return Object.freeze({
    async audit(input = {}) {
      const suite = parseSuite(input.suite);
      const imported = parseUpstreamReport(input.upstreamReport, suite);
      const selection = evaluateSelection(suite, imported);
      const guidance = auditWebMcpGuidance({ tools: input.tools, observations: input.observations });
      const behavior = await evaluateBehavior(input.behavioralProof, verifyProof);
      const blockingGuidance = guidance.findings.filter((finding) => ["critical", "high"].includes(finding.severity));
      const findings = [
        ...selection.findings,
        ...blockingGuidance,
        ...behavior.findings,
      ];
      const inconclusiveReasons = [
        ...guidance.inconclusiveReasons,
        ...behavior.inconclusiveReasons,
      ];
      const verdict = [selection.status, guidance.status, behavior.status].includes("fail")
        ? "fail"
        : [selection.status, guidance.status, behavior.status].includes("inconclusive")
          ? "inconclusive"
          : "pass";

      return deepFreeze({
        kind: "arena.webmcp_eval_audit",
        version: 1,
        status: verdict,
        verdict,
        source: {
          format: "googlechromelabs.webmcp-evals",
          compatibility: "2026-09",
          suiteCases: suite.length,
          importedRows: imported.rowCount,
          trust: "untrusted_import_recomputed",
          target: imported.target,
        },
        layers: { selection, guidance, behavior },
        findings,
        advisories: guidance.findings.filter((finding) => !["critical", "high"].includes(finding.severity)),
        inconclusive_reasons: unique(inconclusiveReasons),
        claim_scope: {
          selection: "recomputed from imported tool calls",
          guidance: "checked from supplied tool definitions and runtime observations",
          behavior: behavior.status === "inconclusive" ? "not established" : "verified Arena proof",
          does_not_prove: [
            "the imported model provider identity",
            "behavior outside the supplied Arena proof",
            "production safety after the audited release changes",
          ],
        },
      });
    },
  });
}

export function auditWebMcpGuidance({ tools, observations } = {}) {
  const normalizedTools = parseTools(tools);
  const findings = [];
  for (const tool of normalizedTools) auditStaticTool(tool, findings);

  const inconclusiveReasons = [];
  const coverage = {
    tools: normalizedTools.length > 0,
    runtime: observations !== undefined,
    cancellation: false,
    tokenLimit: false,
  };
  if (observations === undefined) {
    inconclusiveReasons.push("runtime_observations_missing", "cancellation_not_tested", "agent_token_limit_unverified");
  } else {
    const runtime = parseObservations(observations);
    coverage.cancellation = runtime.cancellation.tested;
    coverage.tokenLimit = runtime.tokenLimit.configured;
    auditRuntime(normalizedTools, runtime, findings, inconclusiveReasons);
  }
  if (!normalizedTools.length) inconclusiveReasons.push("tool_definitions_missing");

  const blocking = findings.some((finding) => ["critical", "high"].includes(finding.severity));
  const status = blocking
    ? "fail"
    : inconclusiveReasons.length
      ? "inconclusive"
      : findings.length
        ? "warn"
        : "pass";
  return deepFreeze({
    status,
    budgets: BUDGETS,
    coverage,
    findings,
    inconclusiveReasons: unique(inconclusiveReasons),
  });
}

function parseSuite(value) {
  if (!Array.isArray(value) || !value.length) throw new TypeError("webmcp-evals suite must contain at least one case");
  const identities = new Set();
  return value.map((candidate, index) => {
    assertPlainObject(candidate, `webmcp-evals case ${index + 1} must be an object`);
    assertAllowedFields(candidate, CASE_FIELDS, `webmcp-evals case ${index + 1}`);
    const name = candidate.name === undefined ? undefined : nonEmptyString(candidate.name, `webmcp-evals case ${index + 1} name`);
    const messages = parseMessages(candidate.messages, index);
    const expectedCall = candidate.expectedCall === null
      ? null
      : parseExpectedNodes(candidate.expectedCall, `webmcp-evals case ${index + 1} expectedCall`);
    const identity = name || firstMessage(messages)?.content;
    if (!identity) throw new TypeError(`webmcp-evals case ${index + 1} needs a name or content message for a stable identity`);
    if (identities.has(identity)) throw new TypeError(`webmcp-evals cases must have a unique case identity: ${identity}`);
    identities.add(identity);
    return deepFreeze({ name, messages, expectedCall, identity });
  });
}

function parseMessages(value, caseIndex) {
  if (!Array.isArray(value)) throw new TypeError(`webmcp-evals case ${caseIndex + 1} messages must be an array`);
  return value.map((message, messageIndex) => {
    assertPlainObject(message, `webmcp-evals case ${caseIndex + 1} message ${messageIndex + 1} must be an object`);
    if (message.type === "message") {
      assertExactFields(message, new Set(["role", "type", "content"]), "content message");
      if (!new Set(["user", "model"]).has(message.role)) throw new TypeError("content message role must be user or model");
      return { role: message.role, type: "message", content: nonEmptyString(message.content, "content message content") };
    }
    if (message.type === "functioncall") {
      assertExactFields(message, new Set(["role", "type", "name", "arguments"]), "function-call message");
      if (message.role !== "model") throw new TypeError("function-call message role must be model");
      assertPlainObject(message.arguments, "function-call message arguments must be an object");
      return { role: "model", type: "functioncall", name: nonEmptyString(message.name, "function-call name"), arguments: clone(message.arguments) };
    }
    if (message.type === "functionresponse") {
      assertExactFields(message, new Set(["role", "type", "name", "response"]), "function-response message");
      if (message.role !== "user") throw new TypeError("function-response message role must be user");
      assertPlainObject(message.response, "function-response message response must be an object");
      return { role: "user", type: "functionresponse", name: nonEmptyString(message.name, "function-response name"), response: clone(message.response) };
    }
    throw new TypeError(`unsupported webmcp-evals message type: ${String(message.type)}`);
  });
}

function parseExpectedNodes(value, label) {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array or null`);
  return value.map((node, index) => parseExpectedNode(node, `${label} node ${index + 1}`));
}

function parseExpectedNode(node, label) {
  assertPlainObject(node, `${label} must be an object`);
  if (Object.hasOwn(node, "ordered") || Object.hasOwn(node, "unordered")) {
    const kind = Object.hasOwn(node, "ordered") ? "ordered" : "unordered";
    assertExactFields(node, new Set([kind]), `${label} group`);
    const children = parseExpectedNodes(node[kind], `${label}.${kind}`);
    if (!children.length) throw new TypeError(`${label}.${kind} must contain at least one node`);
    if (kind === "unordered" && children.length > 15) throw new TypeError(`${label}.${kind} cannot contain more than 15 nodes`);
    return { [kind]: children };
  }
  assertAllowedFields(node, CALL_FIELDS, label);
  const functionName = nonEmptyString(node.functionName, `${label} functionName`);
  if (node.arguments !== undefined && node.arguments !== null) {
    assertPlainObject(node.arguments, `${label} arguments must be an object or null`);
    validateConstraints(node.arguments, `${label} arguments`);
  }
  if (node.result !== undefined) validateConstraints(node.result, `${label} result`);
  if (node.optional !== undefined && typeof node.optional !== "boolean") throw new TypeError(`${label} optional must be a boolean`);
  return {
    functionName,
    ...(Object.hasOwn(node, "arguments") ? { arguments: clone(node.arguments) } : {}),
    ...(Object.hasOwn(node, "result") ? { result: clone(node.result) } : {}),
    ...(Object.hasOwn(node, "mockOutput") ? { mockOutput: clone(node.mockOutput) } : {}),
    ...(node.optional === true ? { optional: true } : {}),
  };
}

function validateConstraints(value, label) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => validateConstraints(item, `${label}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  const keys = Object.keys(value);
  const constraintKeys = keys.filter((key) => key.startsWith("$"));
  if (constraintKeys.length) {
    if (constraintKeys.length !== keys.length) throw new TypeError(`${label} mixes constraint and value keys`);
    for (const key of constraintKeys) {
      if (!CONSTRAINTS.has(key)) throw new TypeError(`${label} contains unsupported constraint: ${key}`);
      if (key === "$pattern") {
        nonEmptyString(value[key], `${label} ${key}`);
        buildPattern(value[key]);
      } else if (key === "$contains") {
        if (typeof value[key] !== "string") throw new TypeError(`${label} ${key} must be a string`);
      } else if (["$gt", "$gte", "$lt", "$lte"].includes(key)) {
        if (!Number.isFinite(value[key])) throw new TypeError(`${label} ${key} must be a finite number`);
      } else if (key === "$type" && !CONSTRAINT_TYPES.has(value[key])) {
        throw new TypeError(`${label} $type is unsupported: ${String(value[key])}`);
      } else if (key === "$any" && typeof value[key] !== "boolean") {
        throw new TypeError(`${label} $any must be a boolean`);
      }
    }
    return;
  }
  for (const [key, item] of Object.entries(value)) validateConstraints(item, `${label}.${key}`);
}

function parseUpstreamReport(value, suite) {
  assertPlainObject(value, "webmcp-evals report must be an object");
  const resultBlock = Array.isArray(value.results) ? value : value.results;
  assertPlainObject(resultBlock, "webmcp-evals report results must be an object");
  if (!Array.isArray(resultBlock.results)) throw new TypeError("webmcp-evals report results.results must be an array");
  const known = new Set(suite.map((testCase) => testCase.identity));
  const grouped = new Map();
  const unexpected = new Set();
  for (let index = 0; index < resultBlock.results.length; index += 1) {
    const row = resultBlock.results[index];
    assertPlainObject(row, `webmcp-evals result row ${index + 1} must be an object`);
    assertPlainObject(row.test, `webmcp-evals result row ${index + 1} test must be an object`);
    const identity = typeof row.test.name === "string" && row.test.name.trim()
      ? row.test.name.trim()
      : firstMessage(Array.isArray(row.test.messages) ? row.test.messages : [])?.content;
    if (!identity) throw new TypeError(`webmcp-evals result row ${index + 1} has no stable case identity`);
    if (!known.has(identity)) unexpected.add(identity);
    const runIndex = positiveInteger(row.runIndex ?? 1, `webmcp-evals result row ${index + 1} runIndex`);
    const stepIndex = positiveInteger(row.stepIndex ?? index + 1, `webmcp-evals result row ${index + 1} stepIndex`);
    const groupKey = `${identity}\0${runIndex}`;
    const rows = grouped.get(groupKey) || [];
    if (rows.some((item) => item.stepIndex === stepIndex)) throw new TypeError(`webmcp-evals report has duplicate step ${stepIndex} for ${identity} run ${runIndex}`);
    rows.push({ stepIndex, response: parseActualCall(row.response, `webmcp-evals result row ${index + 1} response`) });
    grouped.set(groupKey, rows);
  }
  for (const rows of grouped.values()) rows.sort((left, right) => left.stepIndex - right.stepIndex);
  const target = typeof value.config?.url === "string" ? value.config.url : null;
  return { grouped, unexpected: [...unexpected], rowCount: resultBlock.results.length, target };
}

function parseActualCall(value, label) {
  if (value === null || value === undefined || typeof value.functionName !== "string") return null;
  assertPlainObject(value, `${label} must be an object or null`);
  const args = value.args ?? value.arguments;
  assertPlainObject(args, `${label} args must be an object`);
  return {
    functionName: nonEmptyString(value.functionName, `${label} functionName`),
    args: clone(args),
    ...(Object.hasOwn(value, "result") ? { result: clone(value.result) } : {}),
  };
}

function evaluateSelection(suite, imported) {
  const cases = [];
  const findings = [];
  let passCount = 0;
  let failCount = 0;
  for (const testCase of suite) {
    const matchingGroups = [...imported.grouped.entries()]
      .filter(([key]) => key.startsWith(`${testCase.identity}\0`))
      .map(([key, rows]) => ({ runIndex: Number(key.slice(key.lastIndexOf("\0") + 1)), rows }))
      .sort((left, right) => left.runIndex - right.runIndex);
    const groups = matchingGroups.length ? matchingGroups : [{ runIndex: 1, rows: [] }];
    const runs = groups.map(({ runIndex, rows }) => {
      const actual = rows.flatMap((row) => row.response ? [row.response] : []);
      const pass = trajectoryMatches(testCase.expectedCall, actual);
      if (pass) passCount += 1;
      else {
        failCount += 1;
        findings.push(finding({
          code: "tool_selection_mismatch",
          severity: "high",
          title: `Tool trajectory did not match for ${testCase.identity}`,
          evidence: `run ${runIndex}: expected ${countExpected(testCase.expectedCall)} required call(s), observed ${actual.length}`,
          rootCause: "The imported calls do not satisfy the authored webmcp-evals trajectory when Arena recomputes it.",
          repair: "Fix the tool names, descriptions, schemas, or journey state, then rerun webmcp-evals and Arena.",
        }));
      }
      return {
        runIndex,
        status: pass ? "pass" : "fail",
        expectedCount: countExpected(testCase.expectedCall),
        actualCount: actual.length,
        steps: actual.map((call, index) => ({
          index: index + 1,
          status: pass ? "pass" : "unmatched",
          functionName: call.functionName,
          arguments: call.args,
        })),
      };
    });
    cases.push({ identity: testCase.identity, name: testCase.name || null, runs });
  }
  for (const identity of imported.unexpected) {
    failCount += 1;
    findings.push(finding({
      code: "unexpected_eval_case",
      severity: "high",
      title: `Imported report contains an unknown eval case: ${identity}`,
      evidence: identity,
      rootCause: "The report and eval suite do not describe the same case set.",
      repair: "Generate the JSON report from the exact eval file passed to Arena.",
    }));
  }
  return deepFreeze({
    status: failCount ? "fail" : "pass",
    caseCount: suite.length,
    runCount: passCount + failCount,
    passCount,
    failCount,
    cases,
    findings,
  });
}

function trajectoryMatches(expectedCall, actual) {
  if (expectedCall === null) return actual.length === 0;
  const endIndexes = matchOrdered(expectedCall, actual, new Set([0]));
  return endIndexes.has(actual.length);
}

function matchOrdered(nodes, actual, initialIndexes) {
  let indexes = initialIndexes;
  for (const node of nodes) {
    const next = new Set();
    for (const index of indexes) for (const end of matchNode(node, actual, index)) next.add(end);
    if (!next.size) return next;
    indexes = next;
  }
  return indexes;
}

function matchNode(node, actual, index) {
  if (node.ordered) return matchOrdered(node.ordered, actual, new Set([index]));
  if (node.unordered) return matchUnordered(node.unordered, actual, index);
  const indexes = new Set();
  if (node.optional) indexes.add(index);
  if (index < actual.length && callMatches(node, actual[index])) indexes.add(index + 1);
  return indexes;
}

function matchUnordered(nodes, actual, startIndex) {
  const memo = new Map();
  const all = (1 << nodes.length) - 1;
  function visit(mask, index) {
    const key = `${mask}:${index}`;
    if (memo.has(key)) return memo.get(key);
    if (mask === 0) return new Set([index]);
    const outcomes = new Set();
    for (let position = 0; position < nodes.length; position += 1) {
      const bit = 1 << position;
      if (!(mask & bit)) continue;
      for (const afterNode of matchNode(nodes[position], actual, index)) {
        for (const end of visit(mask ^ bit, afterNode)) outcomes.add(end);
      }
    }
    memo.set(key, outcomes);
    return outcomes;
  }
  return visit(all, startIndex);
}

function callMatches(expected, actual) {
  if (expected.functionName !== actual.functionName) return false;
  if (expected.arguments !== undefined && expected.arguments !== null && !matchesArgument(expected.arguments, actual.args)) return false;
  if (expected.result !== undefined && !matchesArgument(expected.result, actual.result)) return false;
  return true;
}

function matchesArgument(expected, actual) {
  if (isConstraintObject(expected)) {
    for (const [operator, constraint] of Object.entries(expected)) {
      if (operator === "$pattern" && (typeof actual !== "string" || !buildPattern(constraint).test(actual))) return false;
      if (operator === "$contains" && (typeof actual !== "string" || !actual.includes(constraint))) return false;
      if (operator === "$gt" && !(typeof actual === "number" && actual > constraint)) return false;
      if (operator === "$gte" && !(typeof actual === "number" && actual >= constraint)) return false;
      if (operator === "$lt" && !(typeof actual === "number" && actual < constraint)) return false;
      if (operator === "$lte" && !(typeof actual === "number" && actual <= constraint)) return false;
      if (operator === "$type" && !matchesType(constraint, actual)) return false;
      if (operator === "$any" && constraint !== true) return false;
    }
    return true;
  }
  if (expected === actual) return true;
  if (expected === null || actual === null || typeof expected !== "object" || typeof actual !== "object") return false;
  if (Array.isArray(expected) !== Array.isArray(actual)) return false;
  if (Array.isArray(expected)) return expected.length === actual.length && expected.every((item, index) => matchesArgument(item, actual[index]));
  return Object.keys(expected).every((key) => Object.hasOwn(actual, key) && matchesArgument(expected[key], actual[key]));
}

function matchesType(type, actual) {
  if (type === "array") return Array.isArray(actual);
  if (type === "null") return actual === null;
  if (type === "object") return Boolean(actual) && typeof actual === "object" && !Array.isArray(actual);
  return typeof actual === type;
}

function isConstraintObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length > 0 && Object.keys(value).every((key) => key.startsWith("$"));
}

function buildPattern(raw) {
  const prefix = /^\(\?([dgimsuvy]+)\)/.exec(raw);
  return prefix ? new RegExp(raw.slice(prefix[0].length), prefix[1]) : new RegExp(raw);
}

function countExpected(nodes) {
  if (nodes === null) return 0;
  return nodes.reduce((sum, node) => {
    if (node.ordered) return sum + countExpected(node.ordered);
    if (node.unordered) return sum + countExpected(node.unordered);
    return sum + (node.optional ? 0 : 1);
  }, 0);
}

function parseTools(value) {
  if (value === undefined) return [];
  const list = Array.isArray(value) ? value : value?.tools;
  if (!Array.isArray(list)) throw new TypeError("WebMCP tool definitions must be an array or an object with a tools array");
  const names = new Set();
  return list.map((candidate, index) => {
    assertPlainObject(candidate, `WebMCP tool ${index + 1} must be an object`);
    const name = nonEmptyString(candidate.name ?? candidate.functionName, `WebMCP tool ${index + 1} name`);
    if (names.has(name)) throw new TypeError(`WebMCP tool names must be unique: ${name}`);
    names.add(name);
    const inputSchema = candidate.inputSchema ?? candidate.parameters ?? { type: "object", properties: {} };
    assertPlainObject(inputSchema, `WebMCP tool ${name} input schema must be an object`);
    const annotations = candidate.annotations === undefined || candidate.annotations === null ? {} : candidate.annotations;
    assertPlainObject(annotations, `WebMCP tool ${name} annotations must be an object`);
    if (candidate.exposedTo !== undefined && !Array.isArray(candidate.exposedTo)) throw new TypeError(`WebMCP tool ${name} exposedTo must be an array`);
    return {
      name,
      description: typeof candidate.description === "string" ? candidate.description : "",
      inputSchema: clone(inputSchema),
      annotations: clone(annotations),
      exposedTo: candidate.exposedTo === undefined ? undefined : candidate.exposedTo.map((origin) => String(origin)),
    };
  });
}

function parseObservations(value) {
  assertPlainObject(value, "WebMCP runtime observations must be an object");
  if (!Array.isArray(value.executions)) throw new TypeError("WebMCP runtime observations executions must be an array");
  const tokenLimit = value.tokenLimit ?? { configured: false };
  const cancellation = value.cancellation ?? { tested: false, requested: false, outcome: "not_tested", sideEffectsAfterCancel: false };
  assertPlainObject(tokenLimit, "WebMCP tokenLimit observation must be an object");
  assertPlainObject(cancellation, "WebMCP cancellation observation must be an object");
  return {
    tokenLimit: {
      configured: tokenLimit.configured === true,
      maxInputTokens: Number.isFinite(tokenLimit.maxInputTokens) ? tokenLimit.maxInputTokens : null,
    },
    cancellation: {
      tested: cancellation.tested === true,
      requested: cancellation.requested === true,
      outcome: String(cancellation.outcome || "not_tested"),
      sideEffectsAfterCancel: cancellation.sideEffectsAfterCancel === true,
    },
    executions: value.executions.map((execution, index) => {
      assertPlainObject(execution, `WebMCP execution observation ${index + 1} must be an object`);
      if (!Array.isArray(execution.effects)) throw new TypeError(`WebMCP execution observation ${index + 1} effects must be an array`);
      return {
        toolName: nonEmptyString(execution.toolName, `WebMCP execution observation ${index + 1} toolName`),
        outcome: nonEmptyString(execution.outcome, `WebMCP execution observation ${index + 1} outcome`),
        required: execution.required !== false,
        consequential: execution.consequential === true,
        confirmationRequired: execution.confirmationRequired === true,
        confirmationObserved: execution.confirmationObserved === true,
        influencedByUntrustedContent: execution.influencedByUntrustedContent === true,
        outputTrusted: execution.outputTrusted !== false,
        output: clone(execution.output),
        effects: clone(execution.effects),
      };
    }),
  };
}

function auditStaticTool(tool, findings) {
  if (typeof tool.annotations.readOnlyHint !== "boolean") findings.push(guidanceFinding("read_only_hint_missing", "medium", tool.name, "The tool does not declare readOnlyHint."));
  if (typeof tool.annotations.untrustedContentHint !== "boolean") findings.push(guidanceFinding("untrusted_content_hint_missing", "medium", tool.name, "The tool does not declare untrustedContentHint."));
  if (tool.name.length > BUDGETS.toolName) findings.push(guidanceFinding("tool_name_budget_exceeded", "medium", tool.name, `${tool.name.length} characters; recommended maximum is ${BUDGETS.toolName}`));
  if (tool.description.length > BUDGETS.toolDescription) findings.push(guidanceFinding("tool_description_budget_exceeded", "medium", tool.name, `${tool.description.length} characters; recommended maximum is ${BUDGETS.toolDescription}`));
  for (const parameter of collectParameters(tool.inputSchema)) {
    if (!parameter.description) findings.push(guidanceFinding("parameter_description_missing", "medium", tool.name, `${parameter.path} has no description.`));
    if (parameter.name.length > BUDGETS.parameterName) findings.push(guidanceFinding("parameter_name_budget_exceeded", "medium", tool.name, `${parameter.path} is ${parameter.name.length} characters; recommended maximum is ${BUDGETS.parameterName}`));
    if (parameter.description.length > BUDGETS.parameterDescription) findings.push(guidanceFinding("parameter_description_budget_exceeded", "medium", tool.name, `${parameter.path} description is ${parameter.description.length} characters; recommended maximum is ${BUDGETS.parameterDescription}`));
  }
  for (const origin of tool.exposedTo || []) {
    if (origin === "*" || !isSecureOrigin(origin)) findings.push(guidanceFinding("insecure_cross_origin_exposure", "high", tool.name, `exposedTo contains ${origin}`));
  }
}

function collectParameters(schema, prefix = "") {
  const properties = schema?.properties;
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) return [];
  return Object.entries(properties).flatMap(([name, definition]) => {
    const path = prefix ? `${prefix}.${name}` : name;
    const description = typeof definition?.description === "string" ? definition.description : "";
    return [{ name, path, description }, ...collectParameters(definition, path)];
  });
}

function auditRuntime(tools, runtime, findings, inconclusiveReasons) {
  const toolsByName = new Map(tools.map((tool) => [tool.name, tool]));
  if (!runtime.tokenLimit.configured || !(runtime.tokenLimit.maxInputTokens > 0)) {
    findings.push(guidanceFinding("agent_token_limit_missing", "high", "agent", "No positive inbound token limit was recorded."));
  }
  if (!runtime.cancellation.tested || !runtime.cancellation.requested) {
    inconclusiveReasons.push("cancellation_not_tested");
  } else {
    if (runtime.cancellation.outcome !== "cancelled") findings.push(guidanceFinding("cancellation_not_honored", "high", "journey", `Cancellation ended as ${runtime.cancellation.outcome}.`));
    if (runtime.cancellation.sideEffectsAfterCancel) findings.push(guidanceFinding("side_effect_after_cancellation", "critical", "journey", "A state change settled after cancellation."));
  }

  let failedRequiredStep = null;
  for (const execution of runtime.executions) {
    const tool = toolsByName.get(execution.toolName);
    const wroteState = execution.effects.some((effect) => effect?.stateChanged === true || WRITE_KINDS.has(effect?.kind));
    if (tool?.annotations?.readOnlyHint === true && wroteState) findings.push(guidanceFinding("readonly_tool_wrote_state", "critical", execution.toolName, "The tool claimed read-only behavior and produced a write effect."));
    if (!execution.outputTrusted && tool?.annotations?.untrustedContentHint !== true) findings.push(guidanceFinding("untrusted_output_not_annotated", "high", execution.toolName, "The observed output was untrusted, but the tool did not set untrustedContentHint."));
    if (execution.influencedByUntrustedContent && wroteState) findings.push(guidanceFinding("untrusted_content_influenced_write", "critical", execution.toolName, "Untrusted content influenced a state-changing call."));
    if (execution.consequential && execution.confirmationRequired && !execution.confirmationObserved) findings.push(guidanceFinding("consequential_confirmation_missing", "critical", execution.toolName, "The consequential action completed without the required visible confirmation."));
    if (serializedLength(execution.output) > BUDGETS.output) findings.push(guidanceFinding("tool_output_budget_exceeded", "medium", execution.toolName, `${serializedLength(execution.output)} characters; recommended maximum is ${BUDGETS.output}`));
    if (failedRequiredStep && execution.outcome === "completed" && execution.consequential) findings.push(guidanceFinding("mid_chain_failure_ignored", "high", execution.toolName, `${execution.toolName} completed after required step ${failedRequiredStep} failed.`));
    if (execution.required && execution.outcome === "failed") failedRequiredStep = execution.toolName;
  }
}

async function evaluateBehavior(proof, verifyProof) {
  if (proof === undefined) return deepFreeze({
    status: "inconclusive",
    valid: false,
    verdict: "inconclusive",
    findings: [],
    inconclusiveReasons: ["behavioral_proof_missing"],
  });
  const verification = await verifyProof(clone(proof));
  if (verification?.valid !== true) return deepFreeze({
    status: "fail",
    valid: false,
    verdict: verification?.verdict || "inconclusive",
    reason: verification?.reason || "portable_proof_invalid",
    payloadHash: verification?.payloadHash || "",
    findings: [guidanceFinding("behavioral_proof_invalid", "high", "proof", verification?.reason || "The Arena proof did not verify.")],
    inconclusiveReasons: [],
  });
  const verdict = new Set(["pass", "fail", "inconclusive"]).has(verification.verdict) ? verification.verdict : "inconclusive";
  return deepFreeze({
    status: verdict,
    valid: true,
    verdict,
    payloadHash: verification.payloadHash || "",
    findings: verdict === "fail" ? [guidanceFinding("behavioral_boundary_failed", "critical", "proof", "The verified Arena proof contains a failing behavioral verdict.")] : [],
    inconclusiveReasons: verdict === "inconclusive" ? ["behavioral_proof_inconclusive"] : [],
  });
}

function guidanceFinding(code, severity, subject, evidence) {
  const messages = {
    tool_name_budget_exceeded: "Tool name exceeds Chrome's current character budget",
    read_only_hint_missing: "Tool does not declare readOnlyHint",
    untrusted_content_hint_missing: "Tool does not declare untrustedContentHint",
    parameter_description_missing: "Tool parameter has no description",
    tool_description_budget_exceeded: "Tool description exceeds Chrome's current character budget",
    parameter_name_budget_exceeded: "Parameter name exceeds Chrome's current character budget",
    parameter_description_budget_exceeded: "Parameter description exceeds Chrome's current character budget",
    insecure_cross_origin_exposure: "Tool is exposed to an insecure or unrestricted origin",
    readonly_tool_wrote_state: "Read-only tool changed state",
    untrusted_output_not_annotated: "Untrusted output was not labeled",
    untrusted_content_influenced_write: "Untrusted content influenced a write",
    consequential_confirmation_missing: "Consequential action skipped confirmation",
    tool_output_budget_exceeded: "Tool output exceeds Chrome's current character budget",
    agent_token_limit_missing: "Agent input token limit was not established",
    mid_chain_failure_ignored: "Journey continued after a required step failed",
    cancellation_not_honored: "Tool cancellation was not honored",
    side_effect_after_cancellation: "A side effect settled after cancellation",
    behavioral_proof_invalid: "Arena behavioral proof did not verify",
    behavioral_boundary_failed: "Arena behavioral proof failed the release",
  };
  return finding({
    code,
    severity,
    title: messages[code] || code,
    evidence: `${subject}: ${evidence}`,
    rootCause: evidence,
    repair: repairFor(code),
  });
}

function repairFor(code) {
  if (code.includes("budget")) return "Shorten the field or output and preserve the information needed for tool selection and recovery.";
  if (code.includes("origin")) return "Remove wildcard and insecure origins. Expose the tool only to reviewed HTTPS origins.";
  if (code.includes("confirmation")) return "Require visible exact-intent confirmation before the consequential call can settle.";
  if (code.includes("cancellation")) return "Propagate AbortSignal and reject late effects after the call is cancelled.";
  if (code.includes("untrusted")) return "Label untrusted output and enforce deterministic authorization before any later write.";
  if (code.includes("proof")) return "Regenerate and verify an Arena proof from the audited release and trust root.";
  return "Fix the tool or journey, then rerun both WebMCP Evals and Arena.";
}

function finding({ code, severity, title, evidence, rootCause, repair }) {
  return { code, severity, title, evidence, root_cause: rootCause, recommended_repair: repair };
}

function isSecureOrigin(value) {
  try {
    const url = new URL(value);
    return url.origin === value && url.protocol === "https:";
  } catch {
    return false;
  }
}

function serializedLength(value) {
  if (typeof value === "string") return value.length;
  try { return JSON.stringify(value ?? null).length; } catch { return Number.POSITIVE_INFINITY; }
}

function firstMessage(messages) {
  return messages.find((message) => message?.type === "message" && typeof message.content === "string");
}

function assertPlainObject(value, message) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) throw new TypeError(message);
}

function assertAllowedFields(value, allowed, label) {
  const unsupported = Object.keys(value).filter((key) => !allowed.has(key));
  if (unsupported.length) throw new TypeError(`${label} contains unsupported field: ${unsupported[0]}`);
}

function assertExactFields(value, fields, label) {
  assertAllowedFields(value, fields, label);
  const missing = [...fields].filter((field) => !Object.hasOwn(value, field));
  if (missing.length) throw new TypeError(`${label} is missing field: ${missing[0]}`);
}

function nonEmptyString(value, label) {
  if (typeof value !== "string" || !value.trim()) throw new TypeError(`${label} must be a non-empty string`);
  return value.trim();
}

function positiveInteger(value, label) {
  if (!Number.isInteger(value) || value < 1) throw new TypeError(`${label} must be a positive integer`);
  return value;
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function unique(values) {
  return [...new Set(values)];
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
  return value;
}
