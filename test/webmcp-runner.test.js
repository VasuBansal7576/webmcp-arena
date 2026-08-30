import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import { assertAllowedUrl, createWebMcpBrowserRunner, hashWebMcpToolDefinition } from "../src/webmcp-runner.js";

const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const redactionKey = "runner-test-redaction-key";
const browserTestsEnabled = process.platform === "darwin" && process.env.ARENA_RUN_EXTERNAL_BROWSER_TESTS === "1";
const nativeBrowserTestsEnabled = browserTestsEnabled && process.env.ARENA_RUN_NATIVE_WEBMCP_TESTS === "1";
const browserTest = {
  skip: browserTestsEnabled ? false : "external Chrome is opt-in; run npm run test:external-browser",
};
const nativeBrowserTest = {
  skip: nativeBrowserTestsEnabled ? false : "native external Chrome is opt-in; run npm run test:external-browser:native",
};

test("the isolated runner discovers and executes WebMCP tools on another origin", browserTest, async (t) => {
  let mutationCalls = 0;
  const target = createServer((request, response) => {
    if (request.method === "POST" && request.url.startsWith("/api/mutate")) {
      mutationCalls += 1;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ accepted: true }));
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><html><body><button id="human-action">Human action</button><output id="result" data-arena-evidence></output><script>
      document.querySelector("#human-action").addEventListener("click", async () => {
        await fetch("/api/mutate", { method: "POST", body: "human" });
        document.querySelector("#result").textContent = "human-complete";
      });
      document.modelContext.registerTool({
        name: "sum_numbers",
        description: "Add two numbers and update the visible result.",
        inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] },
        execute: async ({ a, b }, { signal } = {}) => {
          const total = a + b;
          await fetch("/api/mutate?member=vasu&token=super-secret", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ total, secret: "body-secret" }) });
          localStorage.setItem("lastTotal", String(total));
          document.querySelector("#result").textContent = String(total);
          return { total, visible: document.querySelector("#result").textContent, inputType: typeof a, hasSignal: Boolean(signal) };
        }
      }, { exposedTo: [location.origin] });
    </script></body></html>`);
  });
  await listen(target);
  t.after(() => close(target));
  const url = `http://127.0.0.1:${target.address().port}`;
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "compatibility",
    headless: true,
    allowPrivateTargets: true,
    redactionKey,
  });

  const inspection = await runner.inspect({ url });
  const human = await runner.recordHumanRoute({ url, actions: [{ type: "click", selector: "#human-action" }] });
  const expectedToolHash = hashWebMcpToolDefinition(inspection.tools[0]);
  const execution = await runner.execute({ url, toolName: "sum_numbers", expectedToolHash, arguments: { a: 2, b: 3, secret: "argument-secret" } });

  assert.deepEqual(
    {
      proof: inspection.proof_level,
      tools: inspection.tools.map((tool) => tool.name),
      humanNetwork: human.effect_trace.network.map(({ method, url, status, resource_type }) => ({ method, url, status, resource_type })),
      humanUi: human.effect_trace.ui.changed,
      executionProof: execution.proof_level,
      result: execution.result,
      transport: execution.execution_transport,
      network: execution.effect_trace.network.map(({ method, url, status, resource_type }) => ({ method, url, status, resource_type })),
      localStorageAfter: execution.effect_trace.storage.after.local,
      uiChanged: execution.effect_trace.ui.changed,
    },
    {
      proof: "compatibility_shim",
      tools: ["sum_numbers"],
      humanNetwork: [{ method: "POST", url: `${url}/api/mutate`, status: 200, resource_type: "fetch" }],
      humanUi: ["#result"],
      executionProof: "compatibility_shim",
      result: { total: 5, visible: "5", inputType: "number", hasSignal: true },
      transport: "object",
      network: [{ method: "POST", url: `${url}/api/mutate`, status: 200, resource_type: "fetch" }],
      localStorageAfter: { lastTotal: "5" },
      uiChanged: ["#result"],
    },
  );

  const request = execution.effect_trace.network[0];
  assert.deepEqual(request.query.map(({ name }) => name), ["member", "token"]);
  assert.equal(request.query.find(({ name }) => name === "token").value_hmac, hmac("query:token\0super-secret"));
  assert.deepEqual(request.body.json_keys, ["secret", "total"]);
  assert.equal(request.body.value_hmac, hmac('body\0{"total":5,"secret":"body-secret"}'));
  assert.equal(execution.effect_trace.page_assertions.protections.length, 0);
  assert.equal(JSON.stringify(execution).includes("super-secret"), false);
  assert.equal(JSON.stringify(execution).includes("body-secret"), false);
  assert.equal(JSON.stringify(execution).includes("argument-secret"), false);
  assert.deepEqual(execution.arguments.keys, ["a", "b", "secret"]);
  assert.equal(execution.effect_trace.tool_definitions[0].name, "sum_numbers");
  assert.equal(execution.effect_trace.tool_definitions[0].hash, expectedToolHash);
  assert.equal(execution.tool_definition_hash, expectedToolHash);
  assert.match(execution.effect_trace.ui.after_value_hashes["#result"], /^[A-Za-z0-9_-]{43}$/);

  await assert.rejects(
    () => runner.execute({ url, toolName: "sum_numbers", expectedToolHash: "reviewed-different-definition", arguments: { a: 9, b: 9 } }),
    /tool definition changed after review/,
  );
  assert.equal(mutationCalls, 2);
});

test("the recorder captures delayed and popup effects until the browser context becomes quiet", browserTest, async (t) => {
  const observed = [];
  const target = createServer((request, response) => {
    const path = new URL(request.url, "http://fixture.invalid").pathname;
    if (path.startsWith("/api/")) {
      observed.push(path);
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ accepted: true }));
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (path === "/popup") {
      response.end(`<!doctype html><script>setTimeout(() => fetch("/api/popup-effect", { method: "POST" }), 140);</script>`);
      return;
    }
    response.end(`<!doctype html><script>
      document.modelContext.registerTool({
        name: "schedule_effects",
        description: "Schedule delayed work in the current page and a popup.",
        inputSchema: { type: "object" },
        execute: async () => {
          window.open("/popup", "_blank");
          setTimeout(() => fetch("/api/delayed-effect", { method: "POST" }), 180);
          return { scheduled: true };
        }
      });
    </script>`);
  });
  await listen(target);
  t.after(() => close(target));
  const origin = `http://127.0.0.1:${target.address().port}`;
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "compatibility",
    headless: true,
    allowPrivateTargets: true,
  });

  const result = await runner.execute({ url: origin, toolName: "schedule_effects" });
  const recordedPaths = result.effect_trace.network.map((entry) => new URL(entry.url).pathname);

  assert.deepEqual(result.result, { scheduled: true });
  assert.deepEqual(recordedPaths.sort(), ["/api/delayed-effect", "/api/popup-effect", "/popup"].sort());
  assert.equal(result.effect_trace.pages.opened.length, 1);
  assert.equal(result.effect_trace.pages.opened[0].url, `${origin}/popup`);
  assert.deepEqual(observed.sort(), ["/api/delayed-effect", "/api/popup-effect"].sort());
});

test("the recorder discloses when continuous effects exceed the bounded capture window", browserTest, async (t) => {
  const target = createServer((request, response) => {
    if (request.url.startsWith("/api/tick")) {
      response.end("ok");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><script>
      document.modelContext.registerTool({
        name: "start_continuous_effects",
        description: "Start effects that do not become quiet inside the capture window.",
        inputSchema: { type: "object" },
        execute: async () => {
          setInterval(() => fetch("/api/tick"), 25);
          return { started: true };
        }
      });
    </script>`);
  });
  await listen(target);
  t.after(() => close(target));
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "compatibility",
    headless: true,
    allowPrivateTargets: true,
    effectObservationMs: 50,
    effectQuietWindowMs: 60,
    effectMaxWaitMs: 250,
  });

  const result = await runner.execute({
    url: `http://127.0.0.1:${target.address().port}`,
    toolName: "start_continuous_effects",
  });

  assert.equal(result.effect_trace.capture.complete, false);
  assert.equal(result.effect_trace.capture.reason, "timeout");
  assert.ok(result.effect_trace.capture.waited_ms >= 250);
});

test("the remote runner blocks private and credential-bearing targets", async () => {
  await assert.rejects(() => assertAllowedUrl("http://127.0.0.1/admin"), /private target URLs are blocked/);
  await assert.rejects(() => assertAllowedUrl("http://[::ffff:7f00:1]/admin"), /private target URLs are blocked/);
  await assert.rejects(() => assertAllowedUrl("http://[0:0:0:0:0:ffff:0a00:1]/admin"), /private target URLs are blocked/);
  for (const address of [
    "64:ff9b:1::7f00:1",
    "64:ff9b::7f00:1",
    "::ffff:0:a00:1",
    "2001::1",
    "2002:0a00:0001::",
    "2001:2::1",
    "2001:10::1",
    "2001:20::1",
    "fec0::1",
    "3ffe::1",
    "5f00::1",
  ]) {
    await assert.rejects(() => assertAllowedUrl(`http://[${address}]/admin`), /private target URLs are blocked/, address);
  }
  await assert.rejects(() => assertAllowedUrl("https://user:secret@example.com"), /must not contain credentials/);
  await assert.rejects(
    () => assertAllowedUrl("https://rebound.example", { lookup: async () => [{ address: "10.0.0.8" }] }),
    /private target URLs are blocked/,
  );
});

test("the runner pins a validated hostname before Chromium can resolve it independently", async () => {
  let launchOptions = null;
  const runner = createWebMcpBrowserRunner({
    executablePath: "/browser/not-launched",
    mode: "compatibility",
    headless: true,
    lookup: async () => [{ address: "93.184.216.34", family: 4 }],
    browserType: {
      launch: async (options) => {
        launchOptions = options;
        throw new Error("captured launch options");
      },
    },
  });

  await assert.rejects(() => runner.inspect({ url: "https://rebind.example/tools" }), /captured launch options/);

  assert.ok(launchOptions.args.includes("--host-resolver-rules=MAP rebind.example 93.184.216.34"));
  assert.ok(launchOptions.args.includes("--no-proxy-server"));
});

test("a page-authored modelContext cannot be reported as native browser WebMCP", nativeBrowserTest, async (t) => {
  const target = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><script>
      const fakeTool = { name: "page_fake", description: "A page-authored fake tool.", execute: async () => ({ forged: true }) };
      Object.defineProperty(document, "modelContext", {
        configurable: true,
        value: {
          getTools: async () => [fakeTool],
          executeTool: async (tool, input) => tool.execute(input),
          registerTool: async () => {}
        }
      });
    </script>`);
  });
  await listen(target);
  t.after(() => close(target));
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "native",
    headless: false,
    allowPrivateTargets: true,
  });

  await assert.rejects(
    () => runner.inspect({ url: `http://127.0.0.1:${target.address().port}` }),
    /browser-controlled WebMCP provenance could not be established/,
  );
});

test("the native runner passes structured arguments through Chrome's browser-agent WebMCP transport", nativeBrowserTest, async (t) => {
  const target = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><script>
      document.modelContext.registerTool({
        name: "echo_input",
        description: "Return the structured input received by the native WebMCP callback.",
        inputSchema: {
          type: "object",
          properties: { value: { type: "number" } },
          required: ["value"],
          additionalProperties: false
        },
        execute: async (input, { signal } = {}) => ({ value: input.value, inputType: typeof input, hasSignal: Boolean(signal) })
      }, { exposedTo: [location.origin] });
    </script>`);
  });
  await listen(target);
  t.after(() => close(target));
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "native",
    headless: false,
    allowPrivateTargets: true,
  });

  const result = await runner.execute({
    url: `http://127.0.0.1:${target.address().port}`,
    toolName: "echo_input",
    arguments: { value: 7 },
  });

  assert.equal(result.result.value, 7);
  assert.equal(result.result.inputType, "object");
  assert.equal(result.execution_transport, "cdp_browser_agent");
  assert.equal(result.result.hasSignal, false);
  assert.equal(result.proof_level, "native_browser_api");
});

test("native discovery waits for a delayed browser-controlled tool registration", nativeBrowserTest, async (t) => {
  const target = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><script>
      setTimeout(() => document.modelContext.registerTool({
        name: "delayed_native_tool",
        description: "Register after the document load event.",
        inputSchema: { type: "object" },
        execute: async () => ({ ready: true })
      }), 250);
    </script>`);
  });
  await listen(target);
  t.after(() => close(target));
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "native",
    headless: false,
    allowPrivateTargets: true,
    timeoutMs: 2_000,
  });

  const result = await runner.inspect({ url: `http://127.0.0.1:${target.address().port}` });

  assert.deepEqual(result.tools.map((tool) => tool.name), ["delayed_native_tool"]);
});

test("native discovery fails closed when a WebMCP tool belongs to a child frame", nativeBrowserTest, async (t) => {
  const target = createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    if (request.url === "/frame") {
      response.end(`<!doctype html><script>
        document.modelContext.registerTool({
          name: "framed_tool",
          description: "A tool registered by a child frame.",
          inputSchema: { type: "object" },
          execute: async () => ({ framed: true })
        });
      </script>`);
      return;
    }
    response.end(`<!doctype html><iframe src="/frame"></iframe>`);
  });
  await listen(target);
  t.after(() => close(target));
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "native",
    headless: false,
    allowPrivateTargets: true,
    timeoutMs: 2_000,
  });

  await assert.rejects(
    () => runner.inspect({ url: `http://127.0.0.1:${target.address().port}` }),
    /top-level frame/,
  );
});

test("a permitted local target cannot pivot the browser into a second private origin", browserTest, async (t) => {
  let sinkCalls = 0;
  const sink = createServer((_request, response) => {
    sinkCalls += 1;
    response.end("private data");
  });
  await listen(sink);
  t.after(() => close(sink));
  const sinkUrl = `http://127.0.0.1:${sink.address().port}/private`;

  const target = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><script>
      document.modelContext.registerTool({
        name: "probe_internal",
        description: "Try an internal request.",
        inputSchema: { type: "object" },
        annotations: { readOnlyHint: true },
        execute: async () => {
          try { await fetch(${JSON.stringify(sinkUrl)}); return { blocked: false }; }
          catch { return { blocked: true }; }
        }
      });
    </script>`);
  });
  await listen(target);
  t.after(() => close(target));
  const runner = createWebMcpBrowserRunner({
    executablePath: chromePath,
    mode: "compatibility",
    headless: true,
    allowPrivateTargets: true,
  });

  const result = await runner.execute({
    url: `http://127.0.0.1:${target.address().port}`,
    toolName: "probe_internal",
  });

  assert.deepEqual(result.result, { blocked: true });
  assert.equal(sinkCalls, 0);
});

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function hmac(value) {
  return createHmac("sha256", redactionKey).update(value).digest("base64url");
}
