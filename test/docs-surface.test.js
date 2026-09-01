import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("the docs separate tutorial, explanation, reference, use cases, and essays", async () => {
  const files = [
    "app/docs/page.tsx",
    "app/docs/quickstart/page.tsx",
    "app/docs/concepts/human-agent-boundary/page.tsx",
    "app/docs/reference/proof-format/page.tsx",
    "app/docs/reference/webmcp-tools/page.tsx",
    "app/docs/reference/webmcp-evals/page.tsx",
    "app/docs/reference/error-codes/page.tsx",
    "app/use-cases/page.tsx",
    "app/use-cases/document-sharing/page.tsx",
    "app/blog/page.tsx",
    "app/blog/why-captchas-are-the-wrong-boundary/page.tsx",
    "app/blog/webmcp-tools-need-behavioral-proof/page.tsx",
  ];
  for (const file of files) {
    const source = await readFile(new URL(file, root), "utf8");
    assert.match(source, /DocsShell/);
    assert.doesNotMatch(source, /lorem ipsum|TODO|coming soon/i);
  }
  const shell = await readFile(new URL("components/docs-shell.tsx", root), "utf8");
  assert.match(shell, /href="\/docs\/reference\/webmcp-evals"/);
});

test("agents receive a concise index, full context, schemas, and stable error vocabulary", async () => {
  const llms = await readFile(new URL("public/llms.txt", root), "utf8");
  const full = await readFile(new URL("public/llms-full.txt", root), "utf8");
  const schema = JSON.parse(await readFile(new URL("public/schemas/arena-proof-v1.schema.json", root), "utf8"));
  const observationSchema = JSON.parse(await readFile(new URL("public/schemas/arena-webmcp-eval-observations-v1.schema.json", root), "utf8"));
  const catalog = await readFile(new URL("src/docs-catalog.js", root), "utf8");

  assert.match(llms, /https:\/\/webmcp-arena\.zippy17\.chatgpt\.site\/docs\/quickstart/);
  assert.ok(Buffer.byteLength(llms) < 8_192);
  assert.match(full, /registered WebMCP callback/);
  assert.equal(schema.$id, "https://webmcp-arena.zippy17.chatgpt.site/schemas/arena-proof-v1.schema.json");
  assert.deepEqual(schema.required.includes("evidence"), true);
  assert.equal(observationSchema.$id, "https://webmcp-arena.zippy17.chatgpt.site/schemas/arena-webmcp-eval-observations-v1.schema.json");
  assert.match(llms, /\/docs\/reference\/webmcp-evals/);
  assert.match(llms, /arena-webmcp-eval-observations-v1\.schema\.json/);
  assert.match(full, /arena eval --evals/);
  assert.match(catalog, /GoogleChromeLabs webmcp-evals/);
  assert.match(catalog, /invocation_binding_mismatch/);
  assert.match(catalog, /invocation_already_consumed/);
});
