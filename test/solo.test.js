import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { createSoloServer } from "../scripts/solo-server.js";

test("solo server scans a URL and writes a fix pack", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-solo-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const target = createServer((request, response) => {
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    response.writeHead(200, { "content-type": path.endsWith(".xml") ? "application/xml" : "text/html" });
    response.end(path === "/" ? "<html><body><h1>Solo Target</h1><p>Readable server-rendered page for agents.</p></body></html>" : "ok");
  });
  await listen(target);
  t.after(() => close(target));

  const solo = createSoloServer({ fixPackRoot: join(dir, "fix-packs") });
  await listen(solo);
  t.after(() => close(solo));

  const body = new URLSearchParams({ url: `http://127.0.0.1:${target.address().port}/` });
  const response = await fetch(`http://127.0.0.1:${solo.address().port}/scan`, { method: "POST", body });
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.match(html, /Agent Contract Solo Scan/);
  assert.match(html, /Fix pack:/);
  assert.match(html, /webmcp_registration/);
});

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}
