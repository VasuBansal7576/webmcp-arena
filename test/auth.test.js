import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { loadAuthProfile } from "../src/auth.js";
import { scanUrl } from "../src/scanner.js";
import { runSyntheticMissions } from "../src/missions.js";

const chromePath = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

test("loadAuthProfile rejects raw header secrets and redacts env-backed values", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-auth-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const raw = join(dir, "raw.json");
  const envBacked = join(dir, "env.json");
  await writeFile(raw, JSON.stringify({ headers: { authorization: "Bearer raw-secret" } }));
  await writeFile(envBacked, JSON.stringify({ name: "private", headers: { authorization: { env: "PRIVATE_TOKEN", prefix: "Bearer " } } }));

  await assert.rejects(() => loadAuthProfile(raw, { PRIVATE_TOKEN: "secret" }), /must reference env/);
  const auth = await loadAuthProfile(envBacked, { PRIVATE_TOKEN: "secret" });
  assert.equal(auth.headers.authorization, "Bearer secret");
  assert.deepEqual(auth.audit, {
    name: "private",
    headers: ["authorization"],
    cookies: [],
    env: ["PRIVATE_TOKEN"],
  });
  assert.doesNotMatch(JSON.stringify(auth.audit), /secret/);
});

test("auth profile headers reach scanner fetches and browser missions without leaking secrets", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "agent-contract-auth-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const profilePath = join(dir, "auth.json");
  await writeFile(profilePath, JSON.stringify({ name: "private", headers: { authorization: { env: "PRIVATE_TOKEN", prefix: "Bearer " } } }));
  const auth = await loadAuthProfile(profilePath, { PRIVATE_TOKEN: "secret-token" });

  const server = createServer((request, response) => {
    const ok = request.headers.authorization === "Bearer secret-token";
    const path = new URL(request.url, "http://127.0.0.1").pathname;
    const send = (status, body, type = "text/html") => {
      response.writeHead(status, { "content-type": type });
      response.end(body);
    };
    if (!ok) return send(401, "auth required");
    if (path === "/") return send(200, home());
    if (path === "/pricing") return send(200, "<h1>Pricing</h1><p>Startup $49 per repo</p>");
    if (path === "/docs/quickstart") return send(200, "<h1>API Quickstart</h1><p>GET /v1/contracts</p>");
    if (path === "/robots.txt") return send(200, "User-agent: *\nAllow: /\n", "text/plain");
    if (path === "/sitemap.xml") return send(200, "<urlset><url><loc>/</loc></url></urlset>", "application/xml");
    if (path === "/llms.txt") return send(200, "# Private app\n", "text/plain");
    return send(404, "missing");
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(() => resolve())));
  const baseUrl = `http://127.0.0.1:${server.address().port}/`;

  const scan = await scanUrl(baseUrl, { auth, linkLimit: 2 });
  assert.equal(scan.readiness.score, 100);
  assert.equal(scan.auth_profile.name, "private");
  assert.doesNotMatch(JSON.stringify(scan), /secret-token/);

  const missions = await runSyntheticMissions(baseUrl, {
    auth,
    browserExecutablePath: chromePath,
    cacheDir: join(dir, "cache"),
    contentHash: scan.source.content_hash,
  });
  assert.equal(missions.failed, 0);
  assert.equal(missions.auth_profile.name, "private");
  assert.doesNotMatch(JSON.stringify(missions), /secret-token/);
});

function home() {
  return `<!doctype html><html><head>
    <title>Private Agent Contract OS</title>
    <script type="application/ld+json">{"@context":"https://schema.org","@type":"SoftwareApplication"}</script>
  </head><body>
    <h1>Private Agent Contract OS</h1>
    <p>Private Agent Contract OS validates authenticated docs, pricing, and API quickstarts for enterprise private runners.</p>
    <a href="/pricing">Pricing</a>
    <a href="/docs/quickstart">API quickstart</a>
  </body></html>`;
}
