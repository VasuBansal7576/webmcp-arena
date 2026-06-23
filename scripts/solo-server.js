import { createServer } from "node:http";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { scanUrl } from "../src/scanner.js";
import { writeFixPack } from "../src/fixpack.js";

export function createSoloServer({ fixPackRoot = ".tmp/solo/fix-packs" } = {}) {
  return createServer(async (request, response) => {
    try {
      const route = new URL(request.url, "http://127.0.0.1");
      if (request.method === "GET" && route.pathname === "/") return html(response, page());
      if (request.method === "POST" && route.pathname === "/scan") {
        const body = await readBody(request);
        const target = new URL(new URLSearchParams(body).get("url"));
        if (!["http:", "https:"].includes(target.protocol)) throw new Error("URL must start with http:// or https://");
        const scan = await scanUrl(target.href, { linkLimit: 6, timeoutMs: 10000 });
        const outDir = join(fixPackRoot, target.hostname.replace(/[^a-z0-9.-]/gi, "_"));
        const fixPack = await writeFixPack(outDir, { scan });
        return html(response, page({ scan, fixPack }));
      }
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("not found");
    } catch (error) {
      response.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      response.end(page({ error: error.message }));
    }
  });
}

function page({ scan, fixPack, error } = {}) {
  const findings = scan?.checks?.filter((item) => !item.pass).map((item) => `<li><b>${esc(item.severity)}</b> ${esc(item.id)}: ${esc(item.message)}</li>`).join("") || "";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Contract Solo Scan</title>
  <style>
    body { font: 16px/1.5 system-ui, sans-serif; max-width: 880px; margin: 40px auto; padding: 0 20px; color: #17202a; }
    input, button { font: inherit; padding: 10px 12px; }
    input { width: min(620px, 100%); }
    button { cursor: pointer; }
    .error { color: #b42318; }
    .score { font-size: 40px; font-weight: 800; margin: 24px 0 8px; }
    code { background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>Agent Contract Solo Scan</h1>
  <form method="post" action="/scan">
    <input name="url" type="url" required placeholder="https://example.com">
    <button>Scan</button>
  </form>
  ${error ? `<p class="error">${esc(error)}</p>` : ""}
  ${scan ? `<section>
    <div class="score">${scan.readiness.score} ${esc(scan.readiness.level)}</div>
    <p>Fix pack: <code>${esc(fixPack.outDir)}</code></p>
    <h2>Findings</h2>
    <ul>${findings || "<li>No findings.</li>"}</ul>
  </section>` : ""}
</body>
</html>`;
}

function html(response, body) {
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(body);
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    let body = "";
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 4173);
  createSoloServer().listen(port, "127.0.0.1", () => {
    console.log(`agent-contract solo: http://127.0.0.1:${port}`);
  });
}
