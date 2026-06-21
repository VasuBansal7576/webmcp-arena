import test from "node:test";
import assert from "node:assert/strict";

import { analyzeLogs, identifyBot, parseLogLine } from "../src/logs.js";

test("parseLogLine parses nginx bot access log lines", () => {
  const row = parseLogLine(
    '203.0.113.7 - - [21/Jun/2026:12:00:00 +0000] "GET /pricing?utm=agent HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"',
  );

  assert.equal(row.source, "nginx");
  assert.equal(row.ip, "203.0.113.7");
  assert.equal(row.method, "GET");
  assert.equal(row.path, "/pricing");
  assert.equal(row.status, 200);
  assert.equal(row.bytes, 512);
  assert.equal(identifyBot(row.userAgent), "gptbot");
});

test("parseLogLine parses CloudFront bot access log lines", () => {
  const row = parseLogLine(
    "2026-06-21\t12:05:00\tIAD89\t1234\t198.51.100.9\tGET\texample.com\t/docs\t403\t-\tClaudeBot%2F1.0%20%28https%3A%2F%2Fwww.anthropic.com%2F%29",
  );

  assert.equal(row.source, "cloudfront");
  assert.equal(row.host, "example.com");
  assert.equal(row.ip, "198.51.100.9");
  assert.equal(row.path, "/docs");
  assert.equal(row.status, 403);
  assert.equal(row.bytes, 1234);
  assert.equal(row.userAgent, "ClaudeBot/1.0 (https://www.anthropic.com/)");
  assert.equal(identifyBot(row.userAgent), "claudebot");
});

test("analyzeLogs reports agent empty HTML, auth wall, and rate limit findings", () => {
  const logText = [
    nginx("/thin", 200, 120, "GPTBot/1.0"),
    nginx("/thin?variant=b", 200, 90, "GPTBot/1.0"),
    cloudfront("/thin", 200, 110, "GPTBot%2F1.0"),
    nginx("/private", 403, 1024, "ClaudeBot/1.0"),
    cloudfront("/private", 403, 1024, "ClaudeBot%2F1.0"),
    nginx("/limited", 429, 32, "PerplexityBot/1.0"),
    nginx("/human", 200, 1200, "Mozilla/5.0"),
  ].join("\n");

  const report = analyzeLogs(logText, { emptyHtmlBytes: 200 });
  const thin = report.pages.find((page) => page.path === "/thin");
  const findingIds = report.findings.map((finding) => finding.id);

  assert.equal(report.total_requests, 7);
  assert.equal(report.total_agent_requests, 6);
  assert.equal(report.bots.gptbot.agentRequests, 3);
  assert.equal(thin.agentRequests, 3);
  assert.equal(thin.okResponses, 3);
  assert.equal(thin.emptyHtmlRate, 1);
  assert.equal(thin.bots.gptbot, 3);
  assert.ok(findingIds.includes("empty_html_to_agents"));
  assert.ok(findingIds.includes("agent_auth_wall"));
  assert.ok(findingIds.includes("agent_rate_limited"));
});

function nginx(path, status, bytes, userAgent) {
  return `203.0.113.1 - - [21/Jun/2026:12:00:00 +0000] "GET ${path} HTTP/1.1" ${status} ${bytes} "-" "${userAgent}"`;
}

function cloudfront(path, status, bytes, userAgent) {
  return `2026-06-21\t12:00:00\tIAD89\t${bytes}\t203.0.113.2\tGET\texample.com\t${path}\t${status}\t-\t${userAgent}`;
}
