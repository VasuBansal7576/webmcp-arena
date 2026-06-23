import assert from "node:assert/strict";
import test from "node:test";

import { buildReport, renderHtml, renderMarkdown } from "../src/report.js";

test("reports include finding taxonomy and framing", () => {
  const report = buildReport({
    scan: {
      source: { url: "https://example.test" },
      readiness: { score: 70, level: "silver" },
      checks: [{
        id: "js_only_content",
        pass: false,
        severity: "critical",
        message: "Page has low readable HTML and relies on scripts",
        taxonomy: "AWI::DOMComplexity",
        framing: "Research framing: DOM-heavy pages increase agent navigation cost.",
      }],
    },
  });

  assert.match(renderMarkdown(report), /AWI::DOMComplexity/);
  assert.match(renderMarkdown(report), /Research framing/);
  assert.match(renderHtml(report), /AWI::DOMComplexity/);
});
