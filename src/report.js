export function buildReport({ scan, logReport, missionReport, contractDir }) {
  const staticFindings = (scan?.checks || [])
    .filter((item) => !item.pass)
    .map((item) => ({ id: item.id, severity: item.severity, message: item.message, taxonomy: item.taxonomy, framing: item.framing, metrics: item.metrics, source: "static" }));
  const logFindings = (logReport?.findings || []).map((item) => ({ ...item, source: "logs" }));
  const missionFindings = (missionReport?.results || [])
    .filter((item) => item.status !== "passed")
    .map((item) => ({ id: item.mission, severity: "high", message: item.summary, taxonomy: "AgentContract::SyntheticMissionFailure", source: "missions" }));
  return {
    generated_at: new Date().toISOString(),
    score: scan?.readiness?.score ?? null,
    level: scan?.readiness?.level ?? "unknown",
    url: scan?.source?.url ?? null,
    contractDir,
    findings: [...logFindings, ...missionFindings, ...staticFindings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
    scan,
    logReport,
    missionReport,
  };
}

export function renderMarkdown(report) {
  const findings = report.findings.length
    ? report.findings.map((item) => `- **${item.severity}** \`${item.source}:${item.id}\` ${item.taxonomy ? `\`${item.taxonomy}\` ` : ""}${item.message}${item.framing ? ` ${item.framing}` : ""}`).join("\n")
    : "- No findings.";
  const missions = report.missionReport?.results?.length
    ? report.missionReport.results.map((item) => `- **${item.status}** \`${item.mission}\` ${item.summary}${item.screenshot_path ? ` (screenshot: ${item.screenshot_path})` : ""}`).join("\n")
    : "- Not run.";
  return `# Agent Contract Report

- URL: ${report.url || "n/a"}
- Score: ${report.score ?? "n/a"} (${report.level})
- Contract: ${report.contractDir || "not written"}
- Generated: ${report.generated_at}

## Findings

${findings}

## Synthetic Missions

${missions}
`;
}

export function renderHtml(report) {
  const rows = report.findings.length
    ? report.findings.map((item) => `<tr><td>${esc(item.severity)}</td><td>${esc(item.source)}</td><td><code>${esc(item.id)}</code></td><td>${esc(item.taxonomy || "")}</td><td>${esc(item.message)}${item.framing ? `<p class="muted">${esc(item.framing)}</p>` : ""}</td></tr>`).join("")
    : `<tr><td colspan="5">No findings.</td></tr>`;
  const checks = (report.scan?.checks || []).map((item) => `<li class="${item.pass ? "pass" : "fail"}">${item.pass ? "PASS" : "FAIL"} ${esc(item.id)} — ${esc(item.message)}</li>`).join("");
  const missions = (report.missionReport?.results || []).map((item) => `<li class="${item.status === "passed" ? "pass" : "fail"}">${esc(item.status.toUpperCase())} ${esc(item.mission)} — ${esc(item.summary)}${item.screenshot_path ? ` <span class="muted">screenshot: ${esc(item.screenshot_path)}</span>` : ""}</li>`).join("") || "<li>Not run.</li>";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agent Contract Report</title>
  <style>
    body { font: 15px/1.5 system-ui, sans-serif; margin: 32px; color: #17202a; }
    main { max-width: 1040px; margin: 0 auto; }
    h1 { margin-bottom: 4px; }
    .score { font-size: 48px; font-weight: 800; margin: 16px 0; }
    table { border-collapse: collapse; width: 100%; margin-top: 16px; }
    th, td { border-bottom: 1px solid #d8dee4; padding: 10px; text-align: left; vertical-align: top; }
    code { background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }
    .pass { color: #116329; }
    .fail { color: #b42318; }
    .muted { color: #667085; }
  </style>
</head>
<body>
<main>
  <h1>Agent Contract Report</h1>
  <p class="muted">${esc(report.url || "n/a")} · generated ${esc(report.generated_at)}</p>
  <div class="score">${esc(report.score ?? "n/a")} <span class="muted">${esc(report.level)}</span></div>
  <h2>Findings</h2>
  <table><thead><tr><th>Severity</th><th>Source</th><th>ID</th><th>Taxonomy</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table>
  <h2>Static Checks</h2>
  <ul>${checks}</ul>
  <h2>Synthetic Missions</h2>
  <ul>${missions}</ul>
</main>
</body>
</html>
`;
}

function severityRank(value) {
  return { low: 1, medium: 2, high: 3, critical: 4 }[value] || 0;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}
