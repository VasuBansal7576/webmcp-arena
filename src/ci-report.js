export function buildCiArtifacts({ reports = [] } = {}) {
  if (!Array.isArray(reports)) throw new Error("reports must be an array");
  const findings = reports.flatMap((report) => [
    ...(report.findings || []).map((finding) => ({ report, finding })),
    ...(report.verdict === "inconclusive" ? [{
      report,
      finding: {
        code: "arena_inconclusive",
        severity: "high",
        title: "Arena could not establish the security boundary",
        evidence: (report.inconclusive_reasons || ["required evidence is missing"]).join(", "),
        root_cause: "Required audit evidence was incomplete.",
        recommended_repair: "Restore the missing recorder, reset, or authoritative evidence source and rerun the audit.",
      },
    }] : []),
  ]);
  const summary = {
    passed: reports.length > 0 && findings.length === 0 && reports.every((report) => report.verdict === "pass"),
    reports: reports.length,
    findings: findings.length,
    critical: findings.filter(({ finding }) => finding.severity === "critical").length,
    high: findings.filter(({ finding }) => finding.severity === "high").length,
    medium: findings.filter(({ finding }) => finding.severity === "medium").length,
    low: findings.filter(({ finding }) => finding.severity === "low").length,
  };
  return {
    summary,
    json: { kind: "arena.ci_report", version: 1, summary, reports: structuredClone(reports) },
    junit: buildJunit(reports),
    sarif: buildSarif(findings),
  };
}

function buildJunit(reports) {
  const cases = reports.map((report) => {
    const name = report.contract?.tool_name || report.id || "boundary-audit";
    if (report.verdict === "inconclusive") {
      const message = (report.inconclusive_reasons || ["required evidence is missing"]).join(", ");
      return `<testcase classname="arena.boundary" name="${xml(name)}"><error message="Arena audit was inconclusive">${xml(message)}</error></testcase>`;
    }
    const failures = report.findings || [];
    if (!failures.length) return `<testcase classname="arena.boundary" name="${xml(name)}"/>`;
    const message = failures.map((finding) => `[${finding.severity}] ${finding.title}: ${finding.evidence || finding.root_cause || finding.code}`).join("\n");
    return `<testcase classname="arena.boundary" name="${xml(name)}"><failure message="${xml(`${failures.length} behavioral finding(s)`)}">${xml(message)}</failure></testcase>`;
  }).join("");
  const failedReports = reports.filter((report) => report.findings?.length).length;
  const errorReports = reports.filter((report) => report.verdict === "inconclusive").length;
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Arena Boundary Audits" tests="${reports.length}" failures="${failedReports}" errors="${errorReports}">${cases}</testsuite>`;
}

function buildSarif(findings) {
  const rules = [...new Map(findings.map(({ finding }) => [finding.code, {
    id: finding.code,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.root_cause || finding.title },
    help: { text: finding.recommended_repair || "Review the behavioral divergence." },
  }])).values()];
  const results = findings.map(({ report, finding }) => ({
    ruleId: finding.code,
    level: sarifLevel(finding.severity),
    message: { text: `${finding.title}: ${finding.evidence || finding.root_cause || finding.code}` },
    properties: { audit_id: report.id || null, tool_name: report.contract?.tool_name || null, severity: finding.severity },
  }));
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [{ tool: { driver: { name: "Arena", informationUri: "https://webmcp.dev", rules } }, results }],
  };
}

function sarifLevel(severity) {
  if (["critical", "high"].includes(severity)) return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function xml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
}
