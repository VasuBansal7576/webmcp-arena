import { join } from "node:path";
import { nowIso, writeJson, writeText } from "./util.js";

export const ENTERPRISE_POLICY_PACK = {
  name: "Enterprise Agent Contract Policy",
  version: "1.0.0",
  controls: [
    { id: "robots_txt_present", require: "surface.website.has_robots_txt", equals: true, severity: "high" },
    { id: "sitemap_present", require: "surface.website.has_sitemap", equals: true, severity: "medium" },
    { id: "llms_txt_present", require: "surface.website.has_llms_txt", equals: true, severity: "high" },
    { id: "readiness_score", require: "readiness.score", min: 80, severity: "high" },
    { id: "no_critical_gaps", require: "readiness.critical_gaps.length", equals: 0, severity: "critical" },
    { id: "synthetic_missions_pass", require: "missions.failed", equals: 0, severity: "critical" },
    { id: "cup_user_consent", require: "cup.user_consent.violations.length", equals: 0, severity: "high" },
    { id: "mcp_spec_version_compliant", require: "surface.mcp.spec_version_compliant", equals: true, severity: "medium" },
    { id: "api_error_examples", require: "surface.api.has_error_examples", equals: true, severity: "medium" },
    { id: "api_auth_documented", require: "surface.api.auth_methods.length", min: 1, severity: "medium" },
  ],
};

export function evaluatePolicyPack(contract, policy = ENTERPRISE_POLICY_PACK) {
  const controls = policy.controls.map((control) => {
    const actual = get(contract, control.require);
    const passed = passes(actual, control);
    return {
      id: control.id,
      severity: control.severity || "medium",
      status: passed ? "passed" : "failed",
      require: control.require,
      actual,
      expected: expected(control),
    };
  });
  return {
    generated_at: nowIso(),
    policy: { name: policy.name, version: policy.version || "custom" },
    source: contract.source?.url || null,
    status: controls.every((control) => control.status === "passed") ? "passed" : "failed",
    mcp_compliance: mcpCompliance(contract),
    controls,
  };
}

export async function writePolicyAudit(outDir, contract, policy = ENTERPRISE_POLICY_PACK) {
  const audit = evaluatePolicyPack(contract, policy);
  const files = ["policy-audit.json", "compliance-report.md"];
  await writeJson(join(outDir, files[0]), audit);
  await writeText(join(outDir, files[1]), renderComplianceMarkdown(audit));
  return { ...audit, outDir, files };
}

export function renderComplianceMarkdown(audit) {
  const rows = audit.controls.map((control) => `| ${control.status} | ${control.severity} | ${control.id} | ${control.require} | ${String(control.actual)} | ${control.expected} |`).join("\n");
  const mcp = audit.mcp_compliance;
  return `# ${audit.policy.name}

- Source: ${audit.source || "n/a"}
- Status: ${audit.status}
- Generated: ${audit.generated_at}

## MCP Compliance

- Spec version declared: ${mcp.spec_version_declared || "n/a"}
- Current spec: ${mcp.current_spec}
- Status: ${mcp.status}
- Compliance delta: ${mcp.compliance_delta}
- Missing: ${mcp.missing.length ? mcp.missing.join(", ") : "none"}

| Status | Severity | Control | Evidence Path | Actual | Expected |
|---|---:|---|---|---:|---|
${rows}
`;
}

function mcpCompliance(contract) {
  const mcp = contract.surface?.mcp || {};
  const currentSpec = "2025-06-18";
  if (!mcp.discovered) {
    return {
      spec_version_declared: mcp.spec_version || "",
      current_spec: currentSpec,
      status: "not_applicable",
      compliance_delta: 0,
      missing: [],
    };
  }
  const missing = [];
  if (!mcp.spec_version) missing.push("spec_version");
  if (mcp.spec_version && mcp.spec_version !== currentSpec) missing.push("current_spec_version");
  if (mcp.spec_version_compliant === false) missing.push("spec_version_compliant");
  return {
    spec_version_declared: mcp.spec_version || "",
    current_spec: currentSpec,
    status: missing.length ? "outdated_or_missing" : "current",
    compliance_delta: missing.length,
    missing,
  };
}

function get(value, path) {
  return path.split(".").reduce((current, part) => {
    if (part === "length") return current?.length;
    return current?.[part];
  }, value);
}

function passes(actual, control) {
  if ("equals" in control) return actual === control.equals;
  if ("min" in control) return Number(actual) >= control.min;
  if ("max" in control) return Number(actual) <= control.max;
  return Boolean(actual);
}

function expected(control) {
  if ("equals" in control) return `equals ${control.equals}`;
  if ("min" in control) return `>= ${control.min}`;
  if ("max" in control) return `<= ${control.max}`;
  return "truthy";
}
