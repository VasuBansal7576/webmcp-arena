import { nowIso, sha256 } from "./util.js";

export function buildMembraneBaseline(scan) {
  return {
    version: "1.0.0",
    layer: "agent_session_membrane.layer1",
    generated_at: nowIso(),
    source: scan.source,
    page: {
      url: scan.source.url,
      content_hash: hashValue(scan.source.content_hash),
    },
    watch_zones: [
      ...(scan.page?.critical_elements || []).map((item) => ({
        id: item.id,
        type: "critical_element",
        priority: item.structural_risk ? "high" : "normal",
        cpi: item.cpi,
        baseline_hash: hashValue(item.content_hash),
      })),
      ...(scan.page?.ipi_risks || []).map((item, index) => ({
        id: `ipi_risk_${index + 1}`,
        type: "ipi_risk_zone",
        priority: item.severity,
        baseline_hash: hashValue(item.content_hash),
        snippet: item.snippet,
      })),
    ],
    interpretation_boundary: "Deviation detection only; this baseline does not attribute intent.",
  };
}

export function observationFromHtml({ url, html, userAgent = "", observedAt = nowIso() }) {
  return {
    url,
    observed_at: observedAt,
    user_agent: userAgent,
    content_hash: hashValue(sha256(html || "")),
    bytes: String(html || "").length,
  };
}

export function evaluateRuntimeObservation(baseline, observation) {
  const observed = observation.html ? observationFromHtml({
    url: observation.url,
    html: observation.html,
    userAgent: observation.user_agent,
    observedAt: observation.observed_at,
  }) : observation;
  const events = [
    ...pageDeviationEvents(baseline, observed),
    ...regionDeviationEvents(baseline, observed),
  ];
  return {
    generated_at: nowIso(),
    baseline_url: baseline.page?.url || baseline.source?.url || "",
    observed_url: observed.url || "",
    status: events.length ? "deviation" : "clean",
    events,
    interpretation_boundary: "Deviation detection only; not attack attribution.",
  };
}

export function browserSnippet({ endpoint, siteId = "" }) {
  if (!endpoint) throw new Error("membrane snippet requires an endpoint");
  return `(() => {
  const endpoint = ${JSON.stringify(endpoint)};
  const siteId = ${JSON.stringify(siteId)};
  const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const send = async () => {
    const html = document.documentElement.outerHTML;
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(html));
    const body = JSON.stringify({
      site_id: siteId,
      url: location.href,
      user_agent: navigator.userAgent,
      observed_at: new Date().toISOString(),
      content_hash: "sha256:" + hex(digest)
    });
    navigator.sendBeacon(endpoint, new Blob([body], { type: "application/json" }));
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", send, { once: true });
  else send();
})();`;
}

function pageDeviationEvents(baseline, observed) {
  const expected = hashValue(baseline.page?.content_hash);
  const actual = hashValue(observed.content_hash);
  if (!expected || !actual || expected === actual) return [];
  return [{
    type: "runtime_dom_deviation",
    severity: "high",
    region: "document",
    url: observed.url || baseline.page?.url || "",
    baseline_hash: expected,
    observed_hash: actual,
    observed_at: observed.observed_at || nowIso(),
    user_agent: observed.user_agent || "",
  }];
}

function regionDeviationEvents(baseline, observed) {
  const zones = new Map((baseline.watch_zones || []).map((zone) => [zone.id, zone]));
  return (observed.regions || []).flatMap((region) => {
    const zone = zones.get(region.id);
    const expected = hashValue(zone?.baseline_hash);
    const actual = hashValue(region.content_hash);
    if (!zone || !expected || !actual || expected === actual) return [];
    return [{
      type: "runtime_region_deviation",
      severity: zone.priority === "critical" || zone.priority === "high" ? "high" : "medium",
      region: region.id,
      url: observed.url || baseline.page?.url || "",
      baseline_hash: expected,
      observed_hash: actual,
      observed_at: observed.observed_at || nowIso(),
      user_agent: observed.user_agent || "",
    }];
  });
}

function hashValue(value) {
  if (!value) return "";
  return String(value).startsWith("sha256:") ? String(value) : `sha256:${value}`;
}
