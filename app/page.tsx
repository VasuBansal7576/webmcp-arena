"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";

type AuditVersion = "vulnerable" | "fixed";
type AuditState = "awaiting_approval" | "running" | "waiting_for_effects" | "completed" | "failed";
type Finding = { code: string; kind: string; message: string };
type EvidenceEvent = { sequence: number; channel: string; kind: string; [key: string]: unknown };
type AuditRecord = {
  id: string;
  version: AuditVersion;
  state: AuditState;
  updatedAt: string;
  expiresAt: string;
  review: { targetPreset: string; targetHash: string; toolName: string; toolHash: string; claimScope: string; contractHash: string; arguments: Record<string, unknown>; argumentsHash: string; invariants: { money?: { currency?: string; maxAmount?: number } }; baselineSafety: { status: string }; approvalAssurance: string };
  history: Array<{ state: string; at: string }>;
  result: null | {
    verdict: "pass" | "fail";
    summary: string;
    findings: Finding[];
    payloadHash: string;
    attestation: { algorithm: string; signature: string; keyId: string };
    bundle: { routeParity: { status: string }; baselineSafety: { status: string } };
    display: { humanEvents: EvidenceEvent[]; agentEvents: EvidenceEvent[]; settlement: { complete: boolean; reason: string } };
    verification: { semanticValid: boolean; hashValid: boolean };
  };
};

type AuditStartResponse = { audit: AuditRecord; approvalCapability: string | null };

declare global {
  interface Document {
    modelContext?: {
      registerTool(definition: Record<string, unknown>, options?: { signal?: AbortSignal }): Promise<void>;
    };
  }
}

export default function Home() {
  const [audit, setAudit] = useState<AuditRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [webMcpStatus, setWebMcpStatus] = useState("checking");
  const auditRef = useRef<AuditRecord | null>(null);
  const approvalCapabilityRef = useRef<{ auditId: string; value: string } | null>(null);
  useEffect(() => { auditRef.current = audit; }, [audit]);

  const adoptAudit = useCallback((next: AuditRecord) => {
    setAudit((current) => {
      if (!current || current.id !== next.id) return next;
      return Date.parse(next.updatedAt) >= Date.parse(current.updatedAt) ? next : current;
    });
  }, []);

  const startAudit = useCallback(async (version: AuditVersion, idempotencyKey = crypto.randomUUID()) => {
    setBusy(true); setError("");
    try {
      const response = await requestJson<AuditStartResponse>("/api/audits", { method: "POST", body: JSON.stringify({ version, idempotencyKey }) });
      if (response.approvalCapability) approvalCapabilityRef.current = { auditId: response.audit.id, value: response.approvalCapability };
      adoptAudit(response.audit);
      return publicAudit(response.audit);
    } catch (caught) {
      setError(errorMessage(caught));
      throw caught;
    } finally { setBusy(false); }
  }, [adoptAudit]);

  const getStatus = useCallback(async (auditId: string) => {
    const next = await requestJson<AuditRecord>(`/api/audits?id=${encodeURIComponent(auditId)}`);
    if (auditRef.current?.id === auditId) adoptAudit(next);
    return publicAudit(next);
  }, [adoptAudit]);

  useEffect(() => {
    if (!document.modelContext) { setWebMcpStatus("unavailable"); return; }
    const controller = new AbortController();
    setWebMcpStatus("registering");
    const registrations = [document.modelContext.registerTool({
      name: "start_measured_checkout_audit",
      description: "Prepare a server-owned Human-vs-Agent Checkout audit and show the exact contract for interface approval. This tool cannot approve or execute the agent route.",
      inputSchema: { type: "object", properties: { version: { type: "string", enum: ["vulnerable", "fixed"] }, idempotencyKey: { type: "string", minLength: 8, maxLength: 128, pattern: "^[A-Za-z0-9_-]+$" } }, required: [] },
      annotations: { readOnlyHint: false, untrustedContentHint: false },
      execute: async ({ version = "vulnerable", idempotencyKey = crypto.randomUUID() }: { version?: AuditVersion; idempotencyKey?: string }) => startAudit(version, idempotencyKey),
    }, { signal: controller.signal }),
    document.modelContext.registerTool({
      name: "get_measured_audit_status",
      description: "Poll a measured audit without changing, approving, or executing it.",
      inputSchema: { type: "object", properties: { auditId: { type: "string" } }, required: ["auditId"] },
      annotations: { readOnlyHint: true, untrustedContentHint: false },
      execute: async ({ auditId }: { auditId: string }) => getStatus(auditId),
    }, { signal: controller.signal })];
    void Promise.allSettled(registrations).then((results) => {
      if (controller.signal.aborted) return;
      setWebMcpStatus(results.every((result) => result.status === "fulfilled") ? "2 tools" : "registration failed");
    });
    return () => controller.abort();
  }, [getStatus, startAudit]);

  useEffect(() => {
    if (!audit || !new Set(["running", "waiting_for_effects"]).has(audit.state)) return;
    const timer = window.setInterval(() => getStatus(audit.id).catch(() => {}), 500);
    return () => window.clearInterval(timer);
  }, [audit?.id, audit?.state, getStatus]);

  const approve = async () => {
    if (!audit || audit.state !== "awaiting_approval") return;
    const boundCapability = approvalCapabilityRef.current;
    if (!boundCapability || boundCapability.auditId !== audit.id) {
      setError("This review capability is unavailable or expired. Start a new audit.");
      return;
    }
    setBusy(true); setError("");
    try {
      const next = await requestJson<AuditRecord>("/api/audits/approve", {
        method: "POST",
        headers: { "x-arena-interface-confirmation": "?1" },
        body: JSON.stringify({ auditId: audit.id, approvalCapability: boundCapability.value }),
      });
      approvalCapabilityRef.current = null;
      adoptAudit(next);
    } catch (caught) { setError(errorMessage(caught)); }
    finally { setBusy(false); }
  };

  const steps = useMemo(() => new Set(audit?.history.map((item) => item.state) || []), [audit]);
  const verdict = audit?.result?.verdict;

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Arena home"><span>A</span> Arena</a>
        <nav aria-label="Runtime status"><span>WebMCP · {webMcpStatus}</span><span>D1 durable state</span><span>Ed25519 proof</span></nav>
      </header>

      <section className="hero" id="top">
        <div><p className="eyebrow">The proving ground for the agentic web</p><h1>A tool description is <em>not proof.</em></h1></div>
        <p className="lede">WebMCP tells agents what a site can do. Arena measures whether the agent route preserves the authorization, confirmation, ownership, and spending boundaries built for humans.</p>
      </section>

      <section className="workbench" aria-labelledby="proof-title">
        <div className="section-heading"><div><p className="eyebrow">Live owned-target audit</p><h2 id="proof-title">Human-vs-Agent Checkout Proof</h2></div><span className={`state-pill ${verdict || audit?.state || "idle"}`}>{audit?.state?.replaceAll("_", " ") || "not started"}</span></div>
        <p className="section-copy">An agent may prepare and poll this audit through WebMCP. Approval must traverse the explicit interface route carrying a one-time capability bound to the reviewed contract and browser session. Arena then executes both owned routes and observes effects through a terminal settlement watermark.</p>

        <div className="flow-grid">
          <article className="flow-card"><span className="step">01</span><h3>Agent starts the audit</h3><p>The agent chooses only a server-owned preset. It cannot submit routes, evidence, or approval claims.</p><div className="button-row"><Button size="lg" disabled={busy} onClick={() => startAudit("vulnerable")}>Test vulnerable</Button><Button size="lg" variant="secondary" disabled={busy} onClick={() => startAudit("fixed")}>Test fixed</Button></div></article>
          <article className="flow-card"><span className="step">02</span><h3>Review the exact contract</h3>{audit ? <dl><div><dt>Target</dt><dd>{audit.review.targetPreset}</dd></div><div><dt>Tool</dt><dd>{audit.review.toolName}</dd></div><div><dt>Arguments</dt><dd title={JSON.stringify(audit.review.arguments)}>{JSON.stringify(audit.review.arguments)}</dd></div><div><dt>Spend ceiling</dt><dd>{audit.review.invariants.money?.currency || "USD"} {audit.review.invariants.money?.maxAmount ?? 0}</dd></div><div><dt>Expires</dt><dd>{new Date(audit.expiresAt).toLocaleTimeString()}</dd></div><div><dt>Contract</dt><dd title={audit.review.contractHash}>{short(audit.review.contractHash)}</dd></div></dl> : <p className="empty">Start an audit to prepare the exact review.</p>}<Button size="lg" className="approve" disabled={busy || audit?.state !== "awaiting_approval"} onClick={approve}>Approve measured run</Button><small>Bound to tool, arguments, contract, session, nonce, and expiry. No approval WebMCP tool exists.</small></article>
          <article className="flow-card"><span className="step">03</span><h3>Observe settled outcome</h3>{audit?.result ? <div className={`verdict ${verdict}`}><strong>{verdict?.toUpperCase()}</strong><p>{audit.result.summary}</p></div> : <p className="empty">{audit ? stateMessage(audit.state) : "No route has executed."}</p>}<div className="stage-row">{["preparing", "awaiting_approval", "running", "waiting_for_effects", "completed"].map((state) => <span key={state} className={steps.has(state) ? "done" : ""}>{state.replaceAll("_", " ")}</span>)}</div></article>
        </div>
        {error && <p role="alert" className="error">{error}</p>}
      </section>

      <section className="evidence" aria-labelledby="evidence-title">
        <div className="section-heading"><div><p className="eyebrow">Signed evidence bundle</p><h2 id="evidence-title">Protection boundary, not task completion</h2></div>{audit?.result && <div className="badges"><span>{audit.result.verification.semanticValid && audit.result.verification.hashValid ? "Semantics + hash valid" : "Verification failed"}</span><span>Producer signed</span></div>}</div>
        {!audit?.result ? <div className="evidence-empty">Run either preset to compare authoritative human and agent effects.</div> : <>
          <div className="layer-grid"><Layer title="Route parity" value={audit.result.bundle.routeParity.status} description="Did the agent route preserve the reviewed human outcomes?"/><Layer title="Baseline safety" value={audit.result.bundle.baselineSafety.status} description="Was the human baseline itself safe under the declared invariants?"/><Layer title="Effect settlement" value={audit.result.display.settlement.complete ? "complete" : "inconclusive"} description={`Capture ended at ${audit.result.display.settlement.reason}.`}/></div>
          <div className="timeline-grid"><Timeline title="Human route" events={audit.result.display.humanEvents}/><Timeline title="Agent route" events={audit.result.display.agentEvents}/></div>
          <div className="proof-strip"><div><span>Algorithm</span><strong>{audit.result.attestation.algorithm}</strong></div><div><span>Payload hash</span><strong title={audit.result.payloadHash}>{short(audit.result.payloadHash)}</strong></div><div><span>Signing key</span><strong title={audit.result.attestation.keyId}>{short(audit.result.attestation.keyId)}</strong></div><div><span>Findings</span><strong>{audit.result.findings.length}</strong></div></div>
          {audit.result.findings.length > 0 && <div className="findings">{audit.result.findings.map((finding) => <article key={finding.code}><span>{finding.kind}</span><strong>{finding.code.replaceAll("_", " ")}</strong><p>{finding.message}</p></article>)}</div>}
        </>}
      </section>

      <section className="principles"><article><span>01</span><h3>Descriptions are claims</h3><p>Arena executes isolated owned routes and compares recorded outcomes instead of trusting annotations such as read-only.</p></article><article><span>02</span><h3>Approval is a boundary</h3><p>The WebMCP surface can prepare and poll, but approval must traverse the interface with its one-time session capability.</p></article><article><span>03</span><h3>Return is not settlement</h3><p>Delayed writes are observed until a terminal watermark and final state are recorded.</p></article></section>
      <footer><strong>Arena</strong><span>WebMCP tells agents which tools exist. Arena proves whether those tools deserve trust.</span><a href="https://github.com/VasuBansal7576/webmcp-arena">Source</a></footer>
    </main>
  );
}

function Layer({ title, value, description }: { title: string; value: string; description: string }) { return <article className="layer"><div><h3>{title}</h3><span className={value === "pass" || value === "complete" ? "pass" : "fail"}>{value}</span></div><p>{description}</p></article>; }
function Timeline({ title, events }: { title: string; events: EvidenceEvent[] }) { return <article className="timeline"><h3>{title}</h3>{events.map((event) => <div className={event.kind === "money" ? "event danger" : "event"} key={event.sequence}><span>#{event.sequence}</span><strong>{event.kind.replaceAll("_", " ")}</strong><small>{event.channel} channel</small></div>)}</article>; }
function short(value: string) { return value.length > 22 ? `${value.slice(0, 20)}…` : value; }
function stateMessage(state: AuditState) { return ({ awaiting_approval: "Interface review required. No agent route has executed.", running: "Approved. The agent route is executing.", waiting_for_effects: "The tool returned. Arena is still watching delayed effects.", completed: "Audit complete.", failed: "Audit failed." })[state]; }
function publicAudit(record: AuditRecord) { return { auditId: record.id, state: record.state, expiresAt: record.expiresAt, review: record.review, result: record.result }; }
function errorMessage(value: unknown) { return value instanceof Error ? value.message : "Unexpected audit error"; }
async function requestJson<T>(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  if (init.body) headers.set("content-type", "application/json");
  const response = await fetch(path, { ...init, headers, cache: "no-store" });
  const text = await response.text();
  let value: T & { error?: string };
  try { value = text ? JSON.parse(text) : {} as T & { error?: string }; }
  catch { throw new Error(`Arena returned an invalid response (${response.status})`); }
  if (!response.ok) throw new Error(value.error || `Request failed (${response.status})`);
  return value;
}
