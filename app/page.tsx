"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button } from "@/components/ui/button";

type AuditVersion = "vulnerable" | "fixed";
type AuditState = "awaiting_approval" | "running" | "waiting_for_effects" | "completed" | "failed";
type Finding = { code: string; kind: string; message: string };
type EvidenceEvent = { sequence: number; channel: string; kind: string; [key: string]: unknown };
type AuthorizationCheck = { check: string; status: "denied" | "executed" | "unexpected"; reason: string | null };
type ToolDefinition = { name: string; title?: string | null; description: string; inputSchema: { required?: string[]; additionalProperties?: boolean; [key: string]: unknown }; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; [key: string]: unknown } | null };
type ProofVerification =
  | { valid: true; semanticValid: true; signatureValid: true; keyMatches: true; keyId: string; trustRoot: string }
  | { valid: false; semanticValid: boolean; signatureValid: boolean; keyMatches: boolean; keyId: string; trustRoot: string; reason: string };
type ProofState =
  | { kind: "unchecked" }
  | { kind: "verifying" }
  | { kind: "valid"; proof: ProofVerification }
  | { kind: "invalid"; reason: string; proof?: ProofVerification };
type AuditRecord = {
  id: string;
  version: AuditVersion;
  state: AuditState;
  updatedAt: string;
  approvalExpiresAt: string;
  retentionUntil: string;
  review: { adapterId: string; implementationVersion: AuditVersion; targetPreset: string; target: string; targetHash: string; release: { id: string; version: string; generator: string; artifact: { algorithm: "sha256"; digest: string; subject: string }; hash: string }; releaseHash: string; releaseManifest: { tools: ToolDefinition[] }; coverage: { auditedTools: string[]; totalTools: number; complete: boolean }; principal: { label: string; scope: string; hash: string }; principalHash: string; agent: { id: string; assurance: string; hash: string }; agentHash: string; toolName: string; toolDefinition: ToolDefinition; toolDefinitionHash: string; toolHash: string; claimScope: string; contractHash: string; arguments: Record<string, unknown>; argumentsHash: string; invariants: { money?: { currency?: string; maxAmount?: number } }; baselineSafety: { status: string }; trustMode: "server_attested"; approvalAssurance: string };
  history: Array<{ state: string; at: string }>;
  result: null | {
    verdict: "pass" | "fail";
    summary: string;
    findings: Finding[];
    release: { id: string; version: string; generator: string; artifact: { algorithm: "sha256"; digest: string; subject: string }; hash: string };
    authorization: { status: string; agentHash: string; reviewerHash: string };
    authorizationChecks: AuthorizationCheck[];
    releaseCoverage: { auditedTools: string[]; totalTools: number; complete: boolean };
    selectedToolVerdict: "pass" | "fail" | "inconclusive";
    payloadHash: string;
    attestation: { algorithm: string; signature: string; keyId: string };
    evidence: Record<string, unknown>;
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
  const [proofState, setProofState] = useState<ProofState>({ kind: "unchecked" });
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
    setBusy(true); setError(""); setProofState({ kind: "unchecked" });
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
      name: "start_generated_release_audit",
      description: "Prepare a server-owned audit of a generated WebMCP release and show the exact release, agent, tool, arguments, target, and contract commitments for interface approval. This tool cannot approve or execute the agent route.",
      inputSchema: { type: "object", properties: { version: { type: "string", enum: ["vulnerable", "fixed"] }, idempotencyKey: { type: "string", minLength: 8, maxLength: 128, pattern: "^[A-Za-z0-9_-]+$" } }, required: [] },
      annotations: { readOnlyHint: false, untrustedContentHint: false },
      execute: async ({ version = "vulnerable", idempotencyKey = crypto.randomUUID() }: { version?: AuditVersion; idempotencyKey?: string }) => startAudit(version, idempotencyKey),
    }, { signal: controller.signal }),
    document.modelContext.registerTool({
      name: "get_generated_release_audit_status",
      description: "Poll a generated-release audit without changing, approving, or executing it.",
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

  const verifyProof = useCallback(async (auditId: string) => {
    setProofState({ kind: "verifying" });
    try {
      const proof = await requestJson<ProofVerification>(`/api/audits/verify?id=${encodeURIComponent(auditId)}`);
      if (auditRef.current?.id !== auditId) return;
      setProofState(proof.valid
        ? { kind: "valid", proof }
        : { kind: "invalid", proof, reason: proof.reason.replaceAll("_", " ") });
    } catch (caught) {
      if (auditRef.current?.id !== auditId) return;
      setProofState({ kind: "invalid", reason: errorMessage(caught) });
    }
  }, []);

  useEffect(() => {
    if (!audit?.result) return;
    void verifyProof(audit.id);
  }, [audit?.id, audit?.result?.payloadHash, verifyProof]);

  const downloadProof = () => {
    if (!audit?.result || proofState.kind !== "valid") return;
    const portableProof = {
      kind: "arena.portable_hosted_audit_proof",
      version: 1,
      auditId: audit.id,
      approvalExpiresAt: audit.approvalExpiresAt,
      retentionUntil: audit.retentionUntil,
      evidence: audit.result.evidence,
      payloadHash: audit.result.payloadHash,
      attestation: audit.result.attestation,
      trustRoot: new URL(proofState.proof.trustRoot, window.location.origin).href,
    };
    const url = URL.createObjectURL(new Blob([`${JSON.stringify(portableProof, null, 2)}\n`], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `arena-audit-${audit.id}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const steps = useMemo(() => new Set(audit?.history.map((item) => item.state) || []), [audit]);
  const verdict = audit?.result?.verdict;

  return (
    <main>
      <header className="topbar">
        <a className="brand" href="#top" aria-label="Arena home"><span>A</span> Arena</a>
        <nav aria-label="Runtime status"><span>WebMCP · {webMcpStatus}</span><span>D1 · 30-day proof retention</span><span>Ed25519 proof</span></nav>
      </header>

      <section className="hero" id="top">
        <div><p className="eyebrow">Independent release gate for WebMCP</p><h1>Generated tools need <em>proof.</em></h1></div>
        <p className="lede">Tool generators can publish WebMCP in minutes. Arena executes the human and agent routes, observes settled backend effects, and blocks releases that cross the user&apos;s protection boundary.</p>
      </section>

      <section className="workbench" aria-labelledby="proof-title">
        <div className="section-heading"><div><p className="eyebrow">Live generated-release audit</p><h2 id="proof-title">Generated WebMCP Release Proof</h2></div><span className={`state-pill ${verdict || audit?.state || "idle"}`}>{audit?.state?.replaceAll("_", " ") || "not started"}</span></div>
        <p className="section-copy">An agent may prepare and poll this vendor-neutral release audit through WebMCP. Approval must traverse the visible interface with a one-time capability bound to the release, claimed agent, tool definition, exact arguments, target, contract, browser session, nonce, and expiry. The demo agent label is self-asserted, not vendor-attested. This signed proof measures Arena&apos;s owned server adapter through terminal settlement; the separate <a href="/checkout?mode=vulnerable">registered WebMCP checkout demo</a> is an interactive standards demo, not substituted evidence.</p>

        <div className="flow-grid">
          <article className="flow-card"><span className="step">01</span><h3>Load a generated release</h3><p>The agent chooses a server-owned test release. It cannot submit routes, evidence, or approval claims.</p><div className="button-row"><Button size="lg" disabled={busy} onClick={() => startAudit("vulnerable")}>Audit unsafe release</Button><Button size="lg" variant="secondary" disabled={busy} onClick={() => startAudit("fixed")}>Audit fixed release</Button></div></article>
          <article className="flow-card review-card"><span className="step">02</span><h3>Review the exact intent</h3>{audit ? <dl><div><dt>Release</dt><dd title={audit.review.release.hash}>{audit.review.release.generator} · {audit.review.release.version} · {audit.review.coverage.auditedTools.length}/{audit.review.coverage.totalTools} tools</dd></div><div><dt>Artifact</dt><dd title={`${audit.review.release.artifact.subject}\n${audit.review.release.artifact.digest}`}>{audit.review.release.artifact.algorithm} · {short(audit.review.release.artifact.digest)}</dd></div><div><dt>Measurement</dt><dd>{audit.review.trustMode.replaceAll("_", " ")} · {audit.review.adapterId} {audit.review.implementationVersion}</dd></div><div><dt>Account</dt><dd title={audit.review.principal.hash}>{audit.review.principal.label} · {audit.review.principal.scope}</dd></div><div><dt>Agent claim</dt><dd title={audit.review.agent.hash}>{audit.review.agent.id} · self-asserted</dd></div><div><dt>Target</dt><dd title={`${audit.review.target}\n${audit.review.targetHash}`}>{audit.review.targetPreset} · {short(audit.review.targetHash)}</dd></div><div><dt>Tool claim</dt><dd>{audit.review.toolName} · {audit.review.toolDefinition.annotations?.readOnlyHint ? "read-only" : "writes"}</dd></div><div><dt>Description</dt><dd>{audit.review.toolDefinition.description}</dd></div><div><dt>Schema</dt><dd title={JSON.stringify(audit.review.toolDefinition.inputSchema)}>{schemaSummary(audit.review.toolDefinition)}</dd></div><div><dt>Definition</dt><dd title={audit.review.toolDefinitionHash}>{short(audit.review.toolDefinitionHash)}</dd></div><div><dt>Arguments</dt><dd title={JSON.stringify(audit.review.arguments)}>{JSON.stringify(audit.review.arguments)}</dd></div><div><dt>Spend ceiling</dt><dd>{audit.review.invariants.money?.currency || "USD"} {audit.review.invariants.money?.maxAmount ?? 0}</dd></div><div><dt>Review expires</dt><dd>{new Date(audit.approvalExpiresAt).toLocaleTimeString()}</dd></div><div><dt>Proof retained</dt><dd>{new Date(audit.retentionUntil).toLocaleDateString()}</dd></div><div><dt>Contract</dt><dd title={audit.review.contractHash}>{short(audit.review.contractHash)}</dd></div></dl> : <p className="empty">Start an audit to prepare the exact release and intent.</p>}<Button size="lg" className="approve" disabled={busy || audit?.state !== "awaiting_approval"} onClick={approve}>Approve exact intent</Button><small>No approval WebMCP tool exists. The interface capability is single-use and session-bound.</small></article>
          <article className="flow-card"><span className="step">03</span><h3>Observe settled outcome</h3>{audit?.result ? <div className={`verdict ${verdict}`}><strong>{verdict?.toUpperCase()}</strong><p>{audit.result.summary}</p></div> : <p className="empty">{audit ? stateMessage(audit.state) : "No route has executed."}</p>}<div className="stage-row">{["preparing", "awaiting_approval", "running", "waiting_for_effects", "completed"].map((state) => <span key={state} className={steps.has(state) ? "done" : ""}>{state.replaceAll("_", " ")}</span>)}</div></article>
        </div>
        {error && <p role="alert" className="error">{error}</p>}
      </section>

      <section className={`evidence proof-${proofState.kind}`} aria-labelledby="evidence-title">
        <div className="section-heading"><div><p className="eyebrow">{proofHeading(proofState)}</p><h2 id="evidence-title">Protection boundary, not task completion</h2></div>{audit?.result && <div className="badges"><span>{audit.result.verification.semanticValid && audit.result.verification.hashValid ? "Hosted semantics valid" : "Hosted verification failed"}</span>{proofState.kind === "valid" && <span>Signature + pinned key valid</span>}{proofState.kind === "verifying" && <span>Verifying signature + key…</span>}{proofState.kind === "invalid" && <><span className="proof-invalid">Signature/key invalid · {proofState.reason}</span><button className="verify-proof retry" onClick={() => verifyProof(audit.id)}>Retry verification</button></>}</div>}</div>
        {!audit?.result ? <div className="evidence-empty">Run either preset to compare authoritative human and agent effects.</div> : <>
          <div className="layer-grid"><Layer title="Route parity" value={audit.result.bundle.routeParity.status} description="Did the agent route preserve the reviewed human outcomes?"/><Layer title="Baseline safety" value={audit.result.bundle.baselineSafety.status} description="Was the human baseline itself safe under the declared invariants?"/><Layer title="Effect settlement" value={audit.result.display.settlement.complete ? "complete" : "inconclusive"} description={`Capture ended at ${audit.result.display.settlement.reason}.`}/></div>
          <AuthorizationChecks checks={audit.result.authorizationChecks} releaseHash={audit.result.release.hash}/>
          <div className="timeline-grid"><Timeline title="Human route" events={audit.result.display.humanEvents}/><Timeline title="Agent route" events={audit.result.display.agentEvents}/></div>
          <div className="proof-strip"><div><span>Algorithm</span><strong>{audit.result.attestation.algorithm}</strong></div><div><span>Payload hash</span><strong title={audit.result.payloadHash}>{short(audit.result.payloadHash)}</strong></div><div><span>Signing key</span><strong title={audit.result.attestation.keyId}>{short(audit.result.attestation.keyId)}</strong></div><div><span>Release coverage</span><strong>{audit.result.releaseCoverage.auditedTools.length}/{audit.result.releaseCoverage.totalTools} tools</strong></div><div><span>Trust root</span><strong>{proofTrustRoot(proofState)}</strong></div></div>
          <div className="proof-actions"><Button variant="secondary" disabled={proofState.kind !== "valid"} onClick={downloadProof}>Download signed JSON proof</Button><small>{proofState.kind === "valid" ? `Key-ID-addressed evidence retained until ${new Date(audit.retentionUntil).toLocaleDateString()}; retired verification keys remain discoverable in Arena's trust set.` : "Download unlocks after signature and trust-root verification."}</small></div>
          {audit.result.findings.length > 0 && <div className="findings">{audit.result.findings.map((finding) => <article key={finding.code}><span>{finding.kind}</span><strong>{finding.code.replaceAll("_", " ")}</strong><p>{finding.message}</p></article>)}</div>}
        </>}
      </section>

      <section className="principles"><article><span>01</span><h3>Generation is the start</h3><p>Arena executes owned routes and compares recorded outcomes instead of trusting generated descriptions or read-only annotations.</p></article><article><span>02</span><h3>Approval binds exact intent</h3><p>The capability commits to the release, claimed agent, tool, arguments, target, contract, session, nonce, and expiry.</p></article><article><span>03</span><h3>Return is not settlement</h3><p>Delayed writes are observed until a terminal watermark and final state are recorded.</p></article></section>
      <footer><strong>Arena</strong><span>WebMCP generators ship tools. Arena proves whether those tools deserve to ship.</span><a href="https://github.com/VasuBansal7576/webmcp-arena">Source</a></footer>
    </main>
  );
}

function Layer({ title, value, description }: { title: string; value: string; description: string }) { return <article className="layer"><div><h3>{title}</h3><span className={value === "pass" || value === "complete" ? "pass" : "fail"}>{value}</span></div><p>{description}</p></article>; }
function AuthorizationChecks({ checks, releaseHash }: { checks: AuthorizationCheck[]; releaseHash: string }) { return <section className="authorization-evidence" aria-labelledby="authorization-title"><div><div><p className="eyebrow">Exact-intent authorization</p><h3 id="authorization-title">Attack attempts are evidence too</h3></div><code title={releaseHash}>{short(releaseHash)}</code></div><p>The valid capability remains usable after rejected probes, executes once with the reviewed intent, then rejects replay.</p><div className="authorization-grid">{checks.map((check) => <article key={check.check}><span className={check.status === "unexpected" ? "unsafe" : "safe"}>{check.status}</span><strong>{checkLabel(check.check)}</strong><small>{check.reason?.replaceAll("_", " ") || "reviewed intent consumed"}</small></article>)}</div></section>; }
function Timeline({ title, events }: { title: string; events: EvidenceEvent[] }) { return <article className="timeline"><h3>{title}</h3>{events.map((event) => <div className={event.kind === "money" ? "event danger" : "event"} key={event.sequence}><span>#{event.sequence}</span><strong>{event.kind.replaceAll("_", " ")}</strong><small>{event.channel} channel</small></div>)}</article>; }
function checkLabel(value: string) { switch (value) { case "invalid_capability": return "Invalid capability"; case "tool_substitution": return "Changed tool"; case "wrong_agent": return "Changed claimed agent ID"; case "argument_substitution": return "Changed arguments"; case "exact_intent": return "Exact intent"; case "replay": return "Replay"; default: return value.replaceAll("_", " "); } }
function proofHeading(state: ProofState) { if (state.kind === "valid") return "Verified signed evidence"; if (state.kind === "invalid") return "Untrusted evidence — verification failed"; if (state.kind === "verifying") return "Verifying signed evidence"; return "Unverified evidence"; }
function proofTrustRoot(state: ProofState) { if (state.kind === "valid") return state.proof.trustRoot; if (state.kind === "invalid") return "verification failed"; if (state.kind === "verifying") return "checking…"; return "not checked"; }
function short(value: string) { return value.length > 22 ? `${value.slice(0, 20)}…` : value; }
function schemaSummary(tool: ToolDefinition) { const required = tool.inputSchema.required || []; return `${required.length ? required.join(", ") : "no required inputs"} · additional properties ${tool.inputSchema.additionalProperties === false ? "blocked" : "allowed"}`; }
function stateMessage(state: AuditState) { return ({ awaiting_approval: "Interface review required. No agent route has executed.", running: "Approved. The agent route is executing.", waiting_for_effects: "The tool returned. Arena is still watching delayed effects.", completed: "Audit complete.", failed: "Audit failed." })[state]; }
function publicAudit(record: AuditRecord) { return { auditId: record.id, state: record.state, approvalExpiresAt: record.approvalExpiresAt, retentionUntil: record.retentionUntil, review: record.review, result: record.result }; }
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
