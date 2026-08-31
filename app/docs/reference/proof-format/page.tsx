import { CodeBlock, DocsShell } from "@/components/docs-shell";

export default function ProofReference() { return <DocsShell eyebrow="Reference" title="Portable proof format." description="A portable proof is an immutable envelope around semantic evidence, its canonical payload hash, an Ed25519 attestation, and a key-discovery trust root."><h2>Envelope</h2><CodeBlock>{`{
  "kind": "arena.portable_hosted_audit_proof",
  "version": 1,
  "auditId": "…",
  "approvalExpiresAt": "…",
  "retentionUntil": "…",
  "evidence": { "kind": "arena.hosted_boundary_evidence", "version": 2 },
  "payloadHash": "…",
  "attestation": { "algorithm": "Ed25519", "keyId": "…", "signature": "…" },
  "trustRoot": "https://…/.well-known/arena-signing-keys.json"
}`}</CodeBlock><h2>Invocation receipt</h2><p>Evidence version 2 includes the callback channel, page origin, session commitment, tool-definition hash, argument hash, single-use lease commitment, request hash, result hash, backend trace root, and invocation/settlement timestamps.</p><h2>Verification order</h2><ol><li>Reject unknown or missing fields.</li><li>Recompute exact-intent and callback commitments.</li><li>Verify boundary event hashes, chronology, coverage, and settlement.</li><li>Fetch the key-ID-addressed trust set.</li><li>Verify the Ed25519 signature over canonical evidence.</li><li>Apply the required verdict policy.</li></ol><p>Machine schema: <a href="/schemas/arena-proof-v1.schema.json">arena-proof-v1.schema.json</a>.</p></DocsShell>; }
