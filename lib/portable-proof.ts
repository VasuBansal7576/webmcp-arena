import {
  resolveEvidenceSigningKey,
  verifyEvidenceAttestation,
  type EvidenceSigningKeySet,
} from "./evidence-signing.ts";
import { verifyHostedAuditEvidence } from "../src/hosted-audit.js";

const PROOF_FIELDS = [
  "approvalExpiresAt",
  "attestation",
  "auditId",
  "evidence",
  "kind",
  "payloadHash",
  "retentionUntil",
  "trustRoot",
  "version",
] as const;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const AUDIT_ID = /^[0-9a-f-]{36}$/i;

export type PortableHostedAuditProof = Readonly<{
  kind: "arena.portable_hosted_audit_proof";
  version: 1;
  auditId: string;
  approvalExpiresAt: string;
  retentionUntil: string;
  evidence: Record<string, unknown>;
  payloadHash: string;
  attestation: Record<string, unknown>;
  trustRoot: string;
}>;

export class PortableProofError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super("portable Arena proof is invalid");
    this.name = "PortableProofError";
    this.reason = reason;
  }
}

export function parsePortableHostedAuditProof(candidate: unknown): PortableHostedAuditProof {
  if (!isRecord(candidate) || !hasExactKeys(candidate, PROOF_FIELDS) ||
      candidate.kind !== "arena.portable_hosted_audit_proof" || candidate.version !== 1 ||
      typeof candidate.auditId !== "string" || !AUDIT_ID.test(candidate.auditId) ||
      typeof candidate.approvalExpiresAt !== "string" || !isCanonicalTimestamp(candidate.approvalExpiresAt) ||
      typeof candidate.retentionUntil !== "string" || !isCanonicalTimestamp(candidate.retentionUntil) ||
      typeof candidate.payloadHash !== "string" || !DIGEST.test(candidate.payloadHash) ||
      typeof candidate.trustRoot !== "string" || !isSigningTrustRoot(candidate.trustRoot) ||
      !isRecord(candidate.evidence) || !isRecord(candidate.attestation)) {
    throw new PortableProofError("portable_proof_schema_invalid");
  }
  if (candidate.evidence.auditId !== candidate.auditId ||
      candidate.evidence.retentionUntil !== candidate.retentionUntil ||
      !isRecord(candidate.evidence.approval) ||
      candidate.evidence.approval.expiresAt !== candidate.approvalExpiresAt ||
      candidate.attestation.payloadHash !== candidate.payloadHash) {
    throw new PortableProofError("portable_proof_envelope_mismatch");
  }
  return structuredClone(candidate) as PortableHostedAuditProof;
}

export async function verifyPortableHostedAuditProof(
  proof: PortableHostedAuditProof,
  trustedKeySet: EvidenceSigningKeySet,
) {
  const semantic = await verifyHostedAuditEvidence(proof.evidence);
  const trustedKey = resolveEvidenceSigningKey(trustedKeySet, proof.attestation);
  const signatureValid = trustedKey
    ? await verifyEvidenceAttestation(proof.evidence, proof.attestation, trustedKey.publicKey)
    : false;
  const keyMatches = trustedKey !== null;
  const semanticReason = "reason" in semantic ? semantic.reason : null;
  const reason = semanticReason || (!keyMatches ? "signing_key_unknown" : !signatureValid ? "signature_invalid" : null);
  return {
    valid: semantic.valid && signatureValid && keyMatches,
    semanticValid: semantic.valid,
    signatureValid,
    keyMatches,
    keyId: trustedKey?.keyId || "",
    trustRoot: proof.trustRoot,
    ...(reason ? { reason } : {}),
  };
}

function isSigningTrustRoot(value: string) {
  try {
    const url = new URL(value);
    return new Set(["https:", "http:"]).has(url.protocol) &&
      !url.username && !url.password && !url.search && !url.hash &&
      url.pathname === "/.well-known/arena-signing-keys.json";
  } catch {
    return false;
  }
}

function isCanonicalTimestamp(value: string) {
  const epoch = Date.parse(value);
  return Number.isFinite(epoch) && new Date(epoch).toISOString() === value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]) {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
