import { loadAudit } from "@/lib/audit-store";
import {
  getEvidenceSigningKeySet,
  resolveEvidenceSigningKey,
  verifyEvidenceAttestation,
} from "@/lib/evidence-signing";
import {
  parsePortableHostedAuditProof,
  PortableProofError,
  verifyPortableHostedAuditProof,
} from "@/lib/portable-proof";
import {
  readUtf8RequestBody,
  RequestBodyLimitError,
} from "@/lib/request-body";
import { verifyHostedAuditRecord } from "@/src/hosted-audit.js";

export const runtime = "edge";
const MAX_PORTABLE_PROOF_BYTES = 2 * 1024 * 1024;

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get("id") || "";
  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    return Response.json({ error: "a valid audit id is required" }, { status: 400 });
  }
  try {
    const record = await loadAudit(id);
    if (!record) return Response.json({ error: "audit not found" }, { status: 404 });
    if (record.state !== "completed" || !record.result?.evidence || !record.result?.attestation) {
      return Response.json({ error: "signed audit evidence is not ready" }, { status: 409 });
    }
    const [semantic, trustedKeySet] = await Promise.all([
      verifyHostedAuditRecord(record),
      getEvidenceSigningKeySet(),
    ]);
    const trustedKey = resolveEvidenceSigningKey(trustedKeySet, record.result.attestation);
    const signatureValid = trustedKey
      ? await verifyEvidenceAttestation(
        record.result.evidence,
        record.result.attestation,
        trustedKey.publicKey,
      )
      : false;
    const keyMatches = trustedKey !== null;
    const semanticReason = "reason" in semantic ? semantic.reason : null;
    const reason = semanticReason || (!keyMatches ? "signing_key_unknown" : !signatureValid ? "signature_invalid" : null);
    return Response.json({
      valid: semantic.valid && signatureValid && keyMatches,
      semanticValid: semantic.valid,
      signatureValid,
      keyMatches,
      keyId: trustedKey?.keyId || "",
      trustRoot: "/.well-known/arena-signing-keys.json",
      ...(reason ? { reason } : {}),
    }, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    console.error("Arena evidence verification failed", error);
    return Response.json({ error: "Arena could not verify this audit" }, {
      status: 503,
      headers: { "cache-control": "no-store", "retry-after": "30" },
    });
  }
}

export async function POST(request: Request) {
  try {
    const source = await readUtf8RequestBody(request, MAX_PORTABLE_PROOF_BYTES);
    let candidate: unknown;
    try {
      candidate = JSON.parse(source);
    } catch {
      throw new PortableProofError("portable_proof_json_invalid");
    }
    const proof = parsePortableHostedAuditProof(candidate);
    const expectedTrustRoot = new URL("/.well-known/arena-signing-keys.json", request.url).href;
    if (proof.trustRoot !== expectedTrustRoot) {
      throw new PortableProofError("portable_proof_trust_root_mismatch");
    }
    const result = await verifyPortableHostedAuditProof(proof, await getEvidenceSigningKeySet());
    return Response.json(result, { headers: { "cache-control": "no-store" } });
  } catch (error) {
    if (error instanceof RequestBodyLimitError) {
      return Response.json({ error: "portable proof is too large" }, {
        status: 413,
        headers: { "cache-control": "no-store" },
      });
    }
    if (error instanceof PortableProofError) {
      return Response.json({ error: "portable proof is invalid", reason: error.reason }, {
        status: 400,
        headers: { "cache-control": "no-store" },
      });
    }
    console.error("Arena portable evidence verification failed", error);
    return Response.json({ error: "Arena could not verify this portable proof" }, {
      status: 503,
      headers: { "cache-control": "no-store", "retry-after": "30" },
    });
  }
}
