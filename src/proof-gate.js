import {
  parsePortableHostedAuditProof,
  verifyPortableHostedAuditProof,
} from "../lib/portable-proof.ts";

export async function verifyPortableProof(candidate, { fetchImpl = fetch } = {}) {
  try {
    const proof = parsePortableHostedAuditProof(candidate);
    const response = await fetchImpl(proof.trustRoot, {
      headers: { accept: "application/json" },
      redirect: "error",
    });
    if (!response.ok) return blocked("signing_key_set_unavailable", proof);
    const keySet = await response.json();
    const verification = await verifyPortableHostedAuditProof(proof, keySet);
    return {
      ...verification,
      verdict: proof.evidence.releaseVerdict,
      payloadHash: proof.payloadHash,
    };
  } catch (error) {
    return {
      valid: false,
      verdict: "inconclusive",
      payloadHash: "",
      reason: error?.reason || "portable_proof_invalid",
    };
  }
}

function blocked(reason, proof) {
  return { valid: false, verdict: proof.evidence.releaseVerdict || "inconclusive", payloadHash: proof.payloadHash, reason };
}
