import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from "node:crypto";

export function generateArenaProofKeys() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function createArenaProof({ privateKey, publicKey, issuer = "arena-local", previousHash = null, now = () => new Date(), id = randomUUID } = {}) {
  if (!privateKey || !publicKey) throw new Error("Arena Proof requires an Ed25519 private and public key pair");
  const signingKey = createPrivateKey(privateKey);
  const verificationKey = createPublicKey(publicKey);
  if (signingKey.asymmetricKeyType !== "ed25519" || verificationKey.asymmetricKeyType !== "ed25519") throw new Error("Arena Proof keys must use Ed25519");
  const publicPem = verificationKey.export({ type: "spki", format: "pem" }).toString();
  const keyId = `arena:${digest(verificationKey.export({ type: "spki", format: "der" })).slice(0, 24)}`;
  let previousAttestationHash = previousHash;

  function issue(evidence) {
    if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) throw new Error("attestation evidence must be an object");
    const payload = {
      ...structuredClone(evidence),
      attestation_id: id(),
      issued_at: now().toISOString(),
      previous_attestation_hash: previousAttestationHash,
    };
    const signature = sign(null, Buffer.from(stableJson(payload)), signingKey).toString("base64url");
    const attestation = {
      ...payload,
      proof: { algorithm: "Ed25519", issuer, key_id: keyId, signature },
    };
    previousAttestationHash = hash(attestation);
    return attestation;
  }

  function verifyAttestation(attestation) {
    return attestation?.proof?.key_id === keyId && verifyArenaAttestation(attestation, verificationKey);
  }

  function verifyChain(attestations) {
    if (!Array.isArray(attestations) || !attestations.length) return { valid: false, reason: "empty_chain" };
    for (let index = 0; index < attestations.length; index += 1) {
      const attestation = attestations[index];
      if (!verifyAttestation(attestation)) return { valid: false, reason: "invalid_signature", index };
      const expected = index === 0 ? null : hash(attestations[index - 1]);
      if (attestation.previous_attestation_hash !== expected) return { valid: false, reason: "broken_hash_link", index };
    }
    return { valid: true, count: attestations.length };
  }

  function hash(attestation) {
    return hashArenaAttestation(attestation);
  }

  return {
    issue,
    verify: verifyAttestation,
    verifyChain,
    hash,
    keyId,
    issuer,
    exportPublicKey: () => publicPem,
    getLastHash: () => previousAttestationHash,
  };
}

export function verifyArenaAttestation(attestation, publicKey) {
  if (!attestation || typeof attestation !== "object" || attestation.proof?.algorithm !== "Ed25519" || !attestation.proof?.signature) return false;
  try {
    const key = publicKey?.type === "public" ? publicKey : createPublicKey(publicKey);
    const { proof, ...payload } = attestation;
    return verify(null, Buffer.from(stableJson(payload)), key, Buffer.from(proof.signature, "base64url"));
  } catch {
    return false;
  }
}

export function hashArenaAttestation(attestation) {
  return digest(stableJson(attestation));
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash("sha256").update(value).digest("base64url");
}
