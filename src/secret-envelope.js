import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export function sealSecret(value, secret, purpose) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(secret, purpose), iv);
  cipher.setAAD(Buffer.from(String(purpose)));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return {
    algorithm: "A256GCM",
    purpose: String(purpose),
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
  };
}

export function openSecret(envelope, secret, purpose) {
  if (envelope?.algorithm !== "A256GCM" || envelope.purpose !== String(purpose) || !envelope.iv || !envelope.ciphertext || !envelope.tag) {
    throw new Error("invalid protected state envelope");
  }
  const decipher = createDecipheriv("aes-256-gcm", deriveKey(secret, purpose), Buffer.from(envelope.iv, "base64url"));
  decipher.setAAD(Buffer.from(String(purpose)));
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64url")), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

function deriveKey(secret, purpose) {
  if (!secret || String(secret).length < 16) throw new Error("protected state requires a secret of at least 16 characters");
  return createHash("sha256").update("arena.secret-envelope.v1\0").update(String(purpose)).update("\0").update(String(secret)).digest();
}
