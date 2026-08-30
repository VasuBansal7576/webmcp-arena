import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
} from "node:crypto";

export const APPROVAL_COMMITMENT_FIELDS = Object.freeze([
  "planId",
  "artifactHash",
  "targetHash",
  "toolHash",
  "argumentsHash",
  "contractHash",
  "reviewerId",
  "nonceHash",
  "issuedAt",
  "expiresAt",
]);

const HASH_FIELDS = new Set([
  "artifactHash",
  "targetHash",
  "toolHash",
  "argumentsHash",
  "contractHash",
  "nonceHash",
]);
const VERIFICATION_CLAIM = "registered_passkey_user_verified_by_this_arena_instance";

export class ApprovalEnvelopeError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "ApprovalEnvelopeError";
    this.code = code;
  }
}

export function createApprovalCommitments(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new ApprovalEnvelopeError("invalid_commitments");
  }

  const commitments = {};
  for (const field of APPROVAL_COMMITMENT_FIELDS) {
    const value = input[field];
    if (typeof value !== "string" || value.length === 0 || value.length > 512) {
      throw new ApprovalEnvelopeError(`invalid_${field}`);
    }
    if (HASH_FIELDS.has(field) && !/^[a-f0-9]{64}$/i.test(value)) {
      throw new ApprovalEnvelopeError(`invalid_${field}`);
    }
    commitments[field] = value;
  }

  commitments.issuedAt = normalizeTimestamp(commitments.issuedAt, "issuedAt");
  commitments.expiresAt = normalizeTimestamp(commitments.expiresAt, "expiresAt");
  if (Date.parse(commitments.expiresAt) <= Date.parse(commitments.issuedAt)) {
    throw new ApprovalEnvelopeError("invalid_approval_window");
  }
  return Object.freeze(commitments);
}

export function hashApprovalCommitments(input) {
  const commitments = createApprovalCommitments(input);
  return approvalDigest(commitments).toString("hex");
}

export function createApprovalChallenge(input) {
  const commitments = createApprovalCommitments(input);
  return approvalDigest(commitments).toString("base64url");
}

export function generateApprovalEnvelopeKeys() {
  return generateKeyPairSync("ed25519");
}

export function createApprovalEnvelopeIssuer({
  privateKey,
  publicKey,
  issuer,
  arenaInstanceId,
  verifyPasskeyAssertion,
  now = () => new Date(),
  id = randomUUID,
} = {}) {
  if (!privateKey) throw new Error("approval envelope issuer requires an Ed25519 private key");
  if (!issuer || !arenaInstanceId) throw new Error("approval envelope issuer requires issuer and arenaInstanceId");
  if (typeof verifyPasskeyAssertion !== "function") throw new Error("approval envelope issuer requires a trusted passkey verifier");
  const signingKey = privateKey;
  const verificationKey = publicKey ? asPublicKey(publicKey) : createPublicKey(privateKey);
  if (verificationKey.asymmetricKeyType !== "ed25519") {
    throw new Error("approval envelopes require Ed25519 keys");
  }
  const derivedPublicKey = createPublicKey(privateKey);
  if (!derivedPublicKey.export({ format: "der", type: "spki" }).equals(verificationKey.export({ format: "der", type: "spki" }))) {
    throw new Error("approval envelope public and private keys do not match");
  }
  const keyId = keyFingerprint(verificationKey);

  function issue({ commitments: input, assertion } = {}) {
    const commitments = createApprovalCommitments(input);
    const passkeyVerification = verifyPasskeyAssertion({ commitments, assertion });
    if (passkeyVerification && typeof passkeyVerification.then === "function") {
      throw new Error("approval envelope passkey verifier must be synchronous");
    }
    validatePasskeyVerification(passkeyVerification, commitments, arenaInstanceId);
    const current = checkedNow(now);
    if (current.getTime() < Date.parse(commitments.issuedAt) || current.getTime() >= Date.parse(commitments.expiresAt)) {
      throw new ApprovalEnvelopeError("approval_outside_valid_window");
    }

    const unsigned = {
      kind: "arena.passkey_approval",
      version: 1,
      approvalId: String(id()),
      issuer: String(issuer),
      signedAt: current.toISOString(),
      commitments,
      commitmentHash: hashApprovalCommitments(commitments),
      assurance: {
        method: "webauthn_passkey",
        claim: VERIFICATION_CLAIM,
        arenaInstanceId: String(arenaInstanceId),
      },
    };
    const signature = sign(null, Buffer.from(canonicalJson(unsigned)), signingKey).toString("base64url");
    return deepFreeze({
      ...unsigned,
      proof: { algorithm: "Ed25519", keyId, signature },
    });
  }

  return {
    issue,
    keyId,
    publicKey: verificationKey,
    verify: (envelope) => verifyApprovalEnvelope(envelope, verificationKey),
  };
}

export function verifyApprovalEnvelope(envelope, publicKey) {
  try {
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) return false;
    if (envelope.kind !== "arena.passkey_approval" || envelope.version !== 1) return false;
    if (envelope.proof?.algorithm !== "Ed25519" || typeof envelope.proof.signature !== "string") return false;
    const commitments = createApprovalCommitments(envelope.commitments);
    if (envelope.commitmentHash !== hashApprovalCommitments(commitments)) return false;
    if (envelope.assurance?.method !== "webauthn_passkey" || envelope.assurance?.claim !== VERIFICATION_CLAIM) return false;
    const unsigned = {
      kind: envelope.kind,
      version: envelope.version,
      approvalId: envelope.approvalId,
      issuer: envelope.issuer,
      signedAt: envelope.signedAt,
      commitments,
      commitmentHash: envelope.commitmentHash,
      assurance: {
        method: envelope.assurance.method,
        claim: envelope.assurance.claim,
        arenaInstanceId: envelope.assurance.arenaInstanceId,
      },
    };
    const key = asPublicKey(publicKey);
    if (key.asymmetricKeyType !== "ed25519") return false;
    if (envelope.proof.keyId !== keyFingerprint(key)) return false;
    return verify(
      null,
      Buffer.from(canonicalJson(unsigned)),
      key,
      decodeBase64url(envelope.proof.signature),
    );
  } catch {
    return false;
  }
}

function validatePasskeyVerification(result, commitments, arenaInstanceId) {
  if (!result?.verified || result.claim !== VERIFICATION_CLAIM) {
    throw new ApprovalEnvelopeError("passkey_not_verified");
  }
  if (result.arenaInstanceId !== String(arenaInstanceId)) {
    throw new ApprovalEnvelopeError("arena_instance_mismatch");
  }
  if (result.reviewerId !== commitments.reviewerId) {
    throw new ApprovalEnvelopeError("reviewer_mismatch");
  }
  if (result.challenge !== createApprovalChallenge(commitments)) {
    throw new ApprovalEnvelopeError("challenge_mismatch");
  }
}

function approvalDigest(commitments) {
  return createHash("sha256")
    .update("arena.passkey-approval.commitments.v1\0")
    .update(canonicalJson(commitments))
    .digest();
}

function normalizeTimestamp(value, field) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new ApprovalEnvelopeError(`invalid_${field}`);
  return new Date(parsed).toISOString();
}

function checkedNow(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("now must return a valid Date");
  return value;
}

function keyFingerprint(publicKey) {
  return createHash("sha256")
    .update(publicKey.export({ format: "der", type: "spki" }))
    .digest("base64url")
    .slice(0, 24);
}

function asPublicKey(key) {
  if (key?.type === "public") return key;
  if (key?.kty) return createPublicKey({ key, format: "jwk" });
  return createPublicKey(key);
}

function decodeBase64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("invalid base64url");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) throw new Error("non-canonical base64url");
  return decoded;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("canonical JSON only supports finite JSON values");
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}
