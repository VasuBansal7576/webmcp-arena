import {
  constants,
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifySignature,
} from "node:crypto";

import { createApprovalChallenge, createApprovalCommitments } from "./approval-envelope.js";

const VERIFICATION_CLAIM = "registered_passkey_user_verified_by_this_arena_instance";
const USER_PRESENT = 0x01;
const USER_VERIFIED = 0x04;

export class PasskeyAuthenticationError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "PasskeyAuthenticationError";
    this.code = code;
  }
}

export function createPasskeyAuthenticator({
  rpId,
  allowedOrigins,
  arenaInstanceId,
  credentials = [],
  now = () => new Date(),
  clockSkewMs = 0,
  maxApprovalLifetimeMs = 5 * 60_000,
  nonceStore,
} = {}) {
  const normalizedRpId = normalizeRpId(rpId);
  const origins = new Set((allowedOrigins || []).map(normalizeOrigin));
  if (!origins.size) throw new Error("passkey authenticator requires at least one allowed origin");
  for (const origin of origins) {
    const hostname = new URL(origin).hostname;
    if (hostname !== normalizedRpId && !hostname.endsWith(`.${normalizedRpId}`)) {
      throw new Error("allowed passkey origin must be the RP ID or one of its subdomains");
    }
  }
  if (!arenaInstanceId) throw new Error("passkey authenticator requires arenaInstanceId");
  if (!Number.isFinite(clockSkewMs) || clockSkewMs < 0) throw new Error("clockSkewMs must be non-negative");
  if (!Number.isFinite(maxApprovalLifetimeMs) || maxApprovalLifetimeMs <= 0) throw new Error("maxApprovalLifetimeMs must be positive");
  const credentialRegistry = new Map();
  for (const input of credentials) {
    const credential = normalizeCredential(input);
    if (credentialRegistry.has(credential.credentialId)) throw new Error("duplicate passkey credential ID");
    credentialRegistry.set(credential.credentialId, credential);
  }
  const usedNonces = normalizeNonceStore(nonceStore);

  function verify({ commitments: input, assertion } = {}) {
    const commitments = createApprovalCommitments(input);
    const current = checkedNow(now);
    validateApprovalTime(commitments, current, clockSkewMs, maxApprovalLifetimeMs);
    if (!assertion || assertion.type !== "public-key" || !assertion.response) {
      throw new PasskeyAuthenticationError("invalid_assertion");
    }

    const credentialId = normalizeCredentialId(assertion.rawId ?? assertion.id);
    const credential = credentialRegistry.get(credentialId);
    if (!credential) throw new PasskeyAuthenticationError("unknown_credential");
    if (credential.reviewerId !== commitments.reviewerId) {
      throw new PasskeyAuthenticationError("credential_owner_mismatch");
    }

    const clientDataJSON = decodeBinary(assertion.response.clientDataJSON, "client_data", 64 * 1024);
    const clientData = parseClientData(clientDataJSON);
    if (clientData.type !== "webauthn.get") throw new PasskeyAuthenticationError("invalid_client_data_type");
    const challenge = createApprovalChallenge(commitments);
    if (!safeEqualString(clientData.challenge, challenge)) throw new PasskeyAuthenticationError("challenge_mismatch");
    if (!origins.has(clientData.origin)) throw new PasskeyAuthenticationError("origin_mismatch");
    if (clientData.crossOrigin === true) throw new PasskeyAuthenticationError("cross_origin_assertion_rejected");

    const authenticatorData = decodeBinary(assertion.response.authenticatorData, "authenticator_data", 1024);
    if (authenticatorData.length < 37) throw new PasskeyAuthenticationError("invalid_authenticator_data");
    const expectedRpIdHash = createHash("sha256").update(normalizedRpId).digest();
    if (!safeEqual(authenticatorData.subarray(0, 32), expectedRpIdHash)) {
      throw new PasskeyAuthenticationError("rp_id_mismatch");
    }
    const flags = authenticatorData[32];
    if ((flags & USER_PRESENT) === 0) throw new PasskeyAuthenticationError("user_presence_required");
    if ((flags & USER_VERIFIED) === 0) throw new PasskeyAuthenticationError("user_verification_required");
    const signCount = authenticatorData.readUInt32BE(33);
    if ((credential.signCount !== 0 || signCount !== 0) && signCount <= credential.signCount) {
      throw new PasskeyAuthenticationError("signature_counter_not_advanced");
    }
    if (usedNonces.has(commitments.nonceHash) !== false) throw new PasskeyAuthenticationError("nonce_replayed");

    const signature = decodeBinary(assertion.response.signature, "signature", 16 * 1024);
    const clientDataHash = createHash("sha256").update(clientDataJSON).digest();
    const signedData = Buffer.concat([authenticatorData, clientDataHash]);
    if (!verifyAuthenticatorSignature(credential.publicKey, signedData, signature)) {
      throw new PasskeyAuthenticationError("invalid_signature");
    }

    if (usedNonces.consume(commitments.nonceHash) !== true) throw new PasskeyAuthenticationError("nonce_replayed");
    credential.signCount = signCount;
    return Object.freeze({
      verified: true,
      claim: VERIFICATION_CLAIM,
      arenaInstanceId: String(arenaInstanceId),
      reviewerId: commitments.reviewerId,
      challenge,
      verifiedAt: current.toISOString(),
      userPresent: true,
      userVerified: true,
      signCount,
    });
  }

  return { verify };
}

function normalizeCredential(input) {
  if (!input?.publicKey || !input.reviewerId) throw new Error("passkey credential requires publicKey and reviewerId");
  const publicKey = asPublicKey(input.publicKey);
  if (!new Set(["ed25519", "ec", "rsa", "rsa-pss"]).has(publicKey.asymmetricKeyType)) {
    throw new Error(`unsupported passkey public key type: ${publicKey.asymmetricKeyType || "unknown"}`);
  }
  const signCount = input.signCount ?? 0;
  if (!Number.isSafeInteger(signCount) || signCount < 0 || signCount > 0xffffffff) {
    throw new Error("passkey signCount must be an unsigned 32-bit integer");
  }
  return {
    credentialId: normalizeCredentialId(input.credentialId),
    reviewerId: String(input.reviewerId),
    publicKey,
    signCount,
  };
}

function normalizeCredentialId(value) {
  if (typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value) && value.length <= 2048) {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length && decoded.toString("base64url") === value) return value;
  }
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    const bytes = Buffer.isBuffer(value)
      ? value
      : value instanceof ArrayBuffer
        ? Buffer.from(value)
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    if (bytes.length && bytes.length <= 1024) return bytes.toString("base64url");
  }
  throw new PasskeyAuthenticationError("invalid_credential_id");
}

function parseClientData(bytes) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new PasskeyAuthenticationError("invalid_client_data");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new PasskeyAuthenticationError("invalid_client_data");
  if (typeof value.type !== "string" || typeof value.challenge !== "string" || typeof value.origin !== "string") {
    throw new PasskeyAuthenticationError("invalid_client_data");
  }
  return value;
}

function validateApprovalTime(commitments, now, clockSkewMs, maxLifetimeMs) {
  const issuedAt = Date.parse(commitments.issuedAt);
  const expiresAt = Date.parse(commitments.expiresAt);
  if (expiresAt - issuedAt > maxLifetimeMs) throw new PasskeyAuthenticationError("approval_lifetime_too_long");
  if (issuedAt > now.getTime() + clockSkewMs) throw new PasskeyAuthenticationError("approval_issued_in_future");
  if (expiresAt <= now.getTime() - clockSkewMs) throw new PasskeyAuthenticationError("approval_expired");
}

function normalizeRpId(value) {
  if (typeof value !== "string" || !value || value !== value.trim() || value.includes(":") || value.includes("/") || value.endsWith(".")) {
    throw new Error("passkey authenticator requires a valid RP ID hostname");
  }
  let parsed;
  try {
    parsed = new URL(`https://${value}`);
  } catch {
    throw new Error("passkey authenticator requires a valid RP ID hostname");
  }
  if (parsed.hostname !== value.toLowerCase()) throw new Error("passkey authenticator requires a canonical lowercase RP ID");
  return value;
}

function normalizeOrigin(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("allowed passkey origins must be valid URLs");
  }
  if (!new Set(["https:", "http:"]).has(url.protocol) || url.origin === "null" || url.href !== `${url.origin}/`) {
    throw new Error("allowed passkey origins must contain only scheme, host, and port");
  }
  if (url.protocol === "http:" && !new Set(["localhost", "127.0.0.1", "[::1]"]).has(url.hostname)) {
    throw new Error("non-local passkey origins must use HTTPS");
  }
  return url.origin;
}

function decodeBinary(value, label, maxBytes) {
  let bytes;
  if (typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value)) {
    bytes = Buffer.from(value, "base64url");
    if (bytes.toString("base64url") !== value) throw new PasskeyAuthenticationError(`invalid_${label}`);
  } else if (Buffer.isBuffer(value)) {
    bytes = Buffer.from(value);
  } else if (ArrayBuffer.isView(value)) {
    bytes = Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  } else if (value instanceof ArrayBuffer) {
    bytes = Buffer.from(value);
  } else {
    throw new PasskeyAuthenticationError(`invalid_${label}`);
  }
  if (!bytes.length || bytes.length > maxBytes) throw new PasskeyAuthenticationError(`invalid_${label}`);
  return bytes;
}

function verifyAuthenticatorSignature(publicKey, data, signature) {
  try {
    if (publicKey.asymmetricKeyType === "ed25519") return verifySignature(null, data, publicKey, signature);
    if (publicKey.asymmetricKeyType === "rsa-pss") {
      return verifySignature("sha256", data, {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      }, signature);
    }
    return verifySignature("sha256", data, publicKey, signature);
  } catch {
    return false;
  }
}

function asPublicKey(key) {
  if (key?.type === "public") return key;
  if (key?.kty) return createPublicKey({ key, format: "jwk" });
  return createPublicKey(key);
}

function normalizeNonceStore(input) {
  if (!input) {
    const consumed = new Set();
    return {
      has: (nonce) => consumed.has(nonce),
      consume: (nonce) => {
        if (consumed.has(nonce)) return false;
        consumed.add(nonce);
        return true;
      },
    };
  }
  if (typeof input.has === "function" && typeof input.consume === "function") return input;
  if (typeof input.has === "function" && typeof input.add === "function") {
    return {
      has: (nonce) => input.has(nonce),
      consume: (nonce) => {
        if (input.has(nonce)) return false;
        input.add(nonce);
        return true;
      },
    };
  }
  throw new Error("nonceStore must implement has/consume or be a Set");
}

function checkedNow(now) {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error("now must return a valid Date");
  return value;
}

function safeEqual(left, right) {
  return left.length === right.length && timingSafeEqual(left, right);
}

function safeEqualString(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  return safeEqual(Buffer.from(left), Buffer.from(right));
}
