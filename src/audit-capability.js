const CAPABILITY = /^[A-Za-z0-9_-]{32,128}$/;
const SESSION_COOKIE = "arena_session";
const AUDIT_START_WINDOW_MS = 10 * 60_000;
const AUDIT_START_POLICIES = Object.freeze([
  Object.freeze({ scope: "session", limit: 6 }),
  Object.freeze({ scope: "network", limit: 20 }),
  Object.freeze({ scope: "global", limit: 120 }),
]);

/**
 * @param {{
 *   request: Request,
 *   sessionHash: string,
 *   now: number,
 *   consume: (input: { bucketKey: string, now: number, limit: number, windowMs: number, scope: string }) => Promise<{ allowed: boolean, resetAt: number }>
 * }} input
 * @returns {Promise<{ allowed: true } | { allowed: false, resetAt: number, scope: string }>}
 */
export async function admitAuditStart({ request, sessionHash, now, consume }) {
  if (!(request instanceof Request) || !isDigest(sessionHash) || !Number.isInteger(now) ||
      typeof consume !== "function") {
    throw new TypeError("valid audit-start admission inputs are required");
  }
  const ingressIdentity = normalizedIngressIdentity(request);
  const identities = {
    global: "all-public-audit-starts",
    network: ingressIdentity,
    session: sessionHash,
  };

  for (const policy of AUDIT_START_POLICIES) {
    const bucketKey = `audit-start:v1:${await hashMaterial(`arena.audit-start.${policy.scope}.v1\0${identities[policy.scope]}`)}`;
    const result = await consume({
      bucketKey,
      now,
      limit: policy.limit,
      windowMs: AUDIT_START_WINDOW_MS,
      scope: policy.scope,
    });
    if (!result?.allowed) {
      if (!Number.isInteger(result?.resetAt)) throw new Error("audit-start limiter returned an invalid reset boundary");
      return { allowed: false, resetAt: result.resetAt, scope: policy.scope };
    }
  }
  return { allowed: true };
}

export async function ensureAuditSession(request) {
  const existing = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
  const sessionId = CAPABILITY.test(existing || "") ? existing : randomCapability(32);
  return {
    sessionId,
    sessionHash: await hashCapability(sessionId),
    setCookie: existing === sessionId ? null : serializeSessionCookie(sessionId, request.url),
  };
}

export async function createApprovalCapability(sessionHash) {
  if (!isDigest(sessionHash)) throw new Error("a valid session hash is required");
  const capability = randomCapability(32);
  return {
    capability,
    privateApproval: {
      capabilityHash: await hashCapability(capability),
      sessionHash,
      nonceId: randomCapability(18),
    },
  };
}

export async function verifyApprovalCapability(record, { capability, sessionId }) {
  const expected = record?.privateApproval;
  const proof = await approvalCapabilityProof({ capability, sessionId });
  if (!expected || !proof) return false;
  const { capabilityHash, sessionHash } = proof;
  return safeDigestEqual(expected.capabilityHash, capabilityHash) &&
    safeDigestEqual(expected.sessionHash, sessionHash);
}

export async function approvalCapabilityProof({ capability, sessionId }) {
  if (!CAPABILITY.test(capability || "") || !CAPABILITY.test(sessionId || "")) return null;
  const [capabilityHash, sessionHash] = await Promise.all([
    hashCapability(capability),
    hashCapability(sessionId),
  ]);
  return Object.freeze({ capabilityHash, sessionHash });
}

export function auditSessionFromRequest(request) {
  const value = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
  return CAPABILITY.test(value || "") ? value : null;
}

export function sameOriginMutation(request) {
  const expected = new URL(request.url).origin;
  return request.headers.get("origin") === expected &&
    request.headers.get("sec-fetch-site") === "same-origin" &&
    new Set(["cors", "same-origin"]).has(request.headers.get("sec-fetch-mode"));
}

export async function hashCapability(value) {
  if (typeof value !== "string" || !CAPABILITY.test(value)) throw new Error("invalid capability");
  return hashMaterial(value);
}

export async function hashAuditIdempotency({ sessionHash, version, key }) {
  if (!isDigest(sessionHash) || !new Set(["vulnerable", "fixed"]).has(version) ||
      typeof key !== "string" || !/^[A-Za-z0-9_-]{8,128}$/.test(key)) {
    throw new Error("invalid audit idempotency binding");
  }
  const material = `arena.hosted-audit.idempotency.v1\0${sessionHash}\0${version}\0${key}`;
  return hashMaterial(material);
}

export function randomCapability(byteLength = 32) {
  if (!Number.isSafeInteger(byteLength) || byteLength < 16 || byteLength > 64) throw new Error("invalid capability length");
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

function readCookie(header, name) {
  for (const part of String(header || "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0 || part.slice(0, index).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

function serializeSessionCookie(value, requestUrl) {
  const secure = new URL(requestUrl).protocol === "https:" ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=600; HttpOnly; SameSite=Strict${secure}`;
}

function normalizedIngressIdentity(request) {
  const cloudflareIngressIp = request.headers.get("cf-connecting-ip")?.trim();
  if (!cloudflareIngressIp) return "shared-unattributed-cloudflare-ingress";
  return cloudflareIngressIp.slice(0, 128).toLowerCase();
}

async function hashMaterial(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

function safeDigestEqual(left, right) {
  if (!isDigest(left) || !isDigest(right)) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function isDigest(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/.test(value);
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
