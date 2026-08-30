import { createPublicKey, verify } from "node:crypto";

const SUPPORTED_ALGORITHMS = new Set(["EdDSA", "RS256", "ES256"]);

export class AgentIdentityError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "AgentIdentityError";
    this.code = code;
  }
}

export function createTrustedIssuerVerifier({
  issuers = [],
  fetch: fetchImpl = globalThis.fetch,
  now = () => new Date(),
  clockSkewSeconds = 30,
  maxTokenAgeSeconds = 300,
  jwksCacheSeconds = 300,
} = {}) {
  const trusted = new Map(issuers.map(normalizeIssuer).map((issuer) => [issuer.issuer, issuer]));
  const cache = new Map();
  if (trusted.size && typeof fetchImpl !== "function") throw new Error("trusted issuer verification requires fetch");

  async function verifyAgentToken(token) {
    const decoded = decodeJwt(token);
    const issuer = trusted.get(decoded.payload.iss);
    if (!issuer) throw new AgentIdentityError("untrusted_issuer");
    if (!issuer.algorithms.includes(decoded.header.alg) || !SUPPORTED_ALGORITHMS.has(decoded.header.alg)) {
      throw new AgentIdentityError("algorithm_not_allowed");
    }
    if (!decoded.header.kid) throw new AgentIdentityError("missing_key_id");
    validateClaims(decoded.payload, issuer, now(), clockSkewSeconds, maxTokenAgeSeconds);
    const jwk = await findKey(issuer, decoded.header, cache, fetchImpl, now, jwksCacheSeconds);
    const key = createPublicKey({ key: jwk, format: "jwk" });
    if (!verifySignature(decoded.header.alg, decoded.signingInput, decoded.signature, key)) {
      throw new AgentIdentityError("invalid_signature");
    }
    const agentId = decoded.payload[issuer.agentIdClaim] || decoded.payload.sub;
    if (!agentId) throw new AgentIdentityError("missing_agent_id");
    return {
      verified: true,
      issuer: issuer.issuer,
      subject: decoded.payload.sub,
      agent_id: String(agentId),
      token_id: decoded.payload.jti || null,
      algorithm: decoded.header.alg,
    };
  }

  return { verifyAgentToken, trustedIssuers: () => [...trusted.keys()] };
}

function normalizeIssuer(input) {
  if (!input?.issuer || !input?.audience || !input?.jwksUri) throw new Error("trusted issuer requires issuer, audience, and jwksUri");
  const issuer = new URL(input.issuer);
  const jwks = new URL(input.jwksUri);
  if (issuer.protocol !== "https:" || jwks.protocol !== "https:") throw new Error("trusted issuer and JWKS URLs must use HTTPS");
  const algorithms = input.algorithms?.length ? [...new Set(input.algorithms)] : ["EdDSA", "RS256"];
  if (algorithms.some((algorithm) => !SUPPORTED_ALGORITHMS.has(algorithm))) throw new Error("trusted issuer configured an unsupported JWT algorithm");
  return {
    issuer: issuer.href.replace(/\/$/, ""),
    audience: String(input.audience),
    jwksUri: jwks.href,
    algorithms,
    agentIdClaim: input.agentIdClaim || "agent_id",
  };
}

function decodeJwt(token) {
  if (typeof token !== "string" || token.length > 16_384) throw new AgentIdentityError("invalid_token_format");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) throw new AgentIdentityError("invalid_token_format");
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    if (!header || typeof header !== "object" || !payload || typeof payload !== "object") throw new Error("not objects");
    if (header.crit) throw new AgentIdentityError("unsupported_critical_header");
    if (header.typ && String(header.typ).toUpperCase() !== "JWT") throw new AgentIdentityError("invalid_token_type");
    return {
      header,
      payload,
      signingInput: Buffer.from(`${parts[0]}.${parts[1]}`),
      signature: Buffer.from(parts[2], "base64url"),
    };
  } catch (error) {
    if (error instanceof AgentIdentityError) throw error;
    throw new AgentIdentityError("invalid_token_format");
  }
}

function validateClaims(payload, issuer, currentDate, skewSeconds, maxTokenAgeSeconds) {
  if (payload.iss !== issuer.issuer) throw new AgentIdentityError("issuer_mismatch");
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(issuer.audience)) throw new AgentIdentityError("audience_mismatch");
  if (!payload.sub) throw new AgentIdentityError("missing_subject");
  const current = Math.floor(currentDate.getTime() / 1000);
  if (!Number.isFinite(payload.iat)) throw new AgentIdentityError("missing_issued_at");
  if (!Number.isFinite(payload.exp)) throw new AgentIdentityError("missing_expiration");
  if (payload.iat > current + skewSeconds) throw new AgentIdentityError("issued_in_future");
  if (payload.nbf !== undefined && (!Number.isFinite(payload.nbf) || payload.nbf > current + skewSeconds)) throw new AgentIdentityError("not_yet_valid");
  if (payload.exp <= current - skewSeconds) throw new AgentIdentityError("identity_token_expired");
  if (payload.exp - payload.iat > maxTokenAgeSeconds) throw new AgentIdentityError("identity_token_too_long_lived");
}

async function findKey(issuer, header, cache, fetchImpl, now, cacheSeconds) {
  let entry = cache.get(issuer.jwksUri);
  if (!entry || entry.expiresAt <= now().getTime()) {
    const response = await fetchImpl(issuer.jwksUri, { headers: { accept: "application/json" }, redirect: "error" });
    if (!response.ok) throw new AgentIdentityError("jwks_fetch_failed");
    const text = await response.text();
    if (text.length > 262_144) throw new AgentIdentityError("jwks_response_too_large");
    let document;
    try {
      document = JSON.parse(text);
    } catch {
      throw new AgentIdentityError("invalid_jwks");
    }
    if (!Array.isArray(document.keys)) throw new AgentIdentityError("invalid_jwks");
    entry = { keys: document.keys, expiresAt: now().getTime() + cacheSeconds * 1000 };
    cache.set(issuer.jwksUri, entry);
  }
  const candidates = entry.keys.filter((key) => key.kid === header.kid && (!key.alg || key.alg === header.alg) && (!key.use || key.use === "sig"));
  if (candidates.length !== 1) throw new AgentIdentityError(candidates.length ? "ambiguous_signing_key" : "signing_key_not_found");
  return candidates[0];
}

function verifySignature(algorithm, signingInput, signature, key) {
  if (algorithm === "EdDSA") return verify(null, signingInput, key, signature);
  if (algorithm === "RS256") return verify("RSA-SHA256", signingInput, key, signature);
  if (algorithm === "ES256") return verify("sha256", signingInput, { key, dsaEncoding: "ieee-p1363" }, signature);
  return false;
}
