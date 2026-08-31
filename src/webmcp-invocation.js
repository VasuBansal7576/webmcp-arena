const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RECEIPT_FIELDS = Object.freeze([
  "argumentsHash",
  "auditId",
  "backendTraceRoot",
  "channel",
  "invocationLeaseCommitment",
  "invokedAt",
  "kind",
  "pageOrigin",
  "requestHash",
  "resultHash",
  "settledAt",
  "sessionCommitment",
  "toolDefinitionHash",
  "toolName",
  "version",
]);

/**
 * @param {{
 *   auditId: string,
 *   review: {toolName: string, toolDefinitionHash: string, argumentsHash: string},
 *   approval: {sessionCommitment: string},
 *   pageOrigin: string,
 *   invocationLease: string,
 *   invokedAt?: string,
 * }} input
 */
export async function createWebMcpInvocationReceipt({
  auditId,
  review,
  approval,
  pageOrigin,
  invocationLease,
  invokedAt = new Date().toISOString(),
}) {
  validateInputs({ auditId, review, approval, pageOrigin, invocationLease, invokedAt });
  const invocationLeaseCommitment = await sha256Base64Url(`arena.webmcp-invocation-lease.v1\0${invocationLease}`);
  const request = {
    auditId,
    pageOrigin,
    sessionCommitment: approval.sessionCommitment,
    toolName: review.toolName,
    toolDefinitionHash: review.toolDefinitionHash,
    argumentsHash: review.argumentsHash,
    invocationLeaseCommitment,
    invokedAt,
  };
  return Object.freeze({
    kind: "arena.webmcp_invocation_receipt",
    version: 1,
    channel: "registered_webmcp_callback",
    ...request,
    requestHash: await sha256Base64Url(canonicalJson(request)),
  });
}

export async function finalizeWebMcpInvocationReceipt(prepared, {
  result,
  backendTraceRoot,
  settledAt = new Date().toISOString(),
} = {}) {
  if (!isPreparedReceipt(prepared) || !DIGEST.test(backendTraceRoot || "") || !isCanonicalTimestamp(settledAt) ||
      Date.parse(settledAt) < Date.parse(prepared.invokedAt)) {
    throw new Error("a valid prepared callback receipt, trace root, and settlement time are required");
  }
  return Object.freeze({
    ...structuredClone(prepared),
    resultHash: await sha256Base64Url(canonicalJson(result)),
    backendTraceRoot,
    settledAt,
  });
}

export async function verifyPreparedWebMcpInvocationReceipt(receipt, { auditId, review, approval } = {}) {
  try {
    if (!isPreparedReceipt(receipt) || receipt.auditId !== auditId ||
        receipt.toolName !== review?.toolName || receipt.toolDefinitionHash !== review?.toolDefinitionHash ||
        receipt.argumentsHash !== review?.argumentsHash || receipt.sessionCommitment !== approval?.sessionCommitment) {
      return invalid("webmcp_invocation_request_invalid");
    }
    const request = {
      auditId: receipt.auditId,
      pageOrigin: receipt.pageOrigin,
      sessionCommitment: receipt.sessionCommitment,
      toolName: receipt.toolName,
      toolDefinitionHash: receipt.toolDefinitionHash,
      argumentsHash: receipt.argumentsHash,
      invocationLeaseCommitment: receipt.invocationLeaseCommitment,
      invokedAt: receipt.invokedAt,
    };
    if (receipt.requestHash !== await sha256Base64Url(canonicalJson(request))) {
      return invalid("webmcp_invocation_request_hash_mismatch");
    }
    return { valid: true };
  } catch {
    return invalid("webmcp_invocation_request_invalid");
  }
}

export async function verifyWebMcpInvocationReceipt(receipt, {
  auditId,
  review,
  approval,
  result,
  backendTraceRoot,
} = {}) {
  try {
    if (!isPlainObject(receipt) || !hasExactKeys(receipt, RECEIPT_FIELDS) ||
        receipt.kind !== "arena.webmcp_invocation_receipt" || receipt.version !== 1 ||
        receipt.channel !== "registered_webmcp_callback" || receipt.auditId !== auditId ||
        receipt.toolName !== review?.toolName || receipt.toolDefinitionHash !== review?.toolDefinitionHash ||
        receipt.argumentsHash !== review?.argumentsHash || receipt.sessionCommitment !== approval?.sessionCommitment ||
        receipt.backendTraceRoot !== backendTraceRoot || !DIGEST.test(receipt.invocationLeaseCommitment || "") ||
        !validOrigin(receipt.pageOrigin) || !isCanonicalTimestamp(receipt.invokedAt) ||
        !isCanonicalTimestamp(receipt.settledAt) || Date.parse(receipt.settledAt) < Date.parse(receipt.invokedAt)) {
      return invalid("webmcp_invocation_receipt_schema_invalid");
    }
    const request = {
      auditId: receipt.auditId,
      pageOrigin: receipt.pageOrigin,
      sessionCommitment: receipt.sessionCommitment,
      toolName: receipt.toolName,
      toolDefinitionHash: receipt.toolDefinitionHash,
      argumentsHash: receipt.argumentsHash,
      invocationLeaseCommitment: receipt.invocationLeaseCommitment,
      invokedAt: receipt.invokedAt,
    };
    if (receipt.requestHash !== await sha256Base64Url(canonicalJson(request))) {
      return invalid("webmcp_invocation_request_hash_mismatch");
    }
    if (receipt.resultHash !== await sha256Base64Url(canonicalJson(result))) {
      return invalid("webmcp_invocation_result_hash_mismatch");
    }
    return { valid: true };
  } catch {
    return invalid("webmcp_invocation_receipt_invalid");
  }
}

export async function hashWebMcpInvocationArguments(value) {
  if (!isPlainObject(value)) throw new Error("WebMCP invocation arguments must be an object");
  return sha256Base64Url(canonicalJson(value));
}

function validateInputs({ auditId, review, approval, pageOrigin, invocationLease, invokedAt }) {
  if (!UUID.test(auditId || "")) throw new Error("a valid audit id is required");
  if (!isPlainObject(review) || typeof review.toolName !== "string" || !review.toolName ||
      !DIGEST.test(review.toolDefinitionHash || "") || !DIGEST.test(review.argumentsHash || "") ||
      !isPlainObject(approval) || !DIGEST.test(approval.sessionCommitment || "")) {
    throw new Error("a valid reviewed invocation and approval are required");
  }
  if (!validOrigin(pageOrigin)) throw new Error("a canonical HTTP(S) page origin is required");
  if (!UUID.test(invocationLease || "")) throw new Error("a valid invocation lease is required");
  if (!isCanonicalTimestamp(invokedAt)) throw new Error("a canonical invocation timestamp is required");
}

function isPreparedReceipt(value) {
  if (!isPlainObject(value)) return false;
  const expected = RECEIPT_FIELDS.filter((field) => !new Set(["backendTraceRoot", "resultHash", "settledAt"]).has(field));
  return hasExactKeys(value, expected) && value.kind === "arena.webmcp_invocation_receipt" &&
    value.version === 1 && value.channel === "registered_webmcp_callback" &&
    DIGEST.test(value.requestHash || "") && DIGEST.test(value.invocationLeaseCommitment || "") &&
    validOrigin(value.pageOrigin) && isCanonicalTimestamp(value.invokedAt);
}

function validOrigin(value) {
  try {
    const url = new URL(value);
    return new Set(["https:", "http:"]).has(url.protocol) && url.origin === value &&
      !url.username && !url.password && !url.search && !url.hash && url.pathname === "/";
  } catch {
    return false;
  }
}

function isCanonicalTimestamp(value) {
  const epoch = Date.parse(String(value));
  return Number.isFinite(epoch) && new Date(epoch).toISOString() === value;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function hasExactKeys(value, keys) {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalid(reason) {
  return { valid: false, reason };
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  let binary = "";
  for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
