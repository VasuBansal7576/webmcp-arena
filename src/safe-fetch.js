import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";

import { resolveAllowedTarget } from "./webmcp-runner.js";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;
const FORBIDDEN_HEADERS = new Set(["host", "content-length", "connection", "transfer-encoding"]);

export async function fetchTextSafely(input, options = {}) {
  const requested = await allowedTarget(input, options);
  const redirectOrigin = options.sameOriginRedirectsOnly === true ? requested.url.origin : null;
  const authOrigin = authorizedOrigin(options.authOrigin || requested.url.origin);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error("request timed out")), options.timeoutMs ?? 15_000);
  const maxBytes = validMaxBytes(options.maxBytes ?? DEFAULT_MAX_BYTES);
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 20) {
    throw new Error("maxRedirects must be between 0 and 20");
  }
  let current = requested;
  let credentialsDetached = false;

  try {
    for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
      const transport = options.transport || requestTextPinned;
      const response = await transport({
        url: new URL(current.url.href),
        pinnedAddress: current.pinnedAddress,
        signal: controller.signal,
        headers: requestHeaders(options, !credentialsDetached && current.url.origin === authOrigin),
        maxBytes,
      });
      const normalized = normalizeTransportResponse(response, maxBytes);
      if (!REDIRECT_STATUSES.has(normalized.status)) {
        return {
          ok: normalized.status >= 200 && normalized.status < 300,
          requestedUrl: requested.url.href,
          url: current.url.href,
          status: normalized.status,
          contentType: normalized.headers["content-type"] || "",
          headers: normalized.headers,
          text: normalized.text,
        };
      }
      const location = normalized.headers.location;
      if (!location) throw new Error("redirect response is missing a Location header");
      if (redirects === maxRedirects) throw new Error("redirect limit exceeded");
      const redirectTarget = new URL(location, current.url);
      if (redirectOrigin && redirectTarget.origin !== redirectOrigin) {
        throw new Error("redirect target leaves the requested origin");
      }
      const next = await allowedTarget(redirectTarget, options);
      if (next.url.origin !== current.url.origin) credentialsDetached = true;
      current = next;
    }
    throw new Error("redirect limit exceeded");
  } finally {
    clearTimeout(timeout);
  }
}

async function allowedTarget(input, options) {
  const candidate = input instanceof URL ? new URL(input.href) : new URL(String(input));
  if (options.allowPrivateTargets === true) {
    if (!new Set(["http:", "https:"]).has(candidate.protocol) || candidate.username || candidate.password) {
      throw new Error("only credential-free HTTP(S) URLs are allowed");
    }
    return { url: candidate, hostname: candidate.hostname, pinnedAddress: null };
  }
  return resolveAllowedTarget(candidate.href, {
    allowPrivateTargets: false,
    ...(typeof options.lookup === "function" ? { lookup: options.lookup } : {}),
  });
}

function authorizedOrigin(value) {
  const url = new URL(String(value));
  if (!new Set(["http:", "https:"]).has(url.protocol) || url.username || url.password) {
    throw new Error("authOrigin must be a credential-free HTTP(S) origin");
  }
  return url.origin;
}

function requestHeaders(options, includeAuth) {
  const headers = {
    "user-agent": options.userAgent || "ArenaWebMCP/0.2 (+https://github.com/VasuBansal7576/webmcp-arena)",
    accept: options.accept || "text/html,application/json,text/plain,*/*",
    "accept-encoding": "gzip, deflate, br",
  };
  if (!includeAuth) return headers;
  for (const [rawName, rawValue] of Object.entries(options.auth?.headers || {})) {
    const name = String(rawName).toLowerCase();
    if (FORBIDDEN_HEADERS.has(name)) continue;
    headers[name] = String(rawValue);
  }
  return headers;
}

function requestTextPinned({ url, pinnedAddress, signal, headers, maxBytes }) {
  return new Promise((resolve, reject) => {
    const request = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, {
      method: "GET",
      headers,
      signal,
      agent: false,
      ...(pinnedAddress ? { lookup: pinnedLookup(pinnedAddress) } : {}),
    }, (response) => {
      const responseHeaders = normalizeHeaders(response.headers);
      const declared = Number(responseHeaders["content-length"]);
      if (Number.isFinite(declared) && declared > maxBytes) {
        response.destroy();
        reject(new Error("response body exceeds the configured byte limit"));
        return;
      }
      let stream;
      try {
        stream = decodedStream(response, responseHeaders["content-encoding"] || "");
      } catch (error) {
        response.destroy();
        reject(error);
        return;
      }
      const chunks = [];
      let size = 0;
      stream.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          stream.destroy(new Error("response body exceeds the configured byte limit"));
          return;
        }
        chunks.push(Buffer.from(chunk));
      });
      stream.once("error", reject);
      stream.once("end", () => {
        const bytes = Buffer.concat(chunks, size);
        resolve({
          status: response.statusCode || 0,
          headers: responseHeaders,
          text: decodeText(bytes, responseHeaders["content-type"] || ""),
        });
      });
    });
    request.once("error", reject);
    request.end();
  });
}

function pinnedLookup(address) {
  const family = isIP(address);
  if (!family) throw new Error("resolved target address is invalid");
  return (_hostname, options, callback) => {
    if (options?.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

function decodedStream(response, encoding) {
  const normalized = String(encoding).trim().toLowerCase();
  if (!normalized || normalized === "identity") return response;
  if (normalized === "gzip" || normalized === "x-gzip") return response.pipe(createGunzip());
  if (normalized === "deflate") return response.pipe(createInflate());
  if (normalized === "br") return response.pipe(createBrotliDecompress());
  throw new Error(`unsupported content encoding: ${normalized}`);
}

function decodeText(bytes, contentType) {
  const charset = String(contentType).match(/;\s*charset\s*=\s*["']?([^;"'\s]+)/i)?.[1] || "utf-8";
  try {
    return new TextDecoder(charset).decode(bytes);
  } catch {
    throw new Error(`unsupported response charset: ${charset}`);
  }
}

function normalizeTransportResponse(response, maxBytes) {
  if (!response || !Number.isInteger(response.status) || response.status < 100 || response.status > 599) {
    throw new Error("safe fetch transport returned an invalid HTTP status");
  }
  const headers = normalizeHeaders(response.headers || {});
  if (typeof response.text !== "string") throw new Error("safe fetch transport must return text");
  if (Buffer.byteLength(response.text) > maxBytes) throw new Error("response body exceeds the configured byte limit");
  return { status: response.status, headers, text: response.text };
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [rawName, rawValue] of Object.entries(headers)) {
    if (rawValue === undefined) continue;
    normalized[String(rawName).toLowerCase()] = Array.isArray(rawValue) ? rawValue.join(", ") : String(rawValue);
  }
  return normalized;
}

function validMaxBytes(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 16 * 1024 * 1024) {
    throw new Error("maxBytes must be between 1 and 16777216");
  }
  return value;
}
