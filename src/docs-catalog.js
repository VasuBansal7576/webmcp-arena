export const ARENA_CANONICAL_ORIGIN = "https://webmcp-arena.zippy17.chatgpt.site";

export const ARENA_DOCS = Object.freeze([
  { kind: "tutorial", title: "Quickstart", path: "/docs/quickstart", summary: "Create an adapter and gate a signed proof." },
  { kind: "explanation", title: "The human–agent boundary", path: "/docs/concepts/human-agent-boundary", summary: "Why route parity means security outcomes, not identical clicks." },
  { kind: "reference", title: "WebMCP tools", path: "/docs/reference/webmcp-tools", summary: "Hosted tools, invocation lifecycle, and response contracts." },
  { kind: "reference", title: "Proof format", path: "/docs/reference/proof-format", summary: "Portable envelope and signed callback commitments." },
  { kind: "reference", title: "Error codes", path: "/docs/reference/error-codes", summary: "Stable failure codes and retry behavior." },
  { kind: "use_case", title: "Document sharing", path: "/use-cases/document-sharing", summary: "Catch recipient, visibility, and data-boundary bypasses." },
  { kind: "essay", title: "Why CAPTCHAs are the wrong boundary", path: "/blog/why-captchas-are-the-wrong-boundary", summary: "Authorize agents by identity, delegation, and limits—not imitation." },
  { kind: "essay", title: "WebMCP tools need behavioral proof", path: "/blog/webmcp-tools-need-behavioral-proof", summary: "Schemas declare intent; settled effects establish behavior." },
]);

export const ARENA_ERROR_CODES = Object.freeze([
  { code: "invocation_requires_registered_callback", retryable: false, meaning: "The request did not traverse Arena's same-origin callback boundary." },
  { code: "invocation_session_missing", retryable: false, meaning: "The browser session expired or was not present." },
  { code: "invocation_lease_expired", retryable: false, meaning: "The approved single-use invocation window expired; prepare a new audit." },
  { code: "invocation_binding_mismatch", retryable: false, meaning: "Session, tool, definition, arguments, or lease differed from the approved intent." },
  { code: "invocation_already_consumed", retryable: false, meaning: "A concurrent call or replay attempted to reuse the lease." },
  { code: "proof_generation_failed", retryable: true, meaning: "Execution was claimed but signed evidence could not be completed." },
]);

export function absoluteDocsCatalog(origin = ARENA_CANONICAL_ORIGIN) {
  return ARENA_DOCS.map((entry) => Object.freeze({ ...entry, url: new URL(entry.path, origin).href }));
}
