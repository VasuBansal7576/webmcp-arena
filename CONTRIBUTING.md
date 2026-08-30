# Contributing

Arena treats evidence boundaries as security boundaries.

Use Node.js 22 or newer. Write a failing public-interface test before changing behavior, then run:

```bash
npm test
npm run release:check
```

Keep these invariants:

- Caller-authored traces never become measured evidence.
- Human and agent trials remain isolated and share only a stable seed.
- Approval binds the exact contract hash, tool definition, arguments, and target.
- A changed or expired binding stops before agent execution.
- A conclusive result requires a terminal effect-settlement watermark and final state.
- Page assertions are non-authoritative.
- Compatibility evidence is never labelled native.
- Route parity and baseline safety remain separate results.
- Static preflight never claims runtime WebMCP behavior.
- Public scanner requests stay DNS-pinned; credentials never return after a cross-origin redirect.
- Approval is never exposed as a WebMCP tool; it must traverse the protected interface-session route.

The measured `arena test` flow requires the exact contract hash or a reviewed external artifact. Do not replace it with blanket approval.

Before opening a change, verify the smallest relevant test, the full browser-free suite, the release contract, and the package dry run. Browser-dependent checks are explicit opt-ins; do not run an external browser when validation is required to stay inside Codex's built-in browser.
