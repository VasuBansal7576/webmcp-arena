# Arena

Arena is a Human-vs-Agent Boundary Audit for WebMCP.

WebMCP tells an agent which tools a page exposes. Arena tests the claim behind the tool description: does the agent route preserve the authorization, approval, ownership, spending, and, when an adapter supplies authoritative disclosure evidence, data boundaries enforced by the human route? The hosted Checkout proof demonstrates authorization, approval binding, ownership, spending, and terminal settlement; it does not claim to measure data disclosure.

```text
Human route ─┐
             ├─ authoritative effects ─ compare ─ verdict ─ signed evidence
Agent route ─┘
```

Arena does not solve CAPTCHAs or declare an agent safe. It measures one scoped execution, waits for delayed effects to settle, and shows exactly where the two routes differ.

**Live challenge app:** [webmcp-arena.zippy17.chatgpt.site](https://webmcp-arena.zippy17.chatgpt.site)

## Hackathon work disclosure

Arena existed before the WebMCP Challenge. The dated Git history separates the two bodies of work:

- **Pre-existing work (June 21–26, 2026):** the original Agent Contract CLI, static site scanner, browser missions, delegation primitives, behavioral registry, and drift scoring. This work ends at [`966eccf`](https://github.com/VasuBansal7576/webmcp-arena/commit/966eccf).
- **WebMCP Challenge extension (August 30, 2026 onward):** the Human-vs-Agent Boundary Audit, Promise-returning `document.modelContext` registration in the hosted app, the owned Checkout target, paired effect measurement, exact-intent interface approval, server-attested and Ed25519-signed evidence, portable verification, D1 coordination, key rotation, and release gates. This work starts at [`beae996`](https://github.com/VasuBansal7576/webmcp-arena/commit/beae996); the complete dated extension is visible in the [`966eccf...main`](https://github.com/VasuBansal7576/webmcp-arena/compare/966eccf...main) comparison.

Only the challenge-window extension is presented for judging.

## Human-vs-Agent Checkout Proof

The main demo uses an owned Checkout fixture with two server-controlled implementations:

- `vulnerable`: `preview_checkout` returns a quote, then schedules a hidden $149 charge.
- `fixed`: the same tool returns the quote and requires confirmation, matching the human route.

The workflow is intentionally split:

1. An agent or human starts a server-owned preset.
2. Arena records the human baseline and prepares an exact contract.
3. The interface shows the target, tool, arguments, contract hash, invariants, and assurance tier.
4. The reviewer approves through a protected interface route carrying a one-time capability bound to that browser session and exact contract. No WebMCP approval tool exists.
5. Arena runs the agent route, waits for a terminal effect-settlement watermark, and records the final backend state.
6. The workbench verifies and displays the signed evidence bundle.

Caller-authored recipes, routes, traces, evidence, and approval claims are rejected. The reviewer can be a human or an authorized browser agent. This hosted proof measures Arena's owned server-attested route adapter; it does not claim that the target execution traversed a browser's native WebMCP channel. Cryptographic human presence is a separate, optional assurance tier.

## Run locally

Arena requires Node.js 22 or newer.

```bash
npm ci
npm test
npm start
```

Open `http://127.0.0.1:4173` for the full local workbench.

The hosted challenge application is a separate Vinext/Cloudflare surface:

```bash
npm run build:site
npm run start:site -- --port 4174
```

Open `http://127.0.0.1:4174`. The local hosted command explicitly enables one process-local signing identity for development, including public-key discovery and proof verification; it resets when the process restarts. Production fails closed and uses a configured Ed25519 key pair.

The hosted challenge application registers exactly two tools through the Promise-returning `document.modelContext.registerTool(...)` API:

- `start_generated_release_audit`
- `get_generated_release_audit_status`

The start tool prepares a server-owned, standards-shaped generated WebMCP manifest for visible exact-intent review. Arena binds the release, transitive owned-execution-stack artifact digest, claimed agent, tool definition, arguments, target, contract, browser session, nonce, and expiry before it executes the owned human and agent route adapter. The status tool is read-only. Neither tool can approve or execute a consequential route. `/checkout` separately registers `preview_checkout` on `document.modelContext` and labels its page-observed channel only as a registered WebMCP tool call. That page is an unsigned interactive standards demo and is never substituted for the server-attested evidence.

Completed hosted evidence is checked twice: a pure semantic verifier recomputes its release, target, account, agent, tool, argument, contract, coverage, and authorization-probe bindings, then Ed25519 verification resolves the signed key ID against the deployment trust set published at `/.well-known/arena-signing-keys.json`. The embedded public key is never treated as its own trust root. The singular `/.well-known/arena-signing-key.json` endpoint remains available for current-key compatibility, but portable proofs use the versioned trust set.

The full local workbench additionally registers:

- `inspect_boundary_bundle`
- incident-lab and evidence-export tools

Approval is deliberately absent from the WebMCP tool list. The interface remains usable in browsers without the experimental API.

## Static preflight

`arena preflight` is a bounded, non-behavioral inspection:

```bash
node ./bin/arena.js preflight https://example.com --format json
```

It provides:

- DNS-pinned public requests with private-network blocking and redirect revalidation.
- Sticky credential detachment after a redirect leaves the authorized origin.
- Time, redirect, compressed-response, decoded-response, and charset bounds.
- Validation of the HTML target, `robots.txt`, sitemap, `llms.txt`, Agent Skills, A2A, MCP, and optional OpenAPI data.
- Conservative inline and bounded same-origin bundle analysis that ignores comments, strings, JSON scripts, and commented markup; external scripts and module preloads use strict JavaScript MIME, redirect, time, count, and byte limits.
- Separate static WebMCP hints with no invented runtime or behavioral score.
- Query and fragment redaction in authenticated reports.

Static preflight can identify candidates. It cannot prove runtime registration, successful execution, or safety.

The repository also contains a composite GitHub Action; see `examples/github-action.yml`.

## Browser-backed owned-target test

The CLI retains an owned local Arena Gym adapter for native or compatibility-browser verification:

When installed as a package, invoke the same flow with `arena test --target ...`. From this repository, run:

```bash
node ./bin/arena.js test \
  --target "http://127.0.0.1:4317/?arena_version=fixed" \
  --fixture-token "replace-with-at-least-16-characters" \
  --browser-executable "/path/to/a-compatible-browser" \
  --browser-mode compatibility \
  --write-contract "/tmp/arena-contract.json" \
  --format json
```

Review the artifact, then run with `--approved-contract /tmp/arena-contract.json`. Direct hash review is also available through `--approve-contract <contract_hash>`.

Exit code `0` is a pass, `1` is a measured divergence, and `2` is review-required, inconclusive, or a setup failure. JSON, SARIF, and JUnit outputs are supported.

Compatibility mode installs a standards-shaped shim and labels the result `compatibility_shim`; it is not native WebMCP proof.

## Evidence and assurance

Arena separates three questions:

| Layer | Establishes | Does not establish |
| --- | --- | --- |
| Static preflight | Transport, support-file validity, conservative source candidates | Runtime tools or behavior |
| Runtime inspection | Registered definitions and browser invocation | Backend outcome by itself |
| Boundary audit | Paired observed or server-attested effects for one owned target run | Safety of arbitrary sites or future runs |

Checkout evidence is labelled `server_attested` and scoped to `owned_fixture:checkout`. A terminal settlement event and final state are required before a conclusive verdict can be signed. Missing or timed-out settlement produces an unsigned, inconclusive result.

Arena includes:

- Ed25519 evidence attestations with a hash chain.
- Exact tool, argument, target, contract, reviewer, nonce, and expiry commitments.
- A tested WebAuthn passkey verifier for origin, RP ID, credential ownership, user presence, user verification, counters, expiry, replay, and signature checks.
- Scoped agent delegations with expiry, amount limits, revocation, and idempotency.
- SQLite WAL persistence when the server is launched normally.

The hosted approval control proves traversal of the protected interface-session route; it does not claim biological-human presence. A deployment that claims WebAuthn assurance must register credentials and wire the included passkey verifier into that route.

## Production configuration

The full local workbench fails closed in production unless these are configured:

- `ARENA_SIGNING_SECRET`: at least 32 characters.
- `ARENA_OPERATOR_TOKEN`: at least 32 characters.
- `ARENA_TRUSTED_ISSUERS_JSON`: at least one configured agent-identity issuer.

The hosted challenge application fails closed unless both members of one verified Ed25519 pair are configured:

- `ARENA_SIGNING_PRIVATE_JWK`: private JWK JSON, stored as a secret.
- `ARENA_SIGNING_PUBLIC_JWK`: matching public JWK JSON.
- `ARENA_SIGNING_ARCHIVED_PUBLIC_JWKS`: optional JSON array containing at most 64 non-current trusted public Ed25519 JWKs. Despite the compatibility name, the list is used for both a prepublished next key and retired keys; it becomes required when keys rotate.

Rotate signing keys in two phases. First prepublish the next public key in `ARENA_SIGNING_ARCHIVED_PUBLIC_JWKS` and deploy without changing the active pair. Wait at least the 300-second trust-set cache TTL after that deployment. Then activate the matching new private/public pair while replacing the prepublished entry with the retired previous public key. Retain every retired key through the latest proof `retentionUntil`, and for at least 30 days after the last proof signed by that key. Removing it earlier makes an otherwise intact portable proof unverifiable.

`ARENA_ALLOW_EPHEMERAL_SIGNING=true` is for local development only and must not be enabled in production.

Remote WebMCP inspection and execution are disabled by default. Production blocks private-network targets. Use durable managed storage and protected signing keys for a multi-instance deployment; the included SQLite repository is intended for a single Arena instance.

## Current limitations

- Measured claims are limited to explicit owned-target adapters. Arena does not execute arbitrary third-party WebMCP sites and call the result trustworthy.
- Arena-issued local demo identities do not establish OpenAI, Anthropic, Google, or another vendor.
- The hosted approval boundary requires the same protected browser session and a one-time capability; an authorized browser agent can traverse it. Passkey authentication must be configured before claiming cryptographic human presence.
- Native WebMCP verification requires a compatible visible browser. Automated default tests do not launch an external browser.
- A valid Arena signature proves integrity and signer possession. Verifiers must still decide whether to trust that Arena instance and claim scope.

## Verify a release

```bash
npm test
npm run release:check
npm pack --dry-run --cache /tmp/arena-npm-cache
```

The release check enforces the package identity, exact source allowlist, dependency-safe GitHub Action, WebMCP registration source, focused documentation, and absence of retired plans and modules. Native-browser execution remains an explicit opt-in verification step.

## License

Arena is released under the [MIT License](LICENSE).
