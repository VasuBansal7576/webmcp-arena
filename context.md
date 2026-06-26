# Agent Contract OS Context

Source of truth: what is listed under **Implemented** is already built in this repo.
Do not re-implement those items; inspect and extend the existing code instead.
Use `architecture_v3.md` for bounded technical next steps, not implementation truth.

## What This Project Is

Agent Contract OS is a local production CLI that turns a website or product surface into evidence about whether AI agents can understand it, navigate it, respect its policy boundaries, and produce reviewable artifacts. It combines passive agent-traffic log analysis, static agent-readiness checks, browser-backed synthetic missions, `.agent/` contract export, report-only CI gates, fix packs, policy audits, repo scans, OTLP JSON traces, and the first local Agent Session Membrane primitives.

The project is a proof-and-repair tool for agent compatibility. It is not a pitch deck, planning archive, benchmark paper reproduction, market-validation tracker, or fake demo layer.

## Implemented

- CLI commands: `logs`, `scan`, `contract`, `gate`, `monitor`, `fixpack`, `pr-prep`, `policy-audit`, and `repo-scan`.
- Standalone `agent-traffic-parser` binary that reuses the `logs` command.
- Passive analytics for NGINX and CloudFront logs, including ClaudeBot, GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, and Google-Extended.
- Static URL checks for `robots.txt`, sitemap, `llms.txt`, `agent-skills`, JSON-LD, JS-only HTML, cookie blockers, slider/switch controls, datagrid filtering, A/B variant markers, WebMCP registration markers, sampled broken links, OpenAPI quality, MCP manifests, and dangerous MCP tools.
- Static findings carry taxonomy/framing metadata, and the JS-only check records DOM token metrics.
- Static analysis emits Content Position Index for critical elements and IPI risk findings for suspicious hidden/accessibility instructions.
- Findings include AWI dimensions and reproducibility hashes for element-like CPI/IPI evidence.
- Layer 1 Agent Session Membrane primitives: `membrane-baseline` builds a clean runtime baseline from scanner output, `membrane-snippet` emits a browser-side SHA-256 beacon snippet, and `membrane-check` compares runtime observations against the baseline to emit deviation events.
- Layer 2 local Agent Behavioral Registry primitives: `abr-ingest` stores normalized session/action records from membrane or behavior events, and `abr-score` computes weighted per-agent conformance scores from declarations and observed actions.
- Layer 3 local Drift Score API primitives: `drift-score` exposes ABR conformance as an API-shaped access decision, and `drift-waf-rule` emits NGINX, Cloudflare, and Fastly integration templates.
- Readiness includes AWI six-axis sub-scores, and WebMCP detection includes annotated/unannotated component coverage plus a local CI4A-style completion-rate ceiling estimate.
- Static checks fetch `/.agent/contract.json` for `agent_auth` declarations and emit `agent_auth_undeclared` when missing.
- Static checks fetch `/.well-known/agent.json`, validate minimal A2A Agent Card fields, and emit `a2a_card_absent`, `a2a_card_invalid`, or `a2a_card_valid`.
- `.agent/` contract export with `contract.json`, `missions.yml`, `policies.yml`, `llms.txt`, `llms-full.txt`, `agent-skills/index.json`, `openapi-patches.json`, policy pack, and evidence snapshots.
- Split-ready `.agent` spec material in `spec/`.
- Report-only CI gate with HTML, Markdown, JSON, and OTLP JSON trace outputs.
- OTLP JSON uses current GenAI semconv-aligned agent/workflow attributes without faking model calls.
- GitHub composite action with optional PR comments.
- Browser-backed synthetic missions default to `understand_company`, `find_pricing`, and `find_api_quickstart`.
- Opt-in standard missions include `create_first_api_request`, `find_refund_policy`, and `use_mcp_tool_if_available` via `--mission-ids`.
- Mission evidence includes screenshots, AXTree text, token estimates, context-budget breakdowns, deterministic Prune4Web-style pricing slices, standalone pruning artifacts, and shared mission cache reuse.
- Generated `missions.yml` includes primitive step decompositions, and `gate` validates mission primitives before returning CI status.
- Diff-based monitor that hashes pages, skips unchanged pages, and reruns affected checks/missions.
- Monitor state also tracks MCP tool-description hashes when an MCP manifest is supplied.
- Fix pack export for `llms.txt`, JSON-LD, OpenAPI patch suggestions, and RFC 9457 problem-details examples.
- Fix packs can include observed agent-traffic token-load projection when logs are supplied.
- Fix packs include CPI advice and Sonnet input-cost estimates from logs or a labeled baseline when mission/log data is available.
- Fix packs include `agent_auth` and A2A Agent Card templates when those declarations are missing or invalid.
- Fix packs include an MCP security checklist when an MCP manifest is supplied.
- Optional LLM fix explanation, gated by explicit provider config.
- Local PR prep that applies fix packs on a git branch and records audit evidence. Remote PR creation requires explicit confirmation.
- Env-backed private runner auth profiles with redacted evidence.
- Enterprise policy audit over `.agent/contract.json`, including MCP spec-version comparison and compliance delta.
- Contracts include CuP scoring across six local policy dimensions and MCP spec-version compliance fields.
- Gate output includes local CuP pass/fail status from mission, consent, auth-wall, MCP-danger, and rate-limit signals.
- Repo scan for `.agent/contract.json`, `llms.txt`, OpenAPI files, and CI gate wiring.
- Local Solo web shell at `npm run solo`, built as a thin wrapper around the existing scanner and fix-pack path.
- Local sourced positioning-post draft in `docs/positioning-post.md`.
- `CONTRIBUTING.md` documents rendering-mode discipline: Layer 3 static checks stay simple-mode, while Playwright/screenshots stay in Layer 4 mission evidence.

## Proven Locally

```bash
npm test
npm run smoke
npm run release:check
npm pack --dry-run
```

## Interpretation Boundaries

- AWI six-axis scoring is derived from local scanner signals; it is not a validated industry benchmark score.
- CuP scoring is local policy-dimension scoring over current contract evidence; it is not a full ST-WebAgentBench reproduction.
- WebMCP component coverage is static detection of annotations/markers; it is not real browser tool execution.
- A2A Agent Card validation is static JSON validation plus basic endpoint reachability; it is not delegated A2A task execution.
- Agent identity support is declaration detection only; it does not verify payment-network identity, DIDs, verifiable credentials, or liability shift.
- Cost-at-scale is a token-load projection from observed logs and DOM token metrics; it is not provider billing proof.
- OTel GenAI model/provider/token attributes are emitted only when explicitly supplied; the CLI does not fake model usage from DOM token estimates.
- Mission primitive validation is static schema hygiene over `missions.yml`; it does not prove a mission can complete in a browser.
- Rendering-mode discipline is documented and followed by current code paths; it is not enforced by a separate linter.
- Layer 1 membrane events are hash-based deviation detection only; they do not attribute intent, prove an attack, or identify who introduced a change.
- Layer 2 ABR scores are local file-based conformance calculations over supplied events and declarations; they are not corpus-level reputation or ground-truth intent.
- Layer 3 drift decisions are local API-shaped outputs and WAF templates; they are not a hosted reputation API, live WAF enforcement, or statistically meaningful corpus signal.
- The browser snippet captures rendered DOM hashes from the client side; it is not the raw HTTP response hook described for a production NGINX/Cloudflare install.
- Smoke artifacts are local proof that the CLI paths run; they are not customer or production proof.

## Not Proven Here

- Customer log access.
- Real production traffic.
- Real site membrane installation.
- Continuous runtime event stream from production sessions.
- Server-side NGINX/Cloudflare raw-response capture.
- Hosted Layer 3 Drift Score API or live WAF integrations.
- Layer 4 dual-signed session receipts.
- Layer 5 causal attribution graph.
- Layer 6 counterfactual replay.
- Company pilots or LOIs.
- Real enterprise deployment.
- Real MCP server in the wild.
- Public article/channel publication.
- Public package publication.
- Public standard adoption.
- GitHub stars or external usage.
- 10-site real-world audit corpus.
- Corpus-level performance claims.
- Compliance buyer validation.
- Checkout/signup/payment missions.
- WebMCP tool execution.
- A2A delegated task execution.
- Payment-network agent identity verification.
- Unreviewed auto-PR behavior.

## Current Rule

Keep this file current. Delete or replace stale plans instead of leaving them in root; git history is the archive.
