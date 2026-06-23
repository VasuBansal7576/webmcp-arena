# Agent Contract OS Context

Source of truth: what is listed under **Implemented** is already built in this repo.
Do not re-implement those items; inspect and extend the existing code instead.
Use `architecture_hardening.md` for bounded technical next steps, not implementation truth.

This repo is a local production CLI for proving whether a product surface works for AI agents. It is not a pitch deck or planning archive.

## Implemented

- CLI commands: `logs`, `scan`, `contract`, `gate`, `monitor`, `fixpack`, `pr-prep`, `policy-audit`, and `repo-scan`.
- Standalone `agent-traffic-parser` binary that reuses the `logs` command.
- Passive analytics for NGINX and CloudFront logs, including ClaudeBot, GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, and Google-Extended.
- Static URL checks for `robots.txt`, sitemap, `llms.txt`, `agent-skills`, JSON-LD, JS-only HTML, cookie blockers, slider/switch controls, datagrid filtering, A/B variant markers, WebMCP registration markers, sampled broken links, OpenAPI quality, MCP manifests, and dangerous MCP tools.
- Static findings carry taxonomy/framing metadata, and the JS-only check records DOM token metrics.
- Readiness includes AWI six-axis sub-scores, and WebMCP detection includes component coverage metadata.
- `.agent/` contract export with `contract.json`, `missions.yml`, `policies.yml`, `llms.txt`, `llms-full.txt`, `agent-skills/index.json`, `openapi-patches.json`, policy pack, and evidence snapshots.
- Split-ready `.agent` spec material in `spec/`.
- Report-only CI gate with HTML, Markdown, JSON, and OTLP JSON trace outputs.
- OTLP JSON uses current GenAI semconv-aligned agent/workflow attributes without faking model calls.
- GitHub composite action with optional PR comments.
- Browser-backed synthetic missions default to `understand_company`, `find_pricing`, and `find_api_quickstart`.
- Opt-in standard missions include `create_first_api_request`, `find_refund_policy`, and `use_mcp_tool_if_available` via `--mission-ids`.
- Mission evidence includes screenshots, AXTree text, token estimates, deterministic Prune4Web-style pricing slices, standalone pruning artifacts, and shared mission cache reuse.
- Diff-based monitor that hashes pages, skips unchanged pages, and reruns affected checks/missions.
- Monitor state also tracks MCP tool-description hashes when an MCP manifest is supplied.
- Fix pack export for `llms.txt`, JSON-LD, OpenAPI patch suggestions, and RFC 9457 problem-details examples.
- Fix packs can include observed agent-traffic token-load projection when logs are supplied.
- Fix packs include an MCP security checklist when an MCP manifest is supplied.
- Optional LLM fix explanation, gated by explicit provider config.
- Local PR prep that applies fix packs on a git branch and records audit evidence. Remote PR creation requires explicit confirmation.
- Env-backed private runner auth profiles with redacted evidence.
- Enterprise policy audit over `.agent/contract.json`.
- Contracts include CuP scoring across six local policy dimensions and MCP spec-version compliance fields.
- Repo scan for `.agent/contract.json`, `llms.txt`, OpenAPI files, and CI gate wiring.
- Local Solo web shell at `npm run solo`, built as a thin wrapper around the existing scanner and fix-pack path.
- Local sourced positioning-post draft in `docs/positioning-post.md`.

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
- Cost-at-scale is a token-load projection from observed logs and DOM token metrics; it is not provider billing proof.
- Smoke artifacts are local proof that the CLI paths run; they are not customer or production proof.

## Not Proven Here

- Customer log access.
- Real production traffic.
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
- Unreviewed auto-PR behavior.

## Current Rule

Keep this file current. Delete or replace stale plans instead of leaving them in root; git history is the archive.
