# Agent Contract OS Context

This repo is a local production CLI for proving whether a product surface works for AI agents. It is not a pitch deck or planning archive.

## Implemented

- CLI commands: `logs`, `scan`, `contract`, `gate`, `monitor`, `fixpack`, `pr-prep`, `policy-audit`, and `repo-scan`.
- Standalone `agent-traffic-parser` binary that reuses the `logs` command.
- Passive analytics for NGINX and CloudFront logs, including ClaudeBot, GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, and Google-Extended.
- Static URL checks for `robots.txt`, sitemap, `llms.txt`, `agent-skills`, JSON-LD, JS-only HTML, cookie blockers, slider/switch controls, datagrid filtering, A/B variant markers, WebMCP registration markers, sampled broken links, OpenAPI quality, MCP manifests, and dangerous MCP tools.
- `.agent/` contract export with `contract.json`, `missions.yml`, `policies.yml`, `llms.txt`, `llms-full.txt`, `agent-skills/index.json`, `openapi-patches.json`, policy pack, and evidence snapshots.
- Split-ready `.agent` spec material in `spec/`.
- Report-only CI gate with HTML, Markdown, JSON, and OTLP JSON trace outputs.
- GitHub composite action with optional PR comments.
- Browser-backed synthetic missions default to `understand_company`, `find_pricing`, and `find_api_quickstart`.
- Opt-in standard missions include `create_first_api_request`, `find_refund_policy`, and `use_mcp_tool_if_available` via `--mission-ids`.
- Mission evidence includes screenshots, AXTree text, token estimates, deterministic Prune4Web-style pricing slices, and shared mission cache reuse.
- Diff-based monitor that hashes pages, skips unchanged pages, and reruns affected checks/missions.
- Fix pack export for `llms.txt`, JSON-LD, OpenAPI patch suggestions, and RFC 9457 problem-details examples.
- Optional LLM fix explanation, gated by explicit provider config.
- Local PR prep that applies fix packs on a git branch and records audit evidence. Remote PR creation requires explicit confirmation.
- Env-backed private runner auth profiles with redacted evidence.
- Enterprise policy audit over `.agent/contract.json`.
- Repo scan for `.agent/contract.json`, `llms.txt`, OpenAPI files, and CI gate wiring.
- Local Solo web shell at `npm run solo`, built as a thin wrapper around the existing scanner and fix-pack path.

## Proven Locally

```bash
npm test
npm run smoke
npm run release:check
npm pack --dry-run
```

## Not Proven Here

- Customer log access.
- Company pilots or LOIs.
- Public package publication.
- Public standard adoption.
- GitHub stars or external usage.
- 10-site real-world audit corpus.
- Checkout/signup/payment missions.
- WebMCP tool execution.
- Unreviewed auto-PR behavior.

## Current Rule

Keep this file current. Delete or replace stale plans instead of leaving them in root; git history is the archive.
