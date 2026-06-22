# Agent Contract OS

Production CLI for the first wedge in `plan_final.md`: passive agent traffic analytics, static agent-readiness checks, `.agent/` contract export, report-only CI gates, and OTLP JSON traces.

```bash
node ./bin/agent-contract.js logs access.log --json
node ./bin/agent-contract.js scan https://example.com --json
node ./bin/agent-contract.js contract https://example.com --out .agent
node ./bin/agent-contract.js gate https://example.com --mode report --report reports/agent-contract.html --otel-file reports/otel.json
node ./bin/agent-contract.js gate https://example.com --missions --browser-executable "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
node ./bin/agent-contract.js scan https://example.com/private --auth-profile auth-profile.json
node ./bin/agent-contract.js scan https://example.com --mcp mcp.json
node ./bin/agent-contract.js scan https://example.com --agent-skills .agent/agent-skills/index.json
node ./bin/agent-contract.js monitor https://example.com https://example.com/pricing --missions --browser-executable "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
node ./bin/agent-contract.js fixpack https://example.com --openapi openapi.json --out fix-pack
OPENAI_API_KEY=... AGENT_CONTRACT_LLM_MODEL=... node ./bin/agent-contract.js fixpack https://example.com --llm-explain --out fix-pack
node ./bin/agent-contract.js pr-prep fix-pack --repo /path/to/repo --dry-run
node ./bin/agent-contract.js policy-audit .agent/contract.json --out .agent/audit/policy
node ./bin/agent-contract.js repo-scan /path/to/repo --json
```

The gate defaults to `report` mode. Use `--mode blocking` only after calibration.

## What Exists

- NGINX and CloudFront access-log parsing for ClaudeBot, GPTBot, ChatGPT-User, OAI-SearchBot, PerplexityBot, and Google-Extended.
- Static URL checks for `robots.txt`, sitemap, `llms.txt`, `agent-skills`, JSON-LD, JS-only HTML, cookie blockers, slider/switch controls, datagrid filtering, A/B variant markers, sampled broken links, JSON OpenAPI quality, and optional MCP manifests.
- Portable `.agent/` output with `contract.json`, `missions.yml`, `policies.yml`, `llms.txt`, `llms-full.txt`, `agent-skills/index.json`, `openapi-patches.json`, and evidence snapshots.
- HTML/Markdown/JSON reports and OTLP JSON payloads with `gen_ai.*` attributes.
- Composite GitHub Action wrapper with optional Markdown PR comments and scheduled workflow support.
- Real browser synthetic missions for the plan's first three tasks: understand company, find pricing, and find API quickstart, with PNG screenshots, AXTree evidence, deterministic Prune4Web-style pricing slices, and token evidence.
- Diff-based monitoring: stores page hashes, skips unchanged pages, and reruns only affected missions.
- MCP manifest audits flag destructive, payment, command-execution, and write-side-effect tools unless they carry an explicit human-approval annotation.
- Fix pack export: writes reviewable `llms.txt`, JSON-LD, OpenAPI patch suggestions, and RFC 9457 problem details examples.
- LLM fix explanations are opt-in and provider-gated. No key/model means no LLM output.
- PR prep applies fix packs to a real git repo as a local branch and commit. Remote PR creation is opt-in and requires explicit confirmation.
- Repo scan audits local checkouts for `.agent/contract.json`, `llms.txt`, OpenAPI files, and CI gate wiring.
- Enterprise policy audit writes JSON and Markdown compliance reports from `.agent/contract.json`.
- Private runner auth profiles use env-backed secrets only and record redacted audit metadata.

Auth profile values must reference env vars:

```json
{
  "name": "private-runner",
  "headers": {
    "authorization": { "env": "PRIVATE_TOKEN", "prefix": "Bearer " }
  }
}
```

Remote PR creation is opt-in and gated with explicit confirmation. Publishing is verified locally with `npm run release:check`.

## Not Proven By This Repo

The local CLI does not prove market validation steps from `plan_final.md`: customer log access, 5 company pilots, McGill/Mila acknowledgement, real-site audit corpus, LOIs, domain ownership, public package publication, GitHub stars, or public standard adoption. Track those as external proof, not code proof.
