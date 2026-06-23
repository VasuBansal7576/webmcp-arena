# Agent Contract Spec

This folder is the split-ready `.agent/` contract specification. The implementation source of truth remains in `context.md`; this folder is the public standard surface to extract into a standalone repo later.

## Folder

```text
.agent/
├── contract.json
├── missions.yml
├── policies.yml
├── llms.txt
├── llms-full.txt
├── agent-skills/
│   └── index.json
├── openapi-patches.json
├── policy-pack.enterprise.json
├── evidence/
│   └── <timestamp>/
└── mcp/
    └── manifest.json
```

## Required Files

- `contract.json`: machine-readable source, surface, readiness, mission, and telemetry state. JSON Schema lives at `schema/contract.schema.json`.
- `missions.yml`: testable agent missions with `id`, `description`, `expected_outcome`, `max_steps`, `max_tokens`, and `token_strategy`.

## Optional Files

- `policies.yml`: local policy hints for CI and dangerous actions.
- `llms.txt` and `llms-full.txt`: agent-readable summaries and evidence.
- `agent-skills/index.json`: discoverable capabilities compatible with agent-skills style indexes.
- `openapi-patches.json`: reviewable OpenAPI fix suggestions.
- `policy-pack.enterprise.json`: controls for enterprise audit reports.
- `evidence/<timestamp>/`: scan, passive traffic, and mission evidence.
- `mcp/manifest.json`: MCP tool metadata and approval annotations.

## Compatibility

The spec wraps existing agent-facing conventions instead of betting on one winner: `llms.txt`, MCP manifests, agent-skills indexes, OpenAPI, and WebMCP-style browser affordances.

## Validation

```bash
node ./bin/agent-contract.js contract https://example.com --out .agent
node ./bin/agent-contract.js policy-audit .agent/contract.json
```
