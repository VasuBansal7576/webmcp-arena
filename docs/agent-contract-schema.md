# Agent Contract Schema

The `.agent/contract.json` file is the portable artifact produced by Agent Contract OS.

Schema:

- Canonical id: `https://agentcontract.dev/schema/v1`
- Local file: `schema/contract.schema.json`
- Required sections: `source`, `surface`, `readiness`, and `missions`

Runtime outputs:

- `contract.json`: machine-readable agent contract
- `missions.yml`: mission definitions for browser-backed checks
- `llms-full.txt`: expanded agent-readable context with static, passive, API, MCP, and mission evidence
- `agent-skills/index.json`: discoverable mission/capability index with evidence status
- `policy-pack.enterprise.json`: enterprise policy controls
- `evidence/<timestamp>/`: scan, passive traffic, and mission evidence

When `--mcp` is provided, `surface.mcp` records the manifest source, tool count, and dangerous-tool summary. Dangerous tools are static findings only; the gate fails on unapproved destructive, payment, command-execution, or write-side-effect tool surfaces.

Secrets are not stored in the contract. Auth profiles are recorded only as redacted metadata.
