# PR Slices

## PR 1: Passive + Static Wedge

Owns the current production MVP:

- NGINX/CloudFront agent traffic analytics.
- URL static readiness checks.
- `.agent/` contract export.
- Report-only CI gate.
- HTML/JSON/OTLP evidence outputs.
- Diff-based monitor that hashes pages and reruns only affected checks/missions.
- Deterministic fix-pack export for reviewable contract/documentation patches.
- Opt-in LLM explanation for ambiguous fix ordering, gated by explicit provider config.
- Review-gated PR prep that applies fix packs to a real git branch before any remote PR action.
- Enterprise policy pack and audit report over `.agent/contract.json`.
- Private runner auth profiles with env-backed secrets and redacted evidence.

Proof:

```bash
npm test
node ./bin/agent-contract.js gate http://127.0.0.1:PORT --mode report --report reports/agent-contract.html --otel-file reports/otel.json
```

## PR 2: Distribution

- Publishable package metadata.
- GitHub Action wrapper.
- Hosted docs for the `.agent/` contract schema.

## PR 3: Synthetic Missions

Only after PR 1 has real users:

- AXTree mission runner.
- Prune4Web selector generation.
- Shared mission cache.

Skipped for now: checkout/signup missions and auto-PRs. The plan explicitly pushes both later.
