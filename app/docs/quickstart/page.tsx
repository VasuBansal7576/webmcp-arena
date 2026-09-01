import { Callout, CodeBlock, DocsShell } from "@/components/docs-shell";

export default function Quickstart() { return <DocsShell eyebrow="Tutorial · 10 minutes" title="Gate your first WebMCP release." description="Create the adapter skeleton, connect an owned test surface, collect a reviewed contract, and make CI reject any proof that is not both valid and safe."><h2>1. Initialize</h2><CodeBlock>{`npm install --save-dev github:VasuBansal7576/webmcp-arena#v0.5.0
npx arena init
# review arena.config.mjs
# implement arena/document-sharing.adapter.ts`}</CodeBlock><h2>2. Prepare the boundary</h2><p>Your adapter supplies two isolated lanes: the interface a human uses and the registered tool an agent invokes. Record authoritative effects from your backend rather than accepting claims from the page.</p><CodeBlock>{`arena test \\
  --target http://127.0.0.1:4173 \\
  --fixture-token "$ARENA_FIXTURE_TOKEN" \\
  --browser-executable "/path/to/Chrome" \\
  --browser-mode native \\
  --write-contract /tmp/arena-contract.json`}</CodeBlock><h2>3. Review, run, and gate</h2><p>Approve the exact contract outside the Arena package directory, run the agent lane, then make the signed portable proof a release requirement.</p><CodeBlock>{`arena verify arena-proof.json --require pass
# exit 0: signature, semantics, and pass verdict hold
# exit 1: block the release`}</CodeBlock><Callout title="Do not skip the trust boundary"><p>Arena does not turn arbitrary production targets into trustworthy evidence. Use an owned or explicitly authorized test surface with backend-attested effects.</p></Callout><h2>Next</h2><p>Read <a href="/docs/concepts/human-agent-boundary">the human–agent boundary</a>, then use the <a href="/docs/reference/proof-format">proof reference</a> to wire your release system.</p></DocsShell>; }
