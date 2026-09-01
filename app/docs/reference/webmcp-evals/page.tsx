import { CodeBlock, DocsShell } from "@/components/docs-shell";

export default function WebMcpEvalsReference() {
  return <DocsShell eyebrow="Reference" title="WebMCP Evals compatibility." description="Use GoogleChromeLabs webmcp-evals for live model and browser execution, then use Arena to independently check the imported trajectory, Chrome guidance, and signed behavioral evidence.">
    <h2>Why both tools?</h2>
    <p><code>webmcp-evals</code> answers whether a model selected and called the expected tools. Arena treats that report as untrusted input, recomputes every expected trajectory, audits the tool and runtime observations, then verifies an Arena boundary proof. A claimed upstream pass count cannot override a mismatched call.</p>
    <h2>Command</h2>
    <CodeBlock>{`npx arena eval \\
  --evals examples/webmcp-evals/evals.json \\
  --results examples/webmcp-evals/results.json \\
  --tools examples/webmcp-evals/tools.json \\
  --observations examples/webmcp-evals/observations.json \\
  --proof /path/to/arena-proof.json \\
  --format json`}</CodeBlock>
    <p>Without <code>--proof</code>, Arena returns <code>inconclusive</code>. It never converts tool-selection success into a behavioral safety claim.</p>
    <h2>Three independent layers</h2>
    <ol>
      <li><strong>Selection:</strong> matches ordered, unordered, optional, unconstrained, argument, and result expectations from the current eval format.</li>
      <li><strong>Guidance:</strong> checks naming and description budgets, annotations, origin exposure, token limits, untrusted-content flow, confirmation, mid-chain failure, and cancellation.</li>
      <li><strong>Behavior:</strong> verifies the signed Arena proof against authoritative effects. This is the only layer that establishes human-route protection parity.</li>
    </ol>
    <h2>Runtime observations</h2>
    <p>Observations must come from the adapter, agent harness, or authoritative backend trace. Do not populate them from a tool description. Validate the file against <a href="/schemas/arena-webmcp-eval-observations-v1.schema.json">the observation schema</a>.</p>
    <h2>Upstream references</h2>
    <ul>
      <li><a href="https://github.com/GoogleChromeLabs/webmcp-tools">GoogleChromeLabs WebMCP tools</a></li>
      <li><a href="https://developer.chrome.com/docs/ai/webmcp/evals">Run WebMCP evaluations</a></li>
      <li><a href="https://developer.chrome.com/docs/ai/webmcp/secure-tools">Secure WebMCP tools</a></li>
      <li><a href="https://developer.chrome.com/docs/agents/security">Agent security guidance</a></li>
    </ul>
  </DocsShell>;
}
