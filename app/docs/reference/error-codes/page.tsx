import { DocsShell } from "@/components/docs-shell";
import { ARENA_ERROR_CODES } from "@/src/docs-catalog.js";

export default function ErrorReference() { return <DocsShell eyebrow="Reference" title="Stable error codes." description="Agents should branch on code, not prose. retryAfterMs is zero for permanent request errors and positive only when a retry may help."><div className="reference-table" role="table" aria-label="Arena errors">{ARENA_ERROR_CODES.map((entry) => <div role="row" key={entry.code}><code role="cell">{entry.code}</code><span role="cell">{entry.retryable ? "retryable" : "restart or repair"}</span><p role="cell">{entry.meaning}</p></div>)}</div></DocsShell>; }
