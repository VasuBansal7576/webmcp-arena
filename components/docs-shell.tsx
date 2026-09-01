import type { ReactNode } from "react";

export function DocsShell({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children: ReactNode }) {
  return <main className="docs-page">
    <header className="docs-nav"><a className="brand" href="/"><span>A</span> Arena</a><nav aria-label="Documentation"><a href="/docs">Docs</a><a href="/use-cases">Use cases</a><a href="/blog">Blog</a><a href="https://github.com/VasuBansal7576/webmcp-arena">GitHub</a></nav></header>
    <div className="docs-wrap"><aside className="docs-sidebar" aria-label="Documentation sections"><strong>Start</strong><a href="/docs/quickstart">Quickstart</a><strong>Understand</strong><a href="/docs/concepts/human-agent-boundary">Human–agent boundary</a><strong>Reference</strong><a href="/docs/reference/webmcp-tools">WebMCP tools</a><a href="/docs/reference/webmcp-evals">WebMCP Evals</a><a href="/docs/reference/proof-format">Proof format</a><a href="/docs/reference/error-codes">Error codes</a><strong>Apply</strong><a href="/use-cases">Use cases</a><a href="/blog">Essays</a></aside>
      <article className="docs-content"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="docs-lede">{description}</p>{children}</article></div>
  </main>;
}

export function CodeBlock({ children }: { children: string }) { return <pre><code>{children}</code></pre>; }
export function Callout({ title, children }: { title: string; children: ReactNode }) { return <aside className="docs-callout"><strong>{title}</strong><div>{children}</div></aside>; }
