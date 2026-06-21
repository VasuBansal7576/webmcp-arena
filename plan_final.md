# Agent Contract OS — Master Plan v2.1

> **The commercial implementation of the Agentic Web Interface (AWI) standard.**
>
> *"Build the web for agents, not agents for the web" — McGill/Mila, arXiv:2506.10953*

**The CI check that proves your API works for AI agents, not just humans.**

---

## 0. The Academic Foundation

Before anything else, know this:

| Fact | Source | Implication |
|---|---|---|
| Agents succeed on only **14%** of real website tasks | WebArena benchmarks | 86% of agent interactions fail silently. That's your market. |
| AI bots account for **16.9%** of production traffic | Cloudflare / wislr.com study | Google Analytics sees none of it. Bots don't execute JS. |
| A GPT-4.1 agent on a 20-step task costs **~$40** without optimization | DOM token study | Raw DOM is economically broken at scale. AXTree is not. |
| McGill/Mila defined the **Agentic Web Interface (AWI)** standard in June 2025 | arXiv:2506.10953 | Your `.agent/` folder is its commercial implementation. |

Reach out to **Xing Han Lù and Siva Reddy** at McGill/Mila. Introduce yourself as building the commercial AWI. If they acknowledge the connection, it goes in every pitch deck.

---

## 1. The Bet

AI agents are already browsing websites, calling APIs, and completing tasks on behalf of users. Most companies have zero visibility into whether agents can successfully use their product. When an agent fails, the company never knows — the user just leaves.

We are not building an "AI readiness scanner." We are building the infrastructure layer that:
1. **Surfaces existing agent traffic** companies cannot see (passive analytics — zero tokens)
2. **Generates a portable `.agent/` contract** from any product surface
3. **Continuously validates** that the product still honors that contract
4. **Blocks releases** when that contract breaks

**The core insight:** The report is not the product. The `.agent/` contract is.

---

## 2. What We Are Building

### 2.1 The Product in One Sentence

A CI check that generates a portable `.agent/` contract from any URL, repo, or API docs, then continuously validates that the product still honors that contract — so agents don't break silently.

### 2.2 The Three Outputs

1. **Agent Contract** — A `.agent/` folder in your repo that defines how agents should discover, understand, and use your product. The commercial implementation of the academic AWI standard.
2. **Evidence Report** — Every finding is evidence-backed, not opinion-based. Screenshots, DOM snapshots, API responses, token costs — plus real agent traffic from your server logs.
3. **Fix Pack** — PR-ready patches, not advice. `llms.txt`, JSON-LD snippets, OpenAPI fixes, RFC 9457 error examples.

### 2.3 The CI Gate

```bash
npx agent-contract gate
```

Runs in your pipeline. Emits OTel-compatible spans using GenAI Semantic Conventions v1.41 (`gen_ai.*` attributes — operation types: `create_agent`, `invoke_agent`, `invoke_workflow`, `execute_tool`). Datadog ingests these natively from v1.37+. Grafana, New Relic, and all OTLP backends pick them up automatically. Agent readiness appears in existing dashboards. No new tool. No procurement cycle.

Fails the build if:
- Agent task success rate drops
- Token cost per task jumps
- `llms.txt` is stale or missing
- OpenAPI examples break
- MCP tool exposes a dangerous action
- Auth flow becomes agent-hostile
- Docs links break

**Critical rule:** The gate starts as **report-only**. Graduates to **warning** after 30 days of calibration. Only then becomes **blocking**. False positives kill trust in 48 hours.

---

## 3. Architecture

### 3.1 High-Level Flow

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 0: PASSIVE AGENT TRAFFIC ANALYTICS (Zero-Token)       │
│  nginx/CloudFront logs → Bot identification → Segmentation   │
│  → "ClaudeBot hit your pricing page 847x and got empty HTML" │
└───────────────────────┬──────────────────────────────────────┘
                        │ foot-in-door
                        ↓
Website / Docs / API / Repo
        ↓
   Surface Ingest
        ↓
Agent Contract Compiler → .agent/ folder (AWI Standard)
        ↓
    ┌─────────────────────────────┐
    │  Static Checks              │  ← No tokens. Cheap. Fast.
    │  + WebArena Failure Taxonomy│    86% failure patterns imported.
    └──────────────┬──────────────┘
                   ↓
    ┌──────────────────────────────┐
    │  Synthetic Missions          │  ← Real agent missions. Token-optimized.
    │  A11Y Tree Routing           │    AXTree by default. Prune4Web locators.
    │  Shared Mission Cache        │    10x cost reduction.
    └──────────────┬───────────────┘
                   ↓
            Findings Engine
                   ↓
    ┌─────────┬──────────┬──────────────────────┐
    │Fix Pack │Evidence  │CI Gate + OTel spans  │→ Datadog / Grafana
    │Generator│Report    │npx agent-contract gate│
    └─────────┴──────────┴──────────────────────┘
                   ↓
      Continuous Diff Monitor ←── feedback loop
```

### 3.2 Layer Breakdown

---

#### Layer 0: Passive Agent Traffic Analytics *(New — Build First)*

This is the foot-in-the-door. Every company has agent traffic they cannot see. Zero tokens, zero Playwright, zero cost — pure log parsing.

**The problem:** AI bots do not execute JavaScript. Google Analytics cannot see them. ClaudeBot, GPTBot, ChatGPT-User, PerplexityBot, and OAI-SearchBot hit your site constantly and your client-side analytics show nothing.

**What this layer does:** A lightweight nginx/CloudFront log analysis SDK that:
- Identifies agent traffic by bot type and segments by user-agent
- Reports which pages returned empty HTML to bots (JS-rendered content they can't read)
- Reports auth wall hits, 429 rate, retry patterns per page
- Generates a real evidence report — not a synthetic audit, but their actual production data

**The outreach this enables:**
> *"I analyzed your server logs for agent traffic last month. ClaudeBot hit your pricing page 847 times and got empty HTML every time because it's client-side rendered. GPTBot couldn't find your API docs. ChatGPT-User hit your signup flow 23 times and got a cookie modal it couldn't dismiss. I can show you the full breakdown in 5 minutes."*

That is not a cold pitch. That is a diagnosis of their existing invisible traffic.

---

#### Layer 1: Surface Ingest

Accepts:
- Website URL
- Docs URL
- OpenAPI spec (URL or file)
- GitHub repo
- MCP server URL
- Sitemap / `llms.txt`
- `robots.txt`

Preserves the original "paste URL" simplicity.

---

#### Layer 2: Agent Contract Compiler

Generates one portable folder:

```
.agent/
├── contract.json           # Required. Machine-readable contract.
├── missions.yml            # Required. Testable agent missions.
├── policies.yml            # Optional. Security & compliance policies.
├── llms.txt                # Optional. Agent-optimized content.
├── llms-full.txt           # Optional. Extended content for agents.
├── agent-skills/
│   └── index.json          # Optional. Discoverable capabilities.
├── openapi-patches.json    # Optional. Patches to published OpenAPI spec.
├── mcp/
│   └── manifest.json       # Optional. MCP server metadata.
└── evidence/
    └── {timestamp}/        # Generated. Mission evidence + OTel traces.
```

This is the commercial implementation of the AWI standard. The report is consumed once and forgotten. The contract lives in the repo permanently and other tools can build on it.

---

#### Layer 3: Static Readiness Checks + Failure Taxonomy

Cheap, deterministic, no tokens. **Import the WebSuite/WebArena failure taxonomy from day one — do not discover it empirically.** They have already catalogued what breaks agents at the action, interaction, and end-to-end task levels.

- `robots.txt` validity
- Sitemap coverage
- `llms.txt` presence and freshness
- `schema.org` / JSON-LD markup
- OpenAPI quality (descriptions, examples, error schemas)
- API error documentation quality
- Auth and rate-limit documentation
- MCP discovery and agent-skills discovery
- JS-only content detection (agents see empty HTML)
- Cookie and modal blockers
- Broken links
- **Slider/switch interactions** (WebArena failure pattern)
- **Datagrid filtering** (WebArena failure pattern)
- **A/B test variants** (WebArena failure pattern)

Catches ~70% of real agent breakage. Always runs first.

---

#### Layer 4: Synthetic Mission Engine *(Token-Optimized)*

Run real tasks against the product. **The token problem:** DOM trees can exceed 1M tokens. A GPT-4.1 agent on a 20-step task costs ~$40 without optimization. Your mission engine must never feed raw DOM to the LLM by default.

**TOKEN OPTIMIZATION — Three levers:**

**1. A11Y Tree Routing (AXTree)**
The browser's accessibility tree — ARIA roles, accessible names, focusable elements — is what screen readers use and what Browser-Use, MultiOn, and the wave of MCP browser servers already converge on. A page that costs 5,000 vision tokens is ~500 accessibility-tree tokens. Use it as default.

**2. Prune4Web — Task-Conditional DOM Pruning**
Have the LLM generate a lightweight CSS selector program per mission rather than consuming the full DOM. "Find pricing" targets text nodes with price patterns + CTAs only. The mission runs against 200 tokens instead of 50,000.

**3. Shared Mission Caching**
Cache key: `SHA256(normalized_url + content_hash)`. Shared across all customers. 100 customers scan Stripe's docs = 1 mission run. Design for this from day one, not as a later optimization.

**Representation routing table:**

| Mission | Representation | Est. Token Cost |
|---|---|---|
| Find pricing / docs / policy | AXTree | ~500 tok/page |
| Understand product | Hybrid: AXTree + targeted DOM | ~1,500 tok/page |
| Complete form / signup | AXTree only | ~300 tok/page |
| Create first API request | OpenAPI spec direct | ~800 tok total |
| Debug ambiguous failure | Full DOM + frontier model | ~5,000 tok/page |

**Missions (Phase 1 — start here):**
1. "Understand what this company does"
2. "Find pricing"
3. "Find API quickstart"

**Missions (Phase 2 — add when Phase 1 is stable):**
4. "Create first API request"
5. "Find cancellation/refund policy"
6. "Use MCP/tool if available"

**MISSION WE SKIP FOR NOW:** "Complete checkout/signup until payment boundary" requires handling CAPTCHAs, 3D Secure, session state, and A/B test variants. This is an engineering trap. Add it only after anti-bot detection is solved — Phase 8 at the earliest.

Each mission records: steps, screenshots, DOM/AXTree snapshots, fetched markdown, API responses, token estimate, retries, failure reason.

---

#### Layer 5: Findings Engine

Every issue must be evidence-backed from both synthetic missions and passive log data.

- **Bad:** *"Your site is not agent ready."*
- **Good:** *"find_pricing failed — AXTree returned zero price-text nodes in static doc. Full DOM confirms pricing CTA renders only after client JS. Passive logs show ClaudeBot hit this page 847× with 100% empty HTML rate. Fix: expose pricing in server-rendered HTML or add to llms.txt."*

---

#### Layer 6: Fix Pack Generator

Generate patches, not advice:
- `llms.txt` and `llms-full.txt`
- JSON-LD snippets
- OpenAPI description and example fixes
- RFC 9457-style error examples
- `agent-skills/index.json`
- MCP tool suggestions
- PR-ready patch files

**Liability warning:** Auto-generated PRs that are wrong break production. Ship fix packs in fixture-mode with locked golden outputs before enabling auto-PRs. Never auto-PR without human review in v1.

---

#### Layer 7: Continuous Monitoring (Without Token Burn)

```
Hash / Diff Pages
  → Run Static Checks
    → Select Affected Missions Only
      → Run Bounded Agent Test (AXTree by default)
        → Use LLM Only for Ambiguous Explanation/Fixes
```

We continuously watch for reasons to spend tokens. We do not continuously burn them.

---

## 4. Token Efficiency — Cost Model at Scale

| Component | Cost per run | When it runs |
|---|---|---|
| Passive analytics (Layer 0) | $0 | Continuous — log parsing |
| Static checks (Layer 3) | $0 | Every deploy |
| Hash/diff check | $0 | Continuous |
| AXTree mission (Layer 4) | ~$0.02 | On diff trigger |
| Full DOM mission (Layer 4) | ~$0.40 | On ambiguous failure only |
| Shared cache hit | $0 | When URL + content hash matches |

The diff-based monitoring and shared caching are what make the economics viable. Competitors burning tokens on every check cannot match these unit economics.

---

## 5. Build Order

### Phase 0: Open Source the Spec (Week 0)
- Publish the `.agent/` schema on GitHub today — before you have a product
- Write the AWI one-pager citing arXiv:2506.10953
- Email Xing Han Lù and Siva Reddy at McGill/Mila
- Standards win on community, not product. 200 GitHub stars and 3 companies shipping it before Vercel notices you = they integrate you instead of competing.

### Phase 1: Passive Agent Traffic Analytics (Weeks 1–2)
- Build the nginx/CloudFront log parser SDK
- Identify GPTBot, ClaudeBot, ChatGPT-User, PerplexityBot, OAI-SearchBot by user-agent
- Generate real evidence reports from existing traffic data
- **Goal:** Get 5 companies using this before building anything else
- This is your zero-cost wedge and your sales conversation starter

### Phase 2: URL Scanner + Static Checks (Weeks 3–5)
- Paste URL → static audit (import WebArena failure taxonomy) → score → evidence report
- No synthetic missions yet. No fix packs yet.
- Prove the problem exists with real data

### Phase 3: Agent Contract Generator (Weeks 6–7)
- Generate the `.agent/` folder from the static audit
- Make it downloadable and commitable to a repo
- This is the artifact that creates stickiness before a single mission runs

### Phase 4: CI Gate + GitHub Action + OTel Spans (Weeks 8–10)
- `npx agent-contract gate` — static checks only, report-only mode
- Emit OTel `gen_ai.*` spans from day one (Datadog v1.37+ ingests natively)
- GitHub App comments on PRs — not blocking yet
- Enterprise customers see agent readiness in their existing Datadog/Grafana dashboards. No procurement cycle.

### Phase 5: 3 Synthetic Missions with Token Optimization (Weeks 11–14)
- Implement AXTree routing and Prune4Web locators from the start
- Run 3 missions manually against 10 real sites first — build your evidence corpus before automating
- "Understand company" / "Find pricing" / "Find API quickstart" only
- Do not add more missions until these three are reliable and cached

### Phase 6: Evidence Report + Fix Pack Export (Weeks 15–18)
- Rich evidence reports combining synthetic + passive traffic data
- Fix pack export (not auto-PR yet)
- Upsell existing gate customers to the richer evidence tier

### Phase 7: Diff-Based Monitoring (Weeks 19–22)
- Hash/diff pipeline, selective mission re-run, shared mission caching live
- This is what makes continuous monitoring economically viable at scale

### Phase 8: Auto-PR + Private Runner (Months 6–12)
- Open GitHub PRs with golden-tested fix packs
- Private runner for enterprise auth testing
- Enterprise policy packs, audit logs, compliance reports
- Add "complete checkout" mission only here, after anti-bot detection is properly solved

---

## 6. Go-to-Market

### 6.1 Positioning

- **Internal:** The Snyk-shaped thing that Datadog might acquire in four years.
- **External:** *"The CI check that proves your API works for AI agents, not just humans."*
- **Academic backing:** *"The commercial implementation of the Agentic Web Interface (AWI) standard, developed at McGill/Mila."*

Do not sell "AI readiness." Sell:
- **To startups:** "Prevent AI agent breakage in production."
- **To enterprise:** "Your existing observability stack already supports agent readiness — add one line to your pipeline."
- **Lead with passive analytics:** "86% of agents fail on real websites. Here's your data from last month."

### 6.2 Pricing

| Tier | Price | What They Get | Role |
|---|---|---|---|
| Solo | Free | Passive log analytics + URL scan + score + badge + fix pack | Marketing and distribution only. No ARR target. |
| Startup | $49–99/mo per repo | GitHub CI Gate + PR comments + OTel spans + scheduled checks + evidence reports | The real wedge. Low friction, high stickiness. |
| Enterprise | $30–60K/yr | Private runner + auth testing + policy packs + audit logs + compliance reports + SSO | The real revenue. OTel integration removes the new-tool objection. |

### 6.3 How to Find the First 50 Customers

These companies already know they have the problem:

1. Search GitHub for repos with `llms.txt` files (already AWI-aware)
2. Find every company with a published MCP server (the list is short and public)
3. Look at companies appearing in WebArena and WorkArena benchmark environments
4. Find companies whose marketing says "agent-friendly API" or "built for AI workflows"
5. Search HN, Twitter, and Cloudflare forums for companies complaining about AI bot traffic

**Outreach script:**
> *"I analyzed your server logs for agent traffic last month. ClaudeBot hit your pricing page 847 times and got empty HTML every time because it's client-side rendered. GPTBot couldn't find your API docs. I can show you the full breakdown in 5 minutes."*

Not a cold pitch. A diagnosis of their existing invisible traffic. That gets a meeting.

---

## 7. The 30-Day Validation Plan

### Week 1: Passive Analytics Proof
- Build the minimal log parser — identify ClaudeBot/GPTBot traffic
- Find 5 companies willing to share 30 days of nginx logs (or approximate from public signals)
- Generate one real evidence report per company
- **Goal:** One company says "I had no idea this was happening. Show me more."

### Week 2: Cold Outreach + Academic Credibility
- Identify 20 API-first companies with public APIs and/or `llms.txt` files
- Send the Layer 0 diagnosis (not a pitch — a finding)
- Email Xing Han Lù and Siva Reddy at McGill/Mila simultaneously. Introduce yourself as building the commercial AWI. Ask for a 15-minute call. Even an acknowledgement goes in the pitch deck.

### Week 3: Manual Audit of 10 Real Sites
- Target: Stripe, Linear, Notion, Resend, Cal.com, Supabase, Vercel, Railway, Fly.io, Resend
- Run static checks and 3 synthetic missions manually
- Document every place a real agent fails
- This is your demo corpus — the evidence no one else has

### Week 4: LOI + Spec Launch
- Find one startup. Audit them manually. Write their `.agent/` contract by hand.
- Show them what a CI gate would catch: *"Would you pay $200/month for this in your pipeline?"*
- A handshake agreement before you build validates the wedge.
- Simultaneously: Publish the `.agent/` schema on GitHub. Target 100 stars.

---

## 8. Competitive Moat

### 8.1 The Real Threats

| Threat | Timeline | Defense |
|---|---|---|
| Datadog / Sentry / New Relic add "agent observability" | 12–24 months | Own the `.agent/` standard. Emit OTel spans they ingest — become infrastructure they depend on, not a competitor. |
| Vercel / GitHub add native AI readiness checks | 6–18 months | Open-source the spec first. Community standards beat platform-native ones when they have adoption. |
| OpenAI / Anthropic publish their own compatibility standard | Unknown | AWI is already community property (arXiv). Be the working implementation with a head start. McGill/Mila backing helps. |
| Bridge AI or similar expands into CI | 6–12 months | They are a services business disguised as software. CI gate + OTel integration is a different category entirely. |

### 8.2 The Actual Moat (ranked by strength)

1. **OTel Integration** — Agent readiness becomes a native metric in every existing observability stack. Datadog customers see it without a new tool. This makes you infrastructure they depend on.
2. **The Contract Format** — If `contract.json` becomes the recognized artifact (like `package.json` or `.github/workflows/`), network effects kick in. Companies publish contracts publicly. You benchmark against the corpus.
3. **Passive Traffic Analytics** — Zero-cost foot-in-the-door no competitor has. Real production data beats synthetic audits as a sales conversation. Always.
4. **Shared Mission Caching + Token Optimization** — Unit economics competitors burning tokens on every check cannot match. AXTree + Prune4Web = 10x cost advantage.
5. **Evidence Corpus** — Real mission failures against real sites, combined with real agent traffic from server logs. Data no one else has.
6. **Academic Backing** — McGill/Mila AWI paper gives credibility pure commercial startups cannot buy. Use it in every pitch.

---

## 9. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| False positives in CI gate | Fatal | Start report-only. Graduate to warning after 30d. Only block after customer-specific calibration. |
| Anti-bot detection blocking synthetic missions | High | Use Browserless. Rotate user agents. Respect robots.txt. Start with sites that explicitly welcome agents. |
| Synthetic mission brittleness | High | Budget 40% of engineering here. AXTree by default — less brittle than full DOM. Start with 3 missions, not 10. Never add "complete checkout" early. |
| Token cost at scale | High | AXTree routing + Prune4Web + shared caching + hash/diff monitoring. Design all four from day one. |
| Market education burden | Medium | Lead with passive analytics data. Concrete proof before abstract pitch. |
| GitHub Action fatigue | Medium | Start as PR comments. Engineers choose to make it blocking. |
| Platform player publishes competing standard | Medium | Open-source spec today. OTel integration makes you infrastructure they need. McGill/Mila backing helps. |
| Fix pack liability | Medium | Golden outputs. Fixture-mode testing. No auto-PR without human review in v1. |
| Passive analytics adoption | Low | Zero cost for the customer. One-line SDK install. If they won't do this, they won't do anything. |

---

## 10. The .agent/ Contract Spec — Draft v0.2

*Open source from Day 1. Publish on GitHub before you have a product.*

### 10.1 Folder Structure

```
.agent/
├── contract.json           # Required. Machine-readable contract.
├── missions.yml            # Required. Testable agent missions.
├── policies.yml            # Optional. Security & compliance policies.
├── llms.txt                # Optional. Agent-optimized content.
├── llms-full.txt           # Optional. Extended content for agents.
├── agent-skills/
│   └── index.json          # Optional. Discoverable capabilities.
├── openapi-patches.json    # Optional. Patches to published OpenAPI spec.
├── mcp/
│   └── manifest.json       # Optional. MCP server metadata.
└── evidence/
    └── {timestamp}/        # Generated. Mission evidence + OTel traces.
```

### 10.2 contract.json

```json
{
  "$schema": "https://agentcontract.dev/schema/v1",
  "version": "1.0.0",
  "awi_compliance": "1.0",
  "generated_at": "2026-06-21T00:00:00Z",
  "source": {
    "type": "website",
    "url": "https://example.com",
    "ingested_at": "2026-06-21T00:00:00Z"
  },
  "passive_traffic": {
    "period": "30d",
    "total_agent_requests": 1247,
    "bots": {
      "claudebot":    { "requests": 847, "empty_html_rate": 1.0 },
      "gptbot":       { "requests": 312, "404_rate": 0.15 },
      "chatgpt-user": { "requests": 88,  "auth_wall_rate": 0.3 }
    }
  },
  "surface": {
    "website": {
      "url": "https://example.com",
      "has_sitemap": true,
      "has_robots_txt": true,
      "has_llms_txt": false,
      "render_mode": "client_side",
      "agent_blockers": ["cookie_modal", "geo_gate"]
    },
    "api": {
      "openapi_url": "https://example.com/openapi.json",
      "quality_score": 72,
      "has_error_examples": false,
      "has_rate_limit_docs": true,
      "auth_methods": ["bearer_token", "api_key"]
    },
    "mcp": { "server_url": null, "discovered": false }
  },
  "readiness": {
    "score": 68,
    "level": "bronze",
    "critical_gaps": [
      "llms.txt missing",
      "pricing content client-side rendered",
      "openapi missing error examples"
    ]
  },
  "missions": {
    "tested": 3,
    "passed": 1,
    "failed": 2,
    "results": [
      {
        "mission": "find_pricing",
        "status": "failed",
        "reason": "pricing_cta_client_side_only",
        "token_strategy": "a11y_tree",
        "tokens_consumed": 487,
        "evidence_path": "evidence/20260621/find_pricing/"
      }
    ]
  },
  "telemetry": {
    "otel_schema": "gen_ai.1.41.0",
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
  }
}
```

### 10.3 missions.yml

```yaml
version: "1.0.0"

missions:
  - id: understand_company
    description: "Understand what this company does from its homepage"
    expected_outcome: "A clear summary of the company's primary product and value proposition"
    max_steps: 10
    max_tokens: 2000
    token_strategy: hybrid        # a11y_tree | full_dom | prune4web | hybrid

  - id: find_pricing
    description: "Find the pricing page and extract the pricing tiers"
    expected_outcome: "A structured list of pricing tiers with features and costs"
    max_steps: 15
    max_tokens: 1500              # 50% cheaper than full DOM equivalent
    token_strategy: prune4web
    critical: true

  - id: find_api_quickstart
    description: "Find the API quickstart and identify the first request to make"
    expected_outcome: "The endpoint, method, and minimal example for the first API call"
    max_steps: 12
    max_tokens: 1200
    token_strategy: a11y_tree
    critical: true
```

---

## 11. The Pitch Narrative

> "A user asks Claude to 'sign up for ExampleApp and start the free trial.' Claude visits the site. The pricing page is rendered in client-side JavaScript. Claude's accessibility tree — the same representation every major browser agent now uses — finds zero pricing content in the static document. The user gets frustrated and leaves. ExampleApp never knows. They just lost a customer to an invisible failure.
>
> Meanwhile, ClaudeBot has hit their pricing page 847 times in the last 30 days. Every single time, it got empty HTML. They have no idea. Their Google Analytics shows zero of this traffic.
>
> Agent Contract OS surfaces that invisible traffic first — from their own server logs, no tokens, no synthetic testing. Then it generates a `.agent/` contract from their product surface, runs real agent missions against it using the same AXTree representation that browser agents actually use, and puts a CI gate in their pipeline so this never ships again. Their existing Datadog instance picks up the agent readiness metrics automatically. No new tool. No procurement cycle."

---

## 12. Academic References

| Paper / Standard | What It Gives You |
|---|---|
| arXiv:2506.10953 — *"Build the web for agents, not agents for the web"*, Lù et al., McGill/Mila (June 2025) | Defines AWI. Your `.agent/` folder is the commercial implementation. Cite in every pitch deck. |
| *WebSuite: Systematically Evaluating Why Web Agents Fail* | Pre-built failure taxonomy for Layer 3 static checks. Import it — don't discover it empirically. |
| *Read More, Think More: Revisiting Observation Reduction for Web Agents* | Evidence for AXTree vs full DOM routing by model capability. Use for your representation router. |
| arXiv:2511.21398 — *Prune4Web: DOM Tree Pruning Programming* | Task-conditional CSS selector generation. The basis for your 200-token mission inputs. |
| OTel GenAI Semantic Conventions v1.41 | Standard for CI gate span emission. `gen_ai.*` attributes. Datadog v1.37+ native support. |
| WebArena benchmarks | 14% end-to-end agent task success rate. Your headline market stat. |
| Cloudflare / wislr.com agent traffic study | 16.9% of production traffic is AI bots. Google Analytics misses all of it. |

---

## 13. What to Do Today

1. Register `agentcontract.dev` (or similar)
2. Create the GitHub repo for the open spec
3. Write the AWI one-pager (cite arXiv:2506.10953)
4. Email **Xing Han Lù and Siva Reddy** at McGill/Mila — introduce yourself as building the commercial AWI
5. Identify 20 outreach targets via GitHub `llms.txt` search and MCP server lists
6. Build the minimal log parser for Layer 0 — this is your highest-leverage first step

**Do not build the synthetic mission engine yet.** Build passive analytics and static checks first. Get one LOI.

---

*Last updated: 2026-06-21*
*Version: 2.1 — Combined synthesis (research + structure)*
*AWI Standard: arXiv:2506.10953 (McGill/Mila)*
*OTel Standard: GenAI Semantic Conventions v1.41*
