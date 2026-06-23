# Agent Contract OS — GTM/Product Plan
### Strategic Plan · June 2026 · `context.md` is the implementation source of truth

This is a GTM/product strategy document. It is not the implementation source of truth; use `context.md` for what exists in the repo. Any market claim without an inline source link is directional and must be sourced before public, investor, or customer use.

---

## THE CORE THESIS (ONE SENTENCE)

GEO gets you recommended. Agent Contract OS gets you **bought**.

---

## WHY THIS IS URGENT RIGHT NOW — THE DATA

Before anything else — here is why every website owner needs to care. Source these claims before using them outside internal planning.

### The Traffic Shift Already Happened

- Automated traffic is now a majority-class web phenomenon in several public bot-traffic reports.
- AI crawler and agentic traffic has grown sharply year-over-year across infrastructure-provider reports.
- Large AI crawlers consume many more pages than they send back as referral traffic.
- Site owners already have machine traffic consuming content that client-side analytics often misses.
- The practical implication: websites need server-visible evidence, not just browser analytics.

### The Chrome Moment Is Happening Now (The SEO Parallel)

- Browser vendors and search platforms are moving agent interaction closer to the default browsing surface.
- WebMCP, MCP, `llms.txt`, and agent-skills proposals are all competing or converging around machine-readable site affordances.
- Lighthouse-style scoring for agent readiness would turn this from a niche concern into a mainstream website-quality metric.
- This resembles the early schema.org window: the tooling layer matters before the standard becomes boring.

### The Failure Rate Is the Business Case

- Public web-agent benchmarks still show high failure rates on realistic tasks.
- Common failure modes include JavaScript-only content, cookie modals, CAPTCHAs, auth walls, dynamic UI overlays, and brittle form flows.
- The buyer problem is not "agents are imperfect." The buyer problem is "the company has no regression signal when agents fail on its site."
- Developers already feel the debugging pain: headless browsers, real browsers, and agents fail differently, and the failure is often invisible.

### The Commercial Stakes Are Massive

- Analyst reports forecast agentic commerce and enterprise agents becoming large budget categories this decade.
- The exact market size is less important than the buying trigger: teams will need proof that agent-facing flows work before they trust agents with revenue.
- The wedge is operational, not speculative: "show me where agents fail, then prevent the regression."

### The Hostile Web Problem (The Real Pain Point)

From an April 2026 analysis of the agentic commerce landscape:

> *"Most ecommerce stores today are actively hostile to all three agent interaction modes. Modal popups, forced account creation, CAPTCHAs, slow-rendering product pages, inventory that's out of sync with the cart — every one of these is a conversion killer for humans, but for agents, they're often a full-stop blocker."*

**AI agents are less forgiving than humans.** Where a shopper might tolerate missing details or click past a cookie banner, an agent hits these as hard stops. If your pricing page is client-side rendered only, the agent cannot find your price. It moves to a competitor. You never know this happened.

This is the problem Agent Contract OS exists to solve.

---

## THE COMPETITIVE GAP (WHY NOW AND WHY US)

| Tool | What It Does | What It Misses |
|---|---|---|
| Cloudflare isitagentready.com | Protocol layer checks (robots.txt, llms.txt) | No synthetic missions, no CI gate |
| IndexedAI | Free 5-axis score, generates llms.txt | 6 pages only, no missions, no CI gate |
| Higoodie agent audit | 36 checks, 8 categories | No synthetic missions, no CI gate |
| Agentchecker | Sends real agent, scores navigation | No CI gate, no log analytics, no contract folder |
| Semrush / Otterly / GEO tools | AI visibility / citation monitoring | GEO (discovery), not agentic readiness (completion) |
| @kodus/agent-readiness | CI gate for CODEBASE agent readiness | Checks if a repo is ready for coding agents, not if a website works for user-facing agents — different buyer, different problem |
| Google Lighthouse Agentic Browsing | Pass/fail audit for llms.txt presence | Experimental, no weighted score, no missions, no fix packs |

**The gap is the same in every row: nobody is running the actual agent task and recording exactly why it failed.**

Agent Contract OS should win by combining four things in one workflow:
1. Running synthetic missions (real agent tasks, not just presence checks)
2. Generating a CI/Release gate that blocks deploys when agent-readiness regresses
3. Operating Layer 0 passive log analytics (zero-token, no LLM cost) to show what agent traffic is already hitting your site and failing
4. Producing the `.agent/` contract folder as a deployable standard — not just a score

---

## THE PRODUCT — STRATEGY VS IMPLEMENTATION TRUTH

Current implementation state lives in `context.md`. The architecture below is the target product shape, not a promise that every box is fully shipped in this repo.

### Architecture Reference

```
LAYER 0   Passive Agent Traffic Analytics    (zero-token, log parsing)
LAYER 1   Surface Ingest                     (URL, docs, OpenAPI, GitHub, MCP, sitemap, robots)
LAYER 2   Agent Contract Compiler            (.agent/ folder: contract.json, missions.yml, policies.yml, llms.txt, agent-skills/, openapi-patches/, evidence/, mcp/)
LAYER 3   Static Checks + Failure Taxonomy   (14 checks, no LLM tokens)
LAYER 4   Synthetic Missions                 (AXTree routing + Prune4Web-style pruning, target 6 standard missions, OTel spans)
FINDINGS  Evidence Engine                    (every finding evidence-backed, no opinions)
OUTPUTS   Fix Pack + Evidence Report + CI Gate + OTel Spans
LAYER 7   Continuous Monitoring              (hash/diff → bounded agent test → LLM only for ambiguous fixes)
```

The architecture is sound. The next phase is about **shipping it in the right order** to generate real users, real data, and real revenue — without burning runway on features that don't yet have buyers in front of them.

---

## EXECUTION PLAN — PHASED

---

### PHASE 0: Open the Standard (Weeks 1–2)
**Goal: Establish Agent Contract OS as the reference implementation before anyone else does**

This is the schema.org play. You don't need users to do this — you need GitHub stars and researcher citations.

**Actions:**
1. **Publish `agent-contract-spec` on GitHub** — the `.agent/` contract folder as an open standard.
   - `contract.json` schema (JSON Schema + OpenAPI-style)
   - `missions.yml` format spec
   - `policies.yml` format spec
   - `agent-skills/index.json` spec (aligned with Cloudflare's `.well-known/agent-skills/index.json` proposal — be compatible, be first)
   - README that references the McGill/Mila AWI paper (arXiv:2506.10953) and WebMCP spec
   - MIT license — this needs to be free to adopt

2. **Publish `agent-traffic-parser`** — an open-source CLI that reads NGINX/CloudFront access logs and outputs a summary of agent traffic (bot type, pages hit, empty HTML rate, auth wall hits, 429 rate, retry patterns). Zero-token. This is Layer 0 as a standalone tool.
   ```bash
   npx agent-traffic-parser ./access.log --output json
   ```
   Target: every DevOps engineer who has ever wondered "who is hitting my site."

3. **Write the positioning post**: *"GEO gets you recommended. Agent readiness gets you bought."* — publish on dev.to, HN, and Tweet. This is the thesis sentence that owns the space.

**Why first:** The open-source tools generate inbound. The spec gives you authority. Neither requires the full product to be live.

---

### PHASE 1: Ship Solo Tier (Weeks 2–5)
**Goal: First users. Real data. Distribution proof.**

The Solo tier is the wedge. Everything else compounds from it.

**The loop:**
```
Paste URL → Score (0–100) → Fix Pack (llms.txt snippet, JSON-LD, OpenAPI patch, robots.txt directive) → Download
```

**What ships:**
- **Web UI**: Single input box, URL. No login required for first scan.
- **Layer 1**: Ingest website URL, sitemap, robots.txt, llms.txt, OpenAPI spec (if linked)
- **Layer 3**: Run all 14 static checks (no LLM calls — zero token cost to you)
  - robots.txt validity + AI crawler directives
  - sitemap coverage
  - llms.txt presence + format validity
  - schema.org / JSON-LD completeness
  - broken links on key pages
  - JS-only content detection (pricing page, API quickstart, refund policy)
  - cookie modal blocker detection
  - auth wall hits on public pages
  - OpenAPI quality (error docs, auth docs, rate-limit docs)
  - MCP discovery endpoint check
  - A/B test variant detection
  - datagrid filtering check
  - slider/switch interaction detection
  - **WebMCP tool registration check** (source browser support state before claiming first/only/live)
- **Findings Engine**: Every issue gets one line of evidence. No opinions. "Pricing page returned empty HTML because content is loaded via JavaScript after DOM ready."
- **Fix Pack Generator**:
  - Ready-to-paste `llms.txt` snippet
  - JSON-LD snippet for the detected site type
  - `robots.txt` AI crawler directives
  - OpenAPI error doc suggestion
  - WebMCP annotation template (HTML + JS) for detected form elements
- **Email gate**: Score delivered to email (captures lead, enables follow-up, keeps infrastructure simple)

**Phase 1 implementation constraint:**
Reuse the existing CLI scanner and fix-pack code wherever possible. The web tier should be a thin shell around proven repo behavior, not a second scanner.

**Solo tier pricing**: FREE. The score is the product. The fix pack is the hook. The CI gate is the upgrade.

**Target users**: Indie SaaS founders, DevRel engineers, technical SEO leads, DevOps engineers who found `agent-traffic-parser` on GitHub.

---

### PHASE 2: Ship the npm CI Gate (Weeks 5–10)
**Goal: First $49/mo ARR. Recurring revenue. The real wedge.**

This is the Startup tier. It is the wedge most competitors are not focused on.

**The install:**
```bash
npm install --save-dev @agent-contract/ci-gate
```

**The GitHub Action:**
```yaml
# .github/workflows/agent-contract.yml
name: Agent Contract Gate
on:
  pull_request:
    branches: [main]

jobs:
  agent-contract:
    runs-on: ubuntu-latest
    steps:
      - uses: agent-contract/ci-gate@v1
        with:
          url: ${{ vars.PRODUCTION_URL }}
          token: ${{ secrets.AGENT_CONTRACT_TOKEN }}
          fail-on:
            - task-success-drop > 10%     # regression in synthetic mission completion
            - token-cost-jump > 20%        # pricing page getting more expensive to read
            - llms-txt-stale: true         # llms.txt not updated in 30 days
            - openapi-example-break: true  # example in OpenAPI spec is now invalid
            - mcp-dangerous-action: true   # MCP server started exposing an action it shouldn't
            - auth-flow-regression: true   # login wall appeared on a page that was public
            - webmcp-tool-removed: true    # registered WebMCP tool disappeared
```

**What happens on a PR:**
1. CI gate runs Layer 3 static checks against the preview deploy URL
2. Compares results against the stored baseline (from last passing merge)
3. If any threshold is breached: PR comment with exact evidence + link to fix pack
4. Optional: block merge until resolved

**PR comment format:**
```
⚠️  Agent Contract Gate — 2 regressions detected

❌  Pricing page is now JS-only (was server-rendered on last deploy)
    Evidence: GET /pricing returned 0 tokens of pricing content
    Fix: Move price rendering to SSR or add JSON-LD fallback

❌  llms.txt last-modified is 47 days old
    Evidence: Last-Modified header shows May 5, 2026
    Fix: Update llms.txt or set up auto-generation from sitemap

✅  MCP discovery: 3 tools registered, all passing
✅  OpenAPI: 0 breaking changes detected
✅  WebMCP: checkout tool still registered and valid
```

**Startup tier pricing**: $49/mo per repo. Annual: $490/yr.

**Target buyers**: Engineering leads at B2B SaaS, DevRel teams, frontend platform teams at mid-market companies who are already running GitHub Actions CI.

**Why this price point**: The baseline competitor is a senior engineer spending 30 minutes per deploy manually checking agent-readiness. At $100/hr loaded cost, that's $50/deploy. The gate pays for itself on the first week.

---

### PHASE 3: Ship Synthetic Missions — Layer 4 (Weeks 8–14)
**Goal: Unlock the evidence that nobody else has. The product nobody can copy cheaply.**

This is the product that makes Agent Contract OS hard to replace once a team has seen it.

Implementation note: the first three missions remain the default. The full six-mission pack is opt-in through `--mission-ids` until a real-site corpus proves reliability.

**Standard Mission Pack (6 missions):**
1. "Understand what this company does" — zero context, cold start
2. "Find pricing" — can the agent reach a price without hitting a JS wall?
3. "Find API quickstart" — developer onboarding readiness
4. "Create first API request" — can the agent actually use the API from docs alone?
5. "Find refund policy" — legal/trust signal for purchase agents
6. "Use MCP/tool if available" — does the agent discover and use your MCP server?

**What gets recorded per mission:**
- Step trace (every action the agent took)
- Screenshots at each step
- DOM snapshots (for before/after comparisons)
- Token cost (input + output, by model)
- Failure reason taxonomy (matches McGill/Mila failure categories)
- API response citations used
- Pass/fail with confidence score

**AXTree routing** (token optimization):
- Route by mission type: discovery missions → lightweight Prune4Web-style path
- Route by model capability: structural missions → full AXTree or targeted DOM only when needed
- Result: consistent cost budget per mission run, predictable at $X/mission

**Evidence Report output:**
```
MISSION: Find pricing
STATUS: FAILED
REASON: Pricing page returned empty HTML. CTA is client-side rendered only.
        Cookie modal intercepted agent at step 2 of 4.
EVIDENCE: screenshot_step2.png, dom_snapshot_step2.json
TOKEN COST: 14,200 input / 890 output (Claude Sonnet 4.6)
COMPARISON: Last passing run: 9,100 input / 610 output (May 20, 2026)
REGRESSION: Token cost +56%. Likely cause: new marketing section added above pricing CTA.
```

**Solo + Pro access**: Solo gets 1 mission run on scan. Pro ($49/mo) gets scheduled mission runs on every deploy.

---

### PHASE 4: Continuous Monitoring + OTel Integration — Layer 7 (Weeks 12–18)
**Goal: Make the product sticky. Retention = survival.**

**Monitoring loop:**
```
Hash/Diff Pages → Run Static Checks → Select Affected Missions Only → Bounded Agent Test → LLM for Ambiguous Fixes
```

The key insight: you don't re-run all 6 missions on every page change. You hash every page. If `/pricing` changed, you run the "Find pricing" mission. If `/docs/quickstart` changed, you run "Find API quickstart." Bounded cost, bounded time.

**OTel integration:**
- Every mission run emits OTel spans with `gen_ai.*` attributes
- Native ingestion by Datadog, Grafana, New Relic
- Dashboard: agent task success rate over time, token cost trend, failure mode distribution
- This is the "agent observability" story — same hook as application performance monitoring, but for how AI agents experience your site

**Target for OTel integration**: Platform engineering teams, SRE leads. This makes Agent Contract OS a line item in the observability budget, not the "AI stuff" budget.

---

### PHASE 5: Enterprise Tier (Weeks 16–24)
**Goal: $3k–$60k/yr contracts. The real revenue.**

**Enterprise adds:**
- **Private runner**: Customer deploys the scan engine in their own VPC. No data leaves their infrastructure. Critical for fintech, healthcare, any regulated vertical.
- **Auth testing**: The runner can authenticate with the customer's test account credentials to scan pages behind login walls.
- **Policy packs**: Customer-defined mission packs (e.g., "GDPR cookie consent flow", "SOC 2 agent access policy check")
- **Audit logs**: Full compliance trail of every scan, every finding, every fix applied.
- **Compliance reports**: Weekly PDF/dashboard showing agent-readiness score over time, failure taxonomy, regressions caught pre-deploy.

**Enterprise buyer persona:**
- Head of Platform Engineering or VP Engineering at a $10M–$200M ARR B2B SaaS
- Already running GitHub Actions, already using Datadog or Grafana
- Already heard from their AI team that "agents can't navigate our docs site"
- Looking for something that fits into their existing CI/CD and observability stack

**Enterprise pricing: $3k–$60k/yr**
- $3k: private runner, unlimited repos, scheduled scans 1x/day
- $12k: adds auth testing, policy packs
- $30k+: adds compliance reports, dedicated support, SLA, SAML SSO
- $60k+: adds custom mission pack development, quarterly reviews

---

## THE `.agent/` CONTRACT FOLDER — THE STANDARD PLAY

This is the long game. Bigger than the product.

**What it is:**
The `.agent/` folder is to AI agents what `package.json` is to npm — a machine-readable contract that tells any agent what this site is, what it can do, what it cannot do, and how to do it efficiently.

```
.agent/
├── contract.json          # identity, version, scope
├── missions.yml           # supported task types + expected token budgets
├── policies.yml           # what agents are/aren't allowed to do (rate limits, auth requirements, dangerous actions)
├── llms.txt               # content map (linked to standard)
├── agent-skills/          # skill definitions (aligned with Cloudflare .well-known/agent-skills/)
│   └── index.json
├── openapi-patches/       # agent-specific OpenAPI overlays (error handling, rate limits)
├── evidence/              # last scan results (public, for agent trust)
│   └── last-scan.json
└── mcp/                   # MCP server declaration + WebMCP tool registry
    └── server-card.json   # (aligned with MCP spec v2025-06-18)
```

**The spec play:**
1. Open-source the spec (MIT) on GitHub as `agent-contract/spec`
2. Reference McGill/Mila AWI paper, Cloudflare's agent-skills proposal, WebMCP W3C draft — be explicitly compatible with all three
3. Submit to W3C Web Machine Learning Community Group as a related proposal
4. Build a website validator that any tool (Cloudflare, IndexedAI, Google Lighthouse) can check for `.agent/` compliance
5. Be the maintainer of the format that everyone adopts

**The moat:** If the `.agent/` spec becomes a standard, Agent Contract OS is the company that audits compliance with it, generates it, and monitors it. This is like being the company that builds the schema.org validator and the schema.org-aware CMS plugin at the same time.

---

## THE WEBMCP WINDOW

WebMCP and related browser-native agent interfaces may create a short positioning window. Verify the current browser-support state before using this section in public copy.

**What Agent Contract OS should do in this window:**

**In Layer 3 (static checks), add WebMCP detection:**
- Does `navigator.modelContext` get registered on the pricing page?
- Does the checkout form have WebMCP declarative annotations?
- Does the contact form? The API key creation flow?
- Is there a `WebMCP-Enabled` HTTP header or meta tag?

**In Layer 4 (synthetic missions), add WebMCP execution:**
- For sites that have WebMCP tools registered, the mission runner calls the tool directly instead of DOM-navigating
- Records: did the WebMCP tool call succeed? What did it return? How many fewer tokens did it use vs DOM navigation?
- This becomes the "WebMCP ROI" metric: compare DOM-navigation token cost with direct tool-call cost.

**The WebMCP Score:**
Publish a "WebMCP Readiness Score" as a public sub-score on the Agent Contract dashboard. Target 10 high-profile sites. Publish the results if the browser-support facts check out.

**In Fix Pack, add WebMCP patch templates:**
```html
<!-- Agent Contract OS: WebMCP patch for checkout form -->
<form tool-name="checkout" tool-description="Complete purchase with items in cart">
  <input name="shipping_address" type="text" label="Shipping address">
  <input name="payment_method" type="text" label="Payment method token">
</form>
```
This should be a small developer patch from the fix pack. It could materially reduce agent checkout token cost.

---

## FAILURE TAXONOMY — THE DATA MOAT

Academic and browser-agent benchmarks already point to high failure rates and repeatable failure modes. Source exact numbers before using them publicly.

**Nobody has a failure taxonomy database for real production websites.**

Agent Contract OS should build one. Every mission run that fails gets categorized:
- JS-only content (pricing, features, docs)
- Cookie/consent modal blocker
- Auth wall on public page
- CAPTCHA on non-sensitive flow
- A/B test variant (agent gets the variant without pricing)
- Dynamic DOM element (floating ad covers CTA)
- MCP server not declared / wrong endpoint
- OpenAPI spec has no error examples
- llms.txt missing or stale
- WebMCP tool not registered on transactional page

**After 1,000 mission runs**, this database becomes:
- A research dataset (paper-worthy, researcher citations)
- A benchmark for the industry ("Site X has a Failure Taxonomy Score of 3/10")
- A training signal for agents (sites that publish their `.agent/contract.json` give agents a head start)
- A sales tool ("Here are the top 10 failure categories we see in B2B SaaS pricing pages")

---

## GO-TO-MARKET

### Distribution Strategy

**Channel 1: Open Source → Inbound (Weeks 1–8)**
- `agent-traffic-parser` CLI on GitHub (targets DevOps, gets stars)
- `agent-contract/spec` repo (targets researchers, gets citations)
- Blog post: "We scanned 1,000 SaaS pricing pages as an AI agent. Here's what broke." (targets every B2B SaaS founder)

**Channel 2: Solo Tier → Lead Generation (Weeks 3–12)**
- Free scan with email gate = lead list of people who care about agent readiness
- The Fix Pack is the best possible marketing artifact — it's immediately useful and has your brand on it
- Every Fix Pack has: "This report was generated by Agent Contract OS. Your engineers can automate this check on every PR. → [link to CI gate]"

**Channel 3: DevRel Communities (Weeks 4–16)**
- Target communities where buyers hang out: r/selfhosted, r/MachineLearning, r/webdev, Hacker News, DevRel Collective Slack, AI Engineer Discord
- Angle: "We built a tool that actually runs an AI agent on your site and tells you exactly what breaks and why"
- Give free Pro access to influential DevRel engineers in exchange for case study

**Channel 4: GitHub Actions Marketplace (Weeks 8–16)**
- Submit `@agent-contract/ci-gate` to the GitHub Actions Marketplace
- Target: every repo that already has a Lighthouse CI action (same buyer, natural extension)
- Add a "Powered by Agent Contract OS" badge to the PR comment — viral at zero cost

**Channel 5: Enterprise Outbound (Weeks 16+)**
- ICP: VP Engineering or Head of Platform at a B2B SaaS with $10M–$200M ARR, already running GitHub Actions, already using Datadog
- Cold outreach hook: "We detected that [company]'s pricing page returns empty HTML to AI agents. Here's the evidence." (Use Layer 0 data to generate highly specific cold emails)
- Target 50 companies per month. Close rate target: 2%.

### Positioning

**Tagline**: *"The CI gate for the agentic web."*

**One-liner**: *"Agent Contract OS runs the tasks your users' AI agents will run on your site — before they do — and blocks your deploys when something breaks."*

**The fear frame** (use in outreach): "Browser agents fail for boring web reasons: JS-only content, auth walls, cookie modals, and brittle forms. We'll tell you exactly what breaks and generate the fix."

**The opportunity frame** (use with growth-minded buyers): "Analysts expect agentic commerce to become a major channel this decade. The sites that work for agents will win more of it. We'll tell you if yours is ready."

---

## REVENUE MODEL

| Tier | Price | Feature | Target User |
|---|---|---|---|
| Solo | FREE | Paste URL, get score + fix pack, 1 mission run | Indie founders, DevRel, technical SEO |
| Startup | $49/mo per repo | CI gate, PR comments, scheduled checks (daily), 6 mission runs per deploy | Engineering leads at B2B SaaS |
| Startup Annual | $490/yr per repo | Same as Startup, 2 months free | Same, cost-sensitive |
| Enterprise | $3k–$60k/yr | Private runner, auth testing, policy packs, audit logs, compliance reports | VP Eng / CTO at $10M–$200M ARR SaaS |

**Revenue projections (conservative):**
- Month 3: 500 Solo scans, 10 Startup repos → $490 MRR
- Month 6: 2,000 Solo scans, 80 Startup repos, 1 Enterprise → $6,420 MRR
- Month 12: 5,000 Solo scans, 300 Startup repos, 5 Enterprise → $29,450 MRR (~$353k ARR)
- Month 18: 10,000 Solo scans, 700 Startup repos, 15 Enterprise → $83,300 MRR (~$1M ARR)

The Enterprise contracts are the real business. Each one is $3k–$60k. At 15 contracts averaging $20k, that is $300k ARR from 15 customers — less than a standard DevRel headcount for a mid-size company.

---

## MOATS (WHAT MAKES THIS HARD TO COPY)

1. **The failure taxonomy dataset.** After 10,000 mission runs, you have the largest empirical database of how AI agents fail on real websites. This is a research moat and a product moat simultaneously.

2. **The `.agent/` contract spec.** If Agent Contract OS is the maintainer of the open standard that every site deploys, the audit tool is the obvious companion. Google couldn't easily out-compete the W3C validator.

3. **OTel observability integration.** Once your CI gate is emitting spans into a team's Datadog or Grafana dashboard, replacement cost is high. You are infrastructure.

4. **Mission replay library.** Every mission run is stored with reproducible parameters. A customer can say "replay this mission against last week's deploy" to diagnose a regression. Nobody else has this. It requires having run the missions in the first place.

5. **WebMCP positioning.** If browser-native agent interfaces gain traction, Agent Contract OS should publish a readiness score and patch-template generator early enough to own that framing.

---

## IMMEDIATE ACTION LIST (NEXT 14 DAYS)

Priority order. Do not skip ahead.

- [x] **Day 1**: Make `context.md` the repo truth file and delete stale root plans/diagrams from the live working tree.
- [x] **Day 1–2**: Extract the current `.agent/` contract schema/docs into an `agent-contract-spec` repo or package folder. Keep it MIT and compatible with `llms.txt`, agent-skills, MCP, and future WebMCP hooks.
- [x] **Day 2–3**: Decide whether `src/logs.js` becomes a standalone `agent-traffic-parser` package or stays inside this CLI for now. If split, reuse the existing parser and tests.
- [x] **Day 3**: Fact-check the market claims in this plan. Add inline source links or soften the copy before publishing anything.
- [x] **Day 4–6 local**: Draft a positioning post from sourced claims only: "GEO gets you recommended. Agent readiness gets you bought." See `docs/positioning-post.md`.
- [ ] **External publish**: Publish the post to dev.to, HN, and X/Twitter after account/channel approval.
- [x] **Day 6–9**: Build the thinnest Solo web shell around the existing CLI scanner/fixpack path. No duplicate scanner logic.
- [x] **Day 9–11**: Add WebMCP detection only after verifying the current public/browser spec shape. Keep the implementation as static checks first.
- [x] **Day 11–14**: Prepare the existing npm package/GitHub Action for distribution: package name decision, README commands, release dry run, and action example.
- [ ] **Blocked on publish/push**: Create one public demo repo after the branch/package is published.

---

## RISKS AND HOW TO MITIGATE THEM

**Risk 1: The standard fragments (WebMCP gets abandoned, llms.txt wins)**
Mitigation: The `.agent/` spec is explicitly modular. It wraps llms.txt, WebMCP, and MCP server declarations. If any one protocol wins, the spec adapts. You are the aggregation layer, not a bet on a single protocol.

**Risk 2: Cloudflare builds this**
Mitigation: Cloudflare's isitagentready.com is a static protocol checker. They are not in the business of running AI agents on customer websites and emitting OTel spans. Their product motion is infrastructure, not developer tooling. You are building the CI gate, not the CDN.

**Risk 3: A well-funded GEO startup pivots to cover this**
Mitigation: GEO tools track citations. Agent Contract OS tracks task completion. The technical infrastructure is completely different — citation monitoring is API calls to LLMs asking "did you cite this brand?", whereas synthetic missions require browser automation, DOM analysis, token cost tracking, and failure taxonomy. The moat is the infrastructure, not the idea.

**Risk 4: Nobody pays for agent readiness (too early)**
Mitigation: This is why the Solo tier is free. If only 1 in 100 free users upgrades, and you get 5,000 free scans in 6 months, that is 50 paying repos = $2,450/mo MRR. Enough to keep going. And the enterprise sales process (VP Eng already has CI/CD budget) is not dependent on the "agent readiness" category being mainstream. It is dependent on one engineer in their org breaking a demo with an agent and asking "how do we prevent this?"

---

## THE SENTENCE THAT CLOSES EVERY SALES CALL

*"Browser agents fail for boring web reasons: JavaScript-only content, auth walls, cookie modals, and brittle forms. Agent Contract OS shows exactly what breaks, generates the fix pack, and turns that check into a CI gate."*

---

*Agent Contract OS — GTM/Product Plan*
*Prepared: June 2026*
*Academic backing: McGill/Mila AWI paper (arXiv:2506.10953)*
*"Build the web for agents, not agents for the web."*
