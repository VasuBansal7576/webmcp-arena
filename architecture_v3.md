# architecture_v3.md

Source of truth for the next direction. What is listed under **Existing Foundation** is already built.
Do not re-plan those items. Build forward from them.
This document describes six layers, in the order they must be built, each one unlocking the next.
The overall system is called the **Agent Session Membrane** — the runtime trust layer between every AI agent and every surface it touches.

---

## What This System Becomes

Agent Contract OS started as a proof-and-repair tool — scan a site once, emit findings, hope someone fixes things.

The destination is different. The membrane sits in every agent session in real time. It sees both sides simultaneously: what the site served and what the agent received. It detects deviations, records evidence, scores behavior, and when things go wrong it can prove what happened and whose fault it was.

This is not a dashboard. It is not observability. LangSmith, Langfuse, and Datadog all trace agent sessions after the fact. They are logs with a UI. This is the infrastructure layer that sits underneath them — the only entity that holds cryptographic evidence of what actually happened between an agent and a surface.

---

## Existing Foundation

Everything listed here is already built. The six new layers extend this foundation — they do not replace it.

The existing scanner (scan, missions, contract, gate, monitor, fixpack, pr-prep, policy-audit, repo-scan) produces a clean baseline for every site it touches. That baseline is the single most important input for everything that follows, because without knowing what a site looks like in a clean state you cannot detect when something has deviated from it.

The IPI risk findings already emitted by the static checker are the pre-flight signal. The runtime membrane is the live signal that validates or contradicts them.

The `.agent/contract.json`, `missions.yml`, and `policies.yml` files are the declared specification of what a site expects agents to do. Layer 4 signs them. Layer 5 walks against them. Layer 6 replays against them.

---

## Layer 1 — IPI Detection Module

**What it is**

A lightweight runtime module that sites embed after running a pre-flight scan. It observes what AI agents actually receive during a live session and compares it against the clean DOM baseline the scanner already produced.

**What it does**

When an agent visits a site, it receives HTML. That HTML may or may not match what legitimate users see. Indirect Prompt Injection (IPI) is the attack where adversarial instructions are hidden inside content that an agent retrieves — instructions that were not there during the pre-flight scan. The module detects this by diffing the live DOM against the stored baseline in real time.

The module has two parts. One part is a small JavaScript snippet the site embeds, similar to how Google Analytics or Cloudflare Beacon is embedded — a one-line addition to the site's existing layout. The other part is a server-side hook in NGINX or Cloudflare that captures the raw HTTP response before it reaches the agent and forwards a hash of that response to the detection backend.

When the live hash deviates from the baseline hash for a given URL or DOM region, the module fires an alert. The alert includes which element deviated, by how much, and when.

**How it connects to the existing work**

The pre-flight scan already identifies IPI-risk zones — elements that are suspicious because they use unusual accessibility attributes or hidden DOM regions. The runtime module watches those specific zones first. High-risk zones from the static scan become high-priority monitoring targets at runtime.

**What it produces**

A continuous stream of deviation events: site, URL, DOM region, baseline hash, observed hash, timestamp, agent user-agent string. Each event is a structured record that feeds into Layer 2.

**What it unlocks**

Physical presence on real sites in production sessions. Without this, everything else in this document is theoretical. With it, you have a data collection endpoint that every subsequent layer builds on.

**Distribution motion**

One-sided install. Site owners install it to protect themselves from IPI attacks. Agent deployers do not need to do anything. This is the same motion as your existing scanner — one party acts, immediate value is delivered.

**Interpretation boundary**

The IPI detection at this layer is deviation detection, not intent attribution. You can say "the content the agent received differed from the clean baseline." You cannot yet say "this was a deliberate attack" or "who introduced the deviation." Those come in Layer 5.

---

## Layer 2 — Passive Telemetry and Agent Behavioral Registry

**What it is**

An extension of Layer 1's event stream that captures not just IPI deviations but the full behavioral trace of every agent session: which pages were visited in what order, which elements were interacted with, what timing patterns were observed, what user-agent identity was presented.

**What it does**

Layer 1 already has a hook in the site's HTTP layer. That hook can forward behavioral event data at almost no additional cost. The telemetry module adds structure to that stream — converting raw HTTP observations into semantically meaningful events like "agent navigated to checkout without reading terms page" or "agent submitted form that was declared off-limits in robots.txt."

These structured events are stored in the Agent Behavioral Registry (ABR), a central backend organized by agent identity, site, session, and action type. The ABR cross-references observed behavior against the agent's published declarations — its agent card, its `agent-permissions.json`, its `/.well-known/agent.json` entry — and flags every case where what the agent did contradicts what it said it would do.

**What it produces**

Per-session behavioral records. Per-agent conformance scores computed by comparing observed actions against declared capabilities. The score for any given agent on any given site type is simply the ratio of conforming actions to total actions, with weights applied by action severity.

**What it unlocks**

The first version of the behavioral corpus. At ten sites it is noise. At thirty it starts to have signal. At one hundred it is a product. The corpus accumulates automatically from Layer 1's existing telemetry infrastructure — no additional site-owner action required beyond the initial Layer 1 install.

**Interpretation boundary**

Conformance scores at this layer are derived from observed HTTP-layer behavior and declared public capabilities. They are not ground-truth proof of agent intent. An agent that bypasses a declared policy may be doing so because of a prompt injection (Layer 1's domain) or because of a bug or because of deliberate design. Attribution of why comes in Layer 5.

---

## Layer 3 — Drift Score API and WAF Integration

**What it is**

An API that exposes the ABR's per-agent conformance scores as a live signal that site operators can consume programmatically to make access control decisions.

**What it does**

Once the ABR has enough data to compute statistically meaningful scores, those scores become operationally useful. A site operator can configure their WAF to query the API before serving a response to a known agent identity: "has this agent conformed to declared policies across the sites we have data for?" If the score is below a threshold, the WAF blocks or rate-limits the agent. If the score is high, the WAF grants preferential treatment — higher rate limits, fewer CAPTCHA challenges.

This is the same model as IP reputation systems, but for agent behavioral identity rather than IP addresses. An agent that has a demonstrated track record of respecting policy boundaries on two hundred sites gets better access than an agent with no track record or a poor one.

The API also exposes segment-level models: conformance patterns for a given agent across e-commerce sites, across API documentation sites, across SaaS dashboards. A site operator can query not just "how does GPTBot behave globally" but "how does GPTBot behave on sites like mine."

**What it produces**

A live API endpoint. WAF integration rules for NGINX, Cloudflare Workers, and Fastly edge. A developer dashboard showing per-agent conformance trends over time.

**What it unlocks**

The first infrastructure lock-in. Once a site operator's WAF rules reference your API, removing your membrane means removing the intelligence those rules depend on. This is the moment you transition from a tool to infrastructure.

**Interpretation boundary**

Drift scores are behavioral aggregate signals computed from observed HTTP-layer traces. They are probabilistic, not deterministic. A low score means the agent has historically deviated from its declared policies — it does not prove it will deviate in any specific future session.

---

## Layer 4 — Dual-Signed Session Receipts

**What it is**

A cryptographic evidence layer that produces tamper-evident records of what happened during an agent session, signed by both the site owner and the agent deployer.

**What it does**

When an agent completes a significant action on a site — submitting a form, completing a purchase, modifying a resource — the membrane generates a session receipt. The receipt contains a structured record of the session: what DOM state the site served, what actions the agent took, what the outcome was. The site owner's private key signs the DOM state they served. The agent deployer's private key signs the agent's perception and action trace.

If the two signatures are consistent with each other and with the session record, the receipt is valid. If they are not — if the DOM the site claims to have served does not match what the agent claims to have received — that discrepancy is itself cryptographic evidence of either IPI or agent hallucination or deliberate misrepresentation.

The receipt is stored by the membrane and can be exported in a legally readable format. When a dispute arises — an enterprise claims an agent made an unauthorized purchase, an agent deployer claims the site served malicious content — the receipt is the evidence.

**Why this becomes possible at Layer 4 and not earlier**

At Layer 1 you have no agent deployers in your install base. At Layer 3 you have enough site operators with meaningful conformance data that agent deployers have a reason to integrate — their agents are already being scored by your system and they want their side of the session recorded so that low scores caused by IPI or site errors can be contested. The cold start problem of the two-sided install dissolves naturally.

**What it produces**

Tamper-evident session receipts with dual signatures. Legal-grade export format for enterprise dispute resolution. An audit trail indexed by session, agent identity, site, and action type.

**What it unlocks**

The enterprise revenue tier. Once receipts are cited in agent SLAs and dispute resolutions, removing you means giving up the evidence trail. This is the deepest lock-in mechanism in the stack.

**Interpretation boundary**

Dual-signed receipts prove that specific signed content was served and that specific signed actions were taken. They do not prove that any outcome was or was not the appropriate response to that content. Causality — proving why the agent took the action it did — comes in Layer 5.

---

## Layer 5 — Causal Attribution Graph

**What it is**

A per-session graph that records not just what happened during an agent session but the causal chain: which DOM element triggered which perception step, which perception step triggered which decision, which decision triggered which action.

**What it does**

Every existing attribution approach works from logs after a session fails. The best published methods achieve around fifty percent accuracy at identifying which agent caused a failure and around fourteen percent at pinpointing the specific failure step. Those numbers are from o1 and DeepSeek R1 — the best available models — applied to post-hoc log analysis.

The causal graph is structurally different. It is built during the session, not reconstructed afterward. Each node in the graph is an observable event: a DOM element rendered, a network request made, a tool call issued, an action taken. Each edge is a temporal dependency: event B happened within the causal window of event A and is attributable to it based on the session's execution context.

When a failure occurs, you walk the graph backward from the failure node. The path to the root of the failure is the causal chain. You are not guessing attribution — you are reading a recorded dependency graph.

**How it connects to existing layers**

The behavioral trace from Layer 2 is the raw material for the causal graph. Layer 2 records what happened. Layer 5 records why, by indexing the events with their temporal and contextual dependencies rather than just their occurrence order.

The IPI deviation events from Layer 1 become nodes in the causal graph. If an IPI deviation event appears in the graph and a downstream action traces causally to that node, you can say with precision: the agent deviated because it received adversarial content at this specific DOM element at this specific timestamp. That is a structurally different claim from "the agent deviated around the time the site looked different."

**What it produces**

A per-session causal graph stored and queryable. An attribution API: given a session ID and a failure event, return the causal path to the failure root with confidence scores at each node. An IPI attribution signal: when a deviation event appears in the causal path to a failure, flag it as a suspected IPI-induced failure.

**What it unlocks**

Counterfactual replay in Layer 6. You cannot replay against a hypothetical without knowing the causal structure of the original session. The graph is the prerequisite.

**Interpretation boundary**

The causal graph records observable dependencies between events in the session's HTTP and DOM layer. It does not have access to the agent's internal reasoning steps, model weights, or prompt context. Causal attribution at this layer is behavioral, not cognitive — you can prove which external event preceded which external action, not why the model chose to respond to it that way.

---

## Layer 6 — Counterfactual Replay

**What it is**

The ability to re-run a specific agent session with one element mutated — a specific DOM element changed, a specific tool response replaced, a specific policy declaration altered — and observe whether the outcome changes.

**What it does**

When site owner and agent deployer dispute the cause of a session failure, the standard approach is to argue from logs. Your approach is to prove it. You take the recorded session from Layer 4's receipts and Layer 5's causal graph, mutate the suspected causal element, replay the session against the mutation, and observe whether the outcome flips.

If mutating element X flips a failed session into a successful one, X is proven to be a necessary cause of the failure. If the session still fails, X is not the cause — look elsewhere in the graph. This is the published DoVer method applied commercially, on demand, as a paid API call.

The replay uses the clean DOM baseline from the pre-flight scan as the ground truth state. Mutations are applied as targeted diffs to that baseline. The agent's behavior in the replay is observed through the same membrane infrastructure that observed the original session.

**What it produces**

A replay API: given a session ID and a mutation specification, return pass or fail with a confidence score and the causal path that changed. An on-demand dispute resolution service. A counterfactual report in legal-readable format that can be attached to an enterprise SLA dispute.

**When to build this**

Only when at least one enterprise customer has an active dispute they need resolved and is willing to pay for the resolution specifically. Do not build this until the demand is explicit. The infrastructure cost is high and the use case is real but rare. Layer 5's attribution graph will handle the majority of disputes without needing full replay.

**Interpretation boundary**

Counterfactual replay proves necessary causation for the specific session replayed. It does not prove that the same causal relationship holds in general, across agents, or across site states. It is evidence, not a universal finding.

---

## How the Layers Compose

The pre-flight scan produces the clean baseline. Layer 1 uses the baseline to detect runtime deviations. Layer 2 uses Layer 1's telemetry infrastructure to build the behavioral corpus. Layer 3 exposes the corpus as an API that creates WAF lock-in. Layer 4 adds cryptographic evidence once both sides of the market are present. Layer 5 structures the evidence into a causal graph. Layer 6 runs interventions against the graph to prove causation.

Each layer is independently shippable and independently valuable. You do not need all six to have a product. You need Layer 1 to have a product. Each subsequent layer is an expansion of the product, not a prerequisite for having one.

---

## Revenue Model

Layer 1 and 2 are free or freemium. They are the distribution mechanism. The value to site operators is clear enough that installation friction is low.

Layer 3 is the first paid tier — drift score API calls, WAF integration support, segment-level intelligence reports. Priced per site per month with a volume discount at scale.

Layer 4 is the enterprise tier. Tamper-evident receipt storage, legal-grade export, dual-signing infrastructure, SLA attestation. Priced per enterprise contract, not per session.

Layer 6 is the dispute resolution service. Priced per replay request. High margin, low volume.

The IPI threat intelligence feed — the library of real-world IPI patterns detected across all sites on the membrane — is sold separately to agent framework teams (LangChain, CrewAI, AutoGPT) as a security dataset subscription.

---

## Sequencing Rule

Build one layer until it has real users on real sites before starting the next. Working code that nobody is using is not a completed layer. A completed layer has at least one site operator who installed it and finds it useful. That is the gate for moving forward.

The temptation will be to build all six in code before shipping any of them. That is the failure mode this document is explicitly designed to prevent.

---

## What This Is Not

This is not an agent framework. Agent Contract OS does not run agents.

This is not a model safety system. It does not inspect model weights, training data, or internal reasoning.

This is not a log aggregator. Logs are inputs. The membrane is an inference layer on top of those logs that produces signed, causal, replayable evidence.

This is not theoretical. The IPI detection baseline, the behavioral telemetry path, and the causal graph approach are all grounded in published methods. The commercial application of those methods to the open web is what has not been done before.

---

## Current Rule

Keep this file current. When a layer is fully shipped and has real users, mark it as implemented and move it to the Implemented section of context.md. Delete stale plans. Git history is the archive.
