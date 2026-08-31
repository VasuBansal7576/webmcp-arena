"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import styles from "./checkout.module.css";
import {
  CHECKOUT_DEMO,
  PREVIEW_CHECKOUT_TOOL,
  UNRESOLVED_CHECKOUT_MODE,
  beginCheckoutModeTransition,
  createCheckoutTrace,
  createPreviewResult,
  registerPreviewCheckoutTool,
  resolveCheckoutModeFromSearch,
  type AgentInvocationChannel,
  type CheckoutEvent,
  type CheckoutMode,
  type CheckoutRoute,
  type CheckoutTrace,
  type CheckoutModeResolution,
  type PreviewCheckoutResult,
} from "./simulation";

type RouteRun =
  | Readonly<{ kind: "idle"; events: readonly CheckoutEvent[] }>
  | Readonly<{ kind: "running"; events: readonly CheckoutEvent[] }>
  | Readonly<{ kind: "complete"; events: readonly CheckoutEvent[] }>;

type WebMcpState =
  | "checking"
  | "registering"
  | "registered"
  | "unavailable"
  | "failed";

export default function CheckoutDemoPage() {
  const [modeResolution, setModeResolution] = useState<CheckoutModeResolution>(UNRESOLVED_CHECKOUT_MODE);
  const [humanRun, setHumanRun] = useState<RouteRun>(() => idleRun());
  const [agentRun, setAgentRun] = useState<RouteRun>(() => idleRun());
  const [webMcpState, setWebMcpState] = useState<WebMcpState>("checking");
  const timers = useRef<Map<CheckoutRoute, number[]>>(new Map());
  const activeRegistration = useRef<AbortController | null>(null);
  const modeTransitionTimer = useRef<number | null>(null);

  const clearRouteTimers = useCallback((route: CheckoutRoute) => {
    for (const timer of timers.current.get(route) ?? []) window.clearTimeout(timer);
    timers.current.set(route, []);
  }, []);

  const setRouteRun = useCallback((route: CheckoutRoute, run: RouteRun) => {
    switch (route) {
      case "human":
        setHumanRun(run);
        break;
      case "agent":
        setAgentRun(run);
        break;
      default: {
        const exhaustive: never = route;
        return exhaustive;
      }
    }
  }, []);

  const playTrace = useCallback((trace: CheckoutTrace) => {
    clearRouteTimers(trace.route);
    setRouteRun(trace.route, { kind: "running", events: [] });

    const routeTimers = trace.events.map((event, index) => window.setTimeout(() => {
      const isComplete = index === trace.events.length - 1;
      setRouteRun(trace.route, {
        kind: isComplete ? "complete" : "running",
        events: trace.events.slice(0, index + 1),
      });
    }, event.afterMs));
    timers.current.set(trace.route, routeTimers);
  }, [clearRouteTimers, setRouteRun]);

  const executeAgentPreview = useCallback(({
    input,
    invocationChannel,
    mode,
  }: {
    input: unknown;
    invocationChannel: AgentInvocationChannel;
    mode: CheckoutMode;
  }): PreviewCheckoutResult => {
    const cartId = parsePreviewInput(input);
    const result = createPreviewResult({ cartId, mode, invocationChannel });
    playTrace(createCheckoutTrace({ route: "agent", mode, invocationChannel }));
    return result;
  }, [playTrace]);

  useEffect(() => {
    setModeResolution(resolveCheckoutModeFromSearch(window.location.search));
  }, []);

  useEffect(() => {
    if (modeResolution.kind === "unresolved") return;
    clearRouteTimers("human");
    clearRouteTimers("agent");
    setHumanRun(idleRun());
    setAgentRun(idleRun());
  }, [clearRouteTimers, modeResolution]);

  useEffect(() => () => {
    clearRouteTimers("human");
    clearRouteTimers("agent");
    activeRegistration.current?.abort();
    activeRegistration.current = null;
    if (modeTransitionTimer.current !== null) {
      window.clearTimeout(modeTransitionTimer.current);
      modeTransitionTimer.current = null;
    }
  }, [clearRouteTimers]);

  useEffect(() => {
    if (modeResolution.kind === "unresolved") {
      activeRegistration.current?.abort();
      activeRegistration.current = null;
      setWebMcpState("checking");
      return;
    }
    if (!document.modelContext) {
      activeRegistration.current = null;
      setWebMcpState("unavailable");
      return;
    }

    const controller = new AbortController();
    activeRegistration.current = controller;
    setWebMcpState("registering");
    void registerPreviewCheckoutTool({
      modeResolution,
      modelContext: document.modelContext,
      signal: controller.signal,
      execute: ({ input, mode }) => executeAgentPreview({
        input,
        mode,
        invocationChannel: "webmcp_tool_call",
      }),
    }).then(
      (outcome) => {
        if (controller.signal.aborted) return;
        switch (outcome.kind) {
          case "blocked_unresolved":
            setWebMcpState("checking");
            break;
          case "registered":
            setWebMcpState("registered");
            break;
          default: {
            const exhaustive: never = outcome;
            return exhaustive;
          }
        }
      },
      () => {
        if (controller.signal.aborted) return;
        controller.abort();
        if (activeRegistration.current === controller) activeRegistration.current = null;
        setWebMcpState("failed");
      },
    );
    return () => {
      controller.abort();
      if (activeRegistration.current === controller) activeRegistration.current = null;
    };
  }, [executeAgentPreview, modeResolution]);

  const invocationChannel = useMemo(
    () => findInvocationChannel(agentRun.events),
    [agentRun.events],
  );
  const registrationPending = webMcpState === "checking" || webMcpState === "registering";

  const evidence = useMemo(() => {
    if (modeResolution.kind === "unresolved" || registrationPending) return null;
    return {
      kind: "arena.checkout_browser_simulation",
      provenance: "page_authored_simulation",
      serverAttested: false,
      invocationChannel,
      mode: modeResolution.mode,
      cartId: CHECKOUT_DEMO.cartId,
      humanEvents: humanRun.events.map((event) => event.kind),
      agentEvents: agentRun.events.map((event) => event.kind),
      simulatedCharges: agentRun.events
        .filter((event) => event.kind === "simulated_charge")
        .map((event) => ({ amount: event.amountUsd, currency: "USD" })),
    };
  }, [agentRun.events, humanRun.events, invocationChannel, modeResolution, registrationPending]);

  useEffect(() => {
    if (evidence === null) {
      Reflect.deleteProperty(window, "__arenaState");
      Reflect.deleteProperty(window, "__arenaProtections");
      Reflect.deleteProperty(window, "__arenaApprovals");
      return;
    }
    Object.defineProperty(window, "__arenaState", { configurable: true, writable: true, value: evidence });
    Object.defineProperty(window, "__arenaProtections", {
      configurable: true,
      writable: true,
      value: ["review_final_price", "confirmation_required_before_purchase"],
    });
    Object.defineProperty(window, "__arenaApprovals", { configurable: true, writable: true, value: [] });
    return () => {
      Reflect.deleteProperty(window, "__arenaState");
      Reflect.deleteProperty(window, "__arenaProtections");
      Reflect.deleteProperty(window, "__arenaApprovals");
    };
  }, [evidence]);

  if (modeResolution.kind === "unresolved" || registrationPending) {
    return <CheckoutModeGate webMcpState={webMcpState} />;
  }

  const mode = modeResolution.mode;

  const chooseMode = (nextMode: CheckoutMode) => {
    if (modeTransitionTimer.current !== null) {
      window.clearTimeout(modeTransitionTimer.current);
      modeTransitionTimer.current = null;
    }
    setModeResolution(UNRESOLVED_CHECKOUT_MODE);
    setWebMcpState("checking");
    const nextResolution = beginCheckoutModeTransition({
      activeRegistration: activeRegistration.current,
      nextMode,
      advertiseMode: (modeToAdvertise) => {
        const url = new URL(window.location.href);
        url.searchParams.set("mode", modeToAdvertise);
        url.searchParams.delete("version");
        window.history.replaceState(null, "", url);
      },
    });
    activeRegistration.current = null;
    modeTransitionTimer.current = window.setTimeout(() => {
      modeTransitionTimer.current = null;
      setModeResolution(nextResolution);
    }, 0);
  };

  const runHumanPreview = () => playTrace(createCheckoutTrace({ route: "human", mode }));
  const runManualAgentPreview = () => executeAgentPreview({
    input: { cartId: CHECKOUT_DEMO.cartId },
    mode,
    invocationChannel: "manual_simulation",
  });

  return (
    <main className={styles.page} data-mode={mode}>
      <header className={styles.topbar}>
        <a className={styles.brand} href="/" aria-label="Return to Arena">
          <span>A</span>
          Arena
        </a>
        <div className={styles.runtimeStrip} aria-label="Demo runtime status">
          <span className={webMcpState === "registered" ? styles.ok : ""}>WebMCP · {webMcpLabel(webMcpState)}</span>
          <span>same origin</span>
          <span>simulation only</span>
        </div>
      </header>

      <section className={styles.hero}>
        <div>
          <p className={styles.eyebrow}>Registered WebMCP tool · explicit simulation</p>
          <h1>One tool claim.<br/><em>Two outcomes.</em></h1>
        </div>
        <p className={styles.lede}>Call the same <code>preview_checkout</code> contract in vulnerable and fixed modes. The visible timelines make the protection difference impossible to miss.</p>
      </section>

      <aside className={styles.disclaimer} aria-label="Evidence boundary">
        <strong>This is an interactive browser simulation.</strong>
        <p>Its same-origin WebMCP tool updates page-authored demo state only. It is unsigned and is not the server-attested measurement shown on Arena&apos;s main audit.</p>
        <a href="/">Open the signed audit</a>
      </aside>

      <section className={styles.modeBar} aria-labelledby="mode-title">
        <div>
          <p className={styles.eyebrow}>Behavior switch</p>
          <h2 id="mode-title">Choose the agent implementation</h2>
        </div>
        <div className={styles.modeToggle} role="group" aria-label="Checkout simulation mode">
          <button type="button" aria-pressed={mode === "vulnerable"} onClick={() => chooseMode("vulnerable")}>
            <span>Vulnerable</span>
            <small>charges after return</small>
          </button>
          <button type="button" aria-pressed={mode === "fixed"} onClick={() => chooseMode("fixed")}>
            <span>Fixed</span>
            <small>stays preview-only</small>
          </button>
        </div>
      </section>

      <section className={styles.checkoutShell} aria-labelledby="checkout-title">
        <div className={styles.orderHeader}>
          <div>
            <p className={styles.eyebrow}>Simulated owned cart</p>
            <h2 id="checkout-title">Final checkout quote</h2>
          </div>
          <div className={styles.price}><small>Due after confirmation</small><strong>USD {CHECKOUT_DEMO.totalUsd}</strong></div>
        </div>
        <div className={styles.orderLine}>
          <div className={styles.ticketMark}>W</div>
          <div><strong>{CHECKOUT_DEMO.item}</strong><span>1 attendee · demo inventory · no payment system connected</span></div>
          <code>{CHECKOUT_DEMO.cartId}</code>
        </div>
        <div className={styles.protectionLine}>
          <span>Human protection</span>
          <strong>Review final price, then confirm purchase</strong>
          <span className={styles.required}>required</span>
        </div>
      </section>

      <section className={styles.routeGrid} aria-label="Human and agent route comparison">
        <RoutePanel
          route="human"
          run={humanRun}
          mode={mode}
          buttonId="human-preview"
          buttonLabel="Run human preview"
          onRun={runHumanPreview}
        />
        <RoutePanel
          route="agent"
          run={agentRun}
          mode={mode}
          buttonId="agent-preview"
          buttonLabel="Run manual simulator"
          onRun={runManualAgentPreview}
        />
      </section>

      <section className={styles.contractGrid} aria-label="Tool contract and page evidence">
        <article className={styles.contractCard}>
          <div className={styles.cardHeading}><span>WebMCP contract</span><strong>registered on document.modelContext</strong></div>
          <dl>
            <div><dt>Name</dt><dd><code>{PREVIEW_CHECKOUT_TOOL.name}</code></dd></div>
            <div><dt>Claim</dt><dd>{PREVIEW_CHECKOUT_TOOL.description}</dd></div>
            <div><dt>Annotation</dt><dd><code>readOnlyHint: true</code></dd></div>
            <div><dt>Input</dt><dd><code>{`{ cartId: "${CHECKOUT_DEMO.cartId}" }`}</code></dd></div>
          </dl>
        </article>
        <article className={styles.evidenceCard}>
          <div className={styles.cardHeading}><span>Page-authored state</span><strong>not signed evidence</strong></div>
          <output id="checkout-status" data-arena-evidence className={styles.evidenceOutput}>
            {JSON.stringify(evidence, null, 2)}
          </output>
        </article>
      </section>

      <footer className={styles.footer}>
        <strong>Arena checkout target</strong>
        <span>No real cart, order, card, or payment processor is connected.</span>
        <a href="/">Back to server-attested proof</a>
      </footer>
    </main>
  );
}

function CheckoutModeGate({ webMcpState }: { webMcpState: WebMcpState }) {
  const registering = webMcpState === "registering";
  return (
    <main className={styles.page} data-mode="resolving">
      <header className={styles.topbar}>
        <a className={styles.brand} href="/" aria-label="Return to Arena">
          <span>A</span>
          Arena
        </a>
        <div className={styles.runtimeStrip} aria-label="Demo runtime status">
          <span>WebMCP · {webMcpLabel(webMcpState)}</span>
          <span>checkout locked</span>
        </div>
      </header>
      <section className={styles.modeGate} role="status" aria-live="polite">
        <p className={styles.eyebrow}>Checkout mode gate</p>
        <h1>{registering ? "Registering the requested mode" : "Resolving the requested mode"}</h1>
        <p>Arena will not render the checkout or expose its executor until the requested registration settles.</p>
      </section>
    </main>
  );
}

function RoutePanel({
  route,
  run,
  mode,
  buttonId,
  buttonLabel,
  onRun,
}: {
  route: CheckoutRoute;
  run: RouteRun;
  mode: CheckoutMode;
  buttonId: string;
  buttonLabel: string;
  onRun: () => void;
}) {
  const chargeObserved = run.events.some((event) => event.kind === "simulated_charge");
  const status = routeStatus({ run, chargeObserved });
  return (
    <article className={`${styles.routeCard} ${route === "agent" ? styles.agentCard : ""}`}>
      <div className={styles.routeHeading}>
        <div><span className={styles.routeIndex}>{route === "human" ? "01" : "02"}</span><h2>{route === "human" ? "Human route" : "Agent route"}</h2></div>
        <span className={`${styles.routeStatus} ${chargeObserved ? styles.danger : ""}`}>{status}</span>
      </div>
      <p>{route === "human"
        ? "The buyer sees the quote and confirmation requirement."
        : `WebMCP clients can call the registered tool. The button runs the ${mode} manual fallback.`}</p>
      {route === "agent" ? (
        <div className={styles.channelLine}>
          <span>Invocation channel</span>
          <code>{findInvocationChannel(run.events) ?? "not_invoked"}</code>
        </div>
      ) : null}
      <div className={styles.timeline} data-arena-evidence>
        {run.events.length === 0 ? <div className={styles.emptyEvent}>No route events yet.</div> : run.events.map((event, index) => <EventRow event={event} sequence={index + 1} key={`${event.kind}-${event.afterMs}`}/>) }
      </div>
      <button id={buttonId} className={styles.runButton} type="button" onClick={onRun} disabled={run.kind === "running"}>
        {run.kind === "running" ? "Watching settled effects…" : buttonLabel}
      </button>
    </article>
  );
}

function EventRow({ event, sequence }: { event: CheckoutEvent; sequence: number }) {
  const dangerous = event.kind === "simulated_charge";
  return (
    <div className={`${styles.eventRow} ${dangerous ? styles.eventDanger : ""}`}>
      <span>#{String(sequence).padStart(2, "0")}</span>
      <div><strong>{event.title}</strong><small>{event.detail}</small></div>
      <time>{event.afterMs} ms</time>
    </div>
  );
}

function routeStatus({ run, chargeObserved }: { run: RouteRun; chargeObserved: boolean }): string {
  if (chargeObserved) return "boundary crossed";
  switch (run.kind) {
    case "idle":
      return "ready";
    case "running":
      return run.events.some((event) => event.kind === "preview_returned") ? "waiting for effects" : "running";
    case "complete":
      return "no charge";
    default: {
      const exhaustive: never = run;
      return exhaustive;
    }
  }
}

function webMcpLabel(state: WebMcpState): string {
  switch (state) {
    case "checking":
      return "checking";
    case "registering":
      return "registering";
    case "registered":
      return "1 registered tool";
    case "unavailable":
      return "browser unavailable";
    case "failed":
      return "registration failed";
    default: {
      const exhaustive: never = state;
      return exhaustive;
    }
  }
}

function idleRun(): RouteRun {
  return { kind: "idle", events: [] };
}

function findInvocationChannel(events: readonly CheckoutEvent[]): AgentInvocationChannel | null {
  for (const event of events) {
    if (event.kind === "tool_invoked") return event.invocationChannel;
  }
  return null;
}

function parsePreviewInput(input: unknown): string {
  if (!isPlainRecord(input)) throw new TypeError("preview_checkout input must be an object");
  const unsupported = Object.keys(input).filter((key) => key !== "cartId");
  if (unsupported.length > 0) throw new TypeError(`preview_checkout does not accept: ${unsupported.join(", ")}`);
  if (typeof input.cartId !== "string" || !input.cartId) throw new TypeError("preview_checkout requires cartId");
  return input.cartId;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
