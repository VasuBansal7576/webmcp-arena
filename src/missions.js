import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { chromium } from "playwright-core";
import { readText, sha256, writeJson } from "./util.js";

export const PHASE_ONE_MISSIONS = [
  { id: "understand_company", maxTokens: 2000 },
  { id: "find_pricing", maxTokens: 1500 },
  { id: "find_api_quickstart", maxTokens: 1200 },
];

export async function runSyntheticMissions(inputUrl, options = {}) {
  const url = new URL(inputUrl).href;
  const cacheDir = options.cacheDir || ".agent/cache/missions";
  const evidenceDir = options.evidenceDir || join(cacheDir, "artifacts");
  const missions = selectMissions(options.missionIds);
  await mkdir(cacheDir, { recursive: true });
  await mkdir(evidenceDir, { recursive: true });

  const cached = [];
  const missing = [];
  for (const mission of missions) {
    const key = missionKey(url, options.contentHash, mission.id);
    const path = cachePath(cacheDir, key);
    const hit = await readCache(path);
    if (hit) cached.push({ ...hit, cached: true });
    else missing.push({ mission, path, key });
  }

  let browser;
  const fresh = [];
  try {
    if (missing.length) browser = await launchBrowser(options);
    for (const item of missing) {
      const context = await browser.newContext({
        userAgent: "AgentContractOS/0.1 synthetic-mission",
        extraHTTPHeaders: options.auth?.headers || undefined,
      });
      try {
        if (options.auth?.cookies?.length) await context.addCookies(options.auth.cookies);
        const page = await context.newPage();
        const result = await runMission(page, url, item.mission, { evidenceDir, key: item.key });
        await writeJson(item.path, result);
        fresh.push(result);
      } finally {
        await context.close();
      }
    }
  } finally {
    if (browser) await browser.close();
  }

  const results = missions.map((mission) => [...cached, ...fresh].find((item) => item.mission === mission.id));
  return {
    tested: results.length,
    passed: results.filter((item) => item.status === "passed").length,
    failed: results.filter((item) => item.status !== "passed").length,
    auth_profile: options.auth?.audit || null,
    results,
  };
}

function selectMissions(ids) {
  if (!ids?.length) return PHASE_ONE_MISSIONS;
  const wanted = new Set(ids);
  return PHASE_ONE_MISSIONS.filter((mission) => wanted.has(mission.id));
}

async function launchBrowser(options) {
  const executablePath = options.browserExecutablePath || process.env.AGENT_CONTRACT_BROWSER;
  if (!executablePath) {
    throw new Error("Set --browser-executable or AGENT_CONTRACT_BROWSER to run synthetic missions with playwright-core.");
  }
  return chromium.launch({ executablePath, headless: true });
}

async function runMission(page, url, mission, runtime) {
  if (mission.id === "understand_company") return understandCompany(page, url, mission, runtime);
  if (mission.id === "find_pricing") return findPricing(page, url, mission, runtime);
  if (mission.id === "find_api_quickstart") return findApiQuickstart(page, url, mission, runtime);
  throw new Error(`Unknown mission: ${mission.id}`);
}

async function understandCompany(page, url, mission, runtime) {
  const evidence = [];
  await goto(page, url, evidence);
  const snapshot = await pageSnapshot(page);
  const summary = firstMeaningfulSentence(snapshot.text) || snapshot.title;
  return finishMission(page, mission, summary ? "passed" : "failed", summary || "No readable company description found.", snapshot, evidence, runtime);
}

async function findPricing(page, url, mission, runtime) {
  const evidence = [];
  await goto(page, url, evidence);
  const link = await findLink(page, /pricing|plans|packages/i);
  if (link?.href) await goto(page, link.href, evidence);
  const snapshot = await pageSnapshot(page);
  const pricePattern = /(?:free|\$[0-9][0-9,]*(?:\.\d{2})?(?:\s*(?:\/|per)\s*(?:mo|month|repo|year))?)/i;
  const prices = snapshot.text.split(/\n+/).map((line) => line.trim()).filter((line) => pricePattern.test(line));
  const summary = prices.length ? prices.slice(0, 6).join("; ") : "No pricing text found in browser-readable page content.";
  return finishMission(page, mission, prices.length ? "passed" : "failed", summary, snapshot, evidence, runtime);
}

async function findApiQuickstart(page, url, mission, runtime) {
  const evidence = [];
  await goto(page, url, evidence);
  const link = await findLink(page, /api|quickstart|docs|developer/i);
  if (link?.href) await goto(page, link.href, evidence);
  const snapshot = await pageSnapshot(page);
  const endpoint = snapshot.text.match(/\b(GET|POST|PUT|PATCH|DELETE)\s+\/[A-Za-z0-9_./:-]+/i)?.[0]
    || snapshot.text.match(/\bcurl\b[^\n]+/i)?.[0];
  const summary = endpoint || "No API quickstart request found in browser-readable page content.";
  return finishMission(page, mission, endpoint ? "passed" : "failed", summary, snapshot, evidence, runtime);
}

async function goto(page, url, evidence) {
  const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
  evidence.push({ url: page.url(), status: response?.status() || 0 });
}

async function findLink(page, pattern) {
  return page.locator("a").evaluateAll((anchors, source) => {
    const pattern = new RegExp(source, "i");
    const match = anchors.find((anchor) => pattern.test(`${anchor.textContent || ""} ${anchor.href || ""}`));
    return match ? { text: match.textContent?.trim() || "", href: match.href } : null;
  }, pattern.source);
}

async function pageSnapshot(page) {
  const title = await page.title();
  let axText = "";
  try {
    axText = await accessibilityText(page);
  } catch {
    axText = "";
  }
  const text = axText || await page.locator("body").innerText({ timeout: 3000 }).catch(() => "");
  return {
    title,
    representation: axText ? "a11y_tree" : "browser_text",
    text: text.slice(0, 12000),
    textLength: text.length,
  };
}

async function accessibilityText(page) {
  const session = await page.context().newCDPSession(page);
  try {
    const { nodes } = await session.send("Accessibility.getFullAXTree");
    return [...new Set(nodes.flatMap(accessibleNodeText).filter((value) => typeof value === "string").map((value) => value.trim()).filter(Boolean))].join("\n");
  } finally {
    await session.detach?.().catch(() => {});
  }
}

function missionResult(mission, status, summary, snapshot, evidence) {
  const tokens = estimateTokens(snapshot.text);
  return {
    mission: mission.id,
    status,
    summary,
    token_strategy: snapshot.representation,
    tokens_consumed: tokens,
    max_tokens: mission.maxTokens,
    evidence,
    screenshot_path: evidence.find((item) => item.type === "screenshot" && item.ok)?.path || null,
    failure_reason: status === "passed" ? null : "mission_expected_content_not_found",
  };
}

async function finishMission(page, mission, status, summary, snapshot, evidence, runtime) {
  evidence.push(await screenshotEvidence(page, runtime, mission));
  return missionResult(mission, status, summary, snapshot, evidence);
}

async function screenshotEvidence(page, runtime, mission) {
  const path = join(runtime.evidenceDir, `${runtime.key}-${mission.id}.png`);
  try {
    await page.screenshot({ path, fullPage: true });
    return { type: "screenshot", ok: true, path, contentType: "image/png" };
  } catch (error) {
    return { type: "screenshot", ok: false, path, error: error.message };
  }
}

function accessibleNodeText(node) {
  return [
    node.name?.value,
    typeof node.value?.value === "string" ? node.value.value : "",
  ];
}

function estimateTokens(text) {
  return Math.ceil((text || "").length / 4);
}

function firstMeaningfulSentence(text) {
  return (text || "").split(/[.!?]\s+/).find((sentence) => sentence.trim().length > 40)?.trim() || "";
}

function missionKey(url, contentHash, missionId) {
  return sha256(`${url}\n${contentHash || "no-content-hash"}\n${missionId}`).slice(0, 16);
}

function cachePath(cacheDir, key) {
  return join(cacheDir, `${key}.json`);
}

async function readCache(path) {
  try {
    return JSON.parse(await readText(path));
  } catch {
    return null;
  }
}
