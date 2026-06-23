import { dirname } from "node:path";
import { mkdir } from "node:fs/promises";
import { scanUrl } from "./scanner.js";
import { loadMcpManifest } from "./mcp.js";
import { runSyntheticMissions } from "./missions.js";
import { nowIso, readText, sha256, writeJson } from "./util.js";

export async function runMonitor(options = {}) {
  const urls = (options.urls || []).map((url) => new URL(url).href);
  if (!urls.length) throw new Error("runMonitor requires at least one URL");

  const statePath = options.statePath || ".agent/state/pages.json";
  const state = await readState(statePath);
  const checked = [];
  const changed = [];
  const unchanged = [];
  const mcp = options.scanOptions?.mcp ? await loadMcpManifest(options.scanOptions.mcp, options.scanOptions) : null;

  for (const url of urls) {
    const page = await fetchPage(url, options);
    const previous = state.pages[url];
    const current = {
      url,
      status: page.status,
      content_hash: sha256(page.text),
      mcp_tool_description_hash: mcp?.tool_description_hash || null,
      checked_at: nowIso(),
    };
    checked.push(current);

    if (previous?.content_hash === current.content_hash && previous?.mcp_tool_description_hash === current.mcp_tool_description_hash) unchanged.push(current);
    else {
      current.previous_hash = previous?.content_hash || null;
      current.previous_mcp_tool_description_hash = previous?.mcp_tool_description_hash || null;
      changed.push(current);
    }
    state.pages[url] = { ...previous, ...current, last_changed_at: previous?.content_hash === current.content_hash && previous?.mcp_tool_description_hash === current.mcp_tool_description_hash ? previous.last_changed_at : current.checked_at };
  }

  await mkdir(dirname(statePath), { recursive: true });
  await writeJson(statePath, state);

  const scans = [];
  for (const page of changed) scans.push(await scanUrl(page.url, options.scanOptions || {}));

  const selectedMissionIds = [...new Set(changed.flatMap((page) => missionsForUrl(page.url)))];
  const missionReport = options.missions && selectedMissionIds.length
    ? await runSyntheticMissions(missionBaseUrl(changed[0].url), {
      browserExecutablePath: options.browserExecutablePath,
      auth: options.auth,
      cacheDir: `${(options.contractDir || ".agent").replace(/\/$/, "")}/cache/missions`,
      evidenceDir: `${(options.contractDir || ".agent").replace(/\/$/, "")}/evidence/mission-artifacts`,
      contentHash: changed.map((page) => page.content_hash).join(":"),
      missionIds: selectedMissionIds,
    })
    : null;

  return {
    generated_at: nowIso(),
    statePath,
    checked,
    changed,
    unchanged,
    selectedMissionIds,
    scans,
    missionReport,
  };
}

async function fetchPage(url, options) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs || 15000);
  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "AgentContractOS/0.1 monitor", ...(options.auth?.headers || {}) },
    });
    return { status: response.status, text: await response.text() };
  } finally {
    clearTimeout(timeout);
  }
}

async function readState(path) {
  try {
    const state = JSON.parse(await readText(path));
    return { version: "1.0.0", pages: state.pages || {} };
  } catch {
    return { version: "1.0.0", pages: {} };
  }
}

function missionsForUrl(input) {
  const { pathname } = new URL(input);
  if (/pricing|plans|packages/i.test(pathname)) return ["find_pricing"];
  if (/api|quickstart|docs|developer/i.test(pathname)) return ["find_api_quickstart"];
  if (pathname === "/" || pathname === "") return ["understand_company", "find_pricing", "find_api_quickstart"];
  return ["understand_company"];
}

function missionBaseUrl(input) {
  const url = new URL(input);
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.href;
}
