import { readText, sha256 } from "./util.js";
import { fetchTextSafely } from "./safe-fetch.js";

export async function loadAgentSkills(input, options = {}) {
  const result = await readSkills(input, options);
  if (!result.ok) {
    return {
      discovered: false,
      source: input,
      error: result.error || `Agent skills index fetch failed with ${result.status}`,
      skill_count: 0,
      skills: [],
    };
  }
  try {
    return analyzeAgentSkills(JSON.parse(result.text), result.url, result.text);
  } catch (error) {
    return {
      discovered: false,
      source: result.url,
      error: `Agent skills index is not valid JSON: ${error.message}`,
      skill_count: 0,
      skills: [],
    };
  }
}

export function analyzeAgentSkills(manifest, source = "inline", rawText = JSON.stringify(manifest)) {
  const skills = extractSkills(manifest);
  return {
    discovered: true,
    source,
    version: manifest?.version || "",
    content_hash: sha256(rawText || JSON.stringify(manifest)),
    skill_count: skills.length,
    skills,
  };
}

async function readSkills(input, options) {
  if (/^https?:\/\//i.test(input)) return fetchSkills(input, options);
  try {
    return { ok: true, url: input, status: 200, text: await readText(input) };
  } catch (error) {
    return { ok: false, url: input, status: 0, text: "", error: error.message };
  }
}

async function fetchSkills(input, options) {
  try {
    return await fetchTextSafely(input, { ...options, accept: "application/json,*/*" });
  } catch (error) {
    return { ok: false, url: input, status: 0, text: "", error: error.message };
  }
}

function extractSkills(manifest) {
  const candidates = [
    manifest?.skills,
    manifest?.capabilities,
    manifest?.agent_skills,
  ].filter(Array.isArray).flat();
  return candidates.map((skill) => {
    if (typeof skill === "string") return { id: skill, description: "" };
    return {
      id: String(skill?.id || skill?.name || skill?.title || ""),
      description: String(skill?.description || skill?.summary || ""),
    };
  }).filter((skill) => skill.id);
}
