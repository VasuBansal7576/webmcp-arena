import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

export const nowIso = () => new Date().toISOString();

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export async function readText(path) {
  return readFile(path, "utf8");
}

export function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
