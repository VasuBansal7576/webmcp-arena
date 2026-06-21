import { createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

export const nowIso = () => new Date().toISOString();

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function traceId() {
  return randomBytes(16).toString("hex");
}

export function spanId() {
  return randomBytes(8).toString("hex");
}

export async function readText(path) {
  return readFile(path, "utf8");
}

export async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

export async function writeText(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, value);
}

export function number(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

export function attr(name, value) {
  if (typeof value === "number") return { key: name, value: { doubleValue: value } };
  if (typeof value === "boolean") return { key: name, value: { boolValue: value } };
  return { key: name, value: { stringValue: String(value ?? "") } };
}
