import { readText } from "./util.js";

export async function loadAuthProfile(path, env = process.env) {
  if (!path) return null;
  const profile = JSON.parse(await readText(path));
  const headers = {};
  const cookies = [];
  const usedEnv = new Set();

  for (const [name, spec] of Object.entries(profile.headers || {})) {
    const resolved = resolveSecret(spec, env);
    headers[name.toLowerCase()] = resolved.value;
    usedEnv.add(resolved.env);
  }

  for (const cookie of profile.cookies || []) {
    const resolved = resolveSecret(cookie.value, env);
    usedEnv.add(resolved.env);
    cookies.push({
      name: cookie.name,
      value: resolved.value,
      url: cookie.url,
      domain: cookie.domain,
      path: cookie.path || "/",
      httpOnly: Boolean(cookie.httpOnly),
      secure: Boolean(cookie.secure),
      sameSite: cookie.sameSite,
    });
  }

  return {
    headers,
    cookies,
    audit: {
      name: profile.name || "auth-profile",
      headers: Object.keys(headers),
      cookies: cookies.map((cookie) => cookie.name),
      env: [...usedEnv].sort(),
    },
  };
}

function resolveSecret(spec, env) {
  if (!spec || typeof spec !== "object" || !spec.env) {
    throw new Error("Auth profile secret values must reference env variables, e.g. {\"env\":\"TOKEN\",\"prefix\":\"Bearer \"}.");
  }
  const value = env[spec.env];
  if (!value) throw new Error(`Missing environment variable for auth profile: ${spec.env}`);
  return { env: spec.env, value: `${spec.prefix || ""}${value}${spec.suffix || ""}` };
}
