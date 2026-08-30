export function loadArenaConfig(env = process.env) {
  const production = env.NODE_ENV === "production";
  const signingSecret = env.ARENA_SIGNING_SECRET || (production ? "" : "arena-local-demo-signing-secret");
  if (production && signingSecret.length < 32) throw new Error("ARENA_SIGNING_SECRET must contain at least 32 characters in production");
  if (!production && signingSecret.length < 16) throw new Error("ARENA_SIGNING_SECRET must contain at least 16 characters");
  const trustedIssuers = parseTrustedIssuers(env.ARENA_TRUSTED_ISSUERS_JSON);
  const requireVerifiedAgents = production || enabled(env.ARENA_REQUIRE_VERIFIED_AGENTS);
  if (requireVerifiedAgents && !trustedIssuers.length) throw new Error("ARENA_TRUSTED_ISSUERS_JSON must configure at least one trusted issuer");
  const remoteExecutionEnabled = enabled(env.ARENA_ENABLE_REMOTE_EXECUTION);
  const remoteInspectionEnabled = remoteExecutionEnabled || enabled(env.ARENA_ENABLE_REMOTE_INSPECTION);
  const operatorToken = env.ARENA_OPERATOR_TOKEN || "";
  if (production && operatorToken.length < 32) {
    throw new Error("ARENA_OPERATOR_TOKEN must contain at least 32 characters in production");
  }
  return {
    production,
    signingSecret,
    operatorToken,
    trustedIssuers,
    requireVerifiedAgents,
    protectHumanRoutes: production,
    remoteExecutionEnabled,
    remoteInspectionEnabled,
    dataPath: env.ARENA_DATA_PATH || ".arena/arena.sqlite",
    originTrialToken: env.ARENA_ORIGIN_TRIAL_TOKEN || "",
    browserExecutable: env.ARENA_BROWSER_EXECUTABLE || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    browserMode: env.ARENA_BROWSER_MODE === "compatibility" ? "compatibility" : "native",
    browserHeadless: env.ARENA_BROWSER_MODE === "compatibility",
    allowPrivateTargets: !production && enabled(env.ARENA_ALLOW_PRIVATE_TARGETS),
    host: env.HOST || (production ? "0.0.0.0" : "127.0.0.1"),
    port: port(env.PORT),
  };
}

function parseTrustedIssuers(value) {
  if (!value) return [];
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("ARENA_TRUSTED_ISSUERS_JSON must be valid JSON");
  }
  if (!Array.isArray(parsed)) throw new Error("ARENA_TRUSTED_ISSUERS_JSON must be a JSON array");
  return parsed;
}

function enabled(value) {
  return String(value).toLowerCase() === "true";
}

function port(value) {
  const parsed = Number(value || 4173);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) throw new Error("PORT must be an integer between 1 and 65535");
  return parsed;
}
