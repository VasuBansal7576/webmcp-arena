const ADAPTERS = new WeakSet();
const ADAPTER_ID = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const SEMVER = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/;
const CLAIM_SCOPE = /^[a-z][a-z0-9._-]{1,63}:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TRUST_MODES = new Set(["native_browser", "compatibility_browser", "server_attested"]);

export function defineOwnedTargetAdapter({ manifest, targetHarness, routeRunner, createRecipe } = {}) {
  const normalizedManifest = normalizeManifest(manifest);
  if (!targetHarness || !["establish", "provision", "release"].every((name) => typeof targetHarness[name] === "function")) {
    throw new Error("owned-target adapter requires establish, provision, and release target harness methods");
  }
  if (!routeRunner || !["runHuman", "runAgent"].every((name) => typeof routeRunner[name] === "function")) {
    throw new Error("owned-target adapter requires runHuman and runAgent route runner methods");
  }
  if (typeof createRecipe !== "function") throw new Error("owned-target adapter requires createRecipe");

  const adapter = Object.freeze({
    manifest: normalizedManifest,
    targetHarness: Object.freeze({
      establish: targetHarness.establish.bind(targetHarness),
      provision: targetHarness.provision.bind(targetHarness),
      release: targetHarness.release.bind(targetHarness),
    }),
    routeRunner: Object.freeze({
      runHuman: routeRunner.runHuman.bind(routeRunner),
      runAgent: routeRunner.runAgent.bind(routeRunner),
    }),
    createRecipe: createRecipe.bind(null),
  });
  ADAPTERS.add(adapter);
  return adapter;
}

export function createAdapterRegistry(adapters = []) {
  if (!Array.isArray(adapters)) throw new Error("owned-target adapter registry requires an explicit adapter array");
  const byId = new Map();
  for (const adapter of adapters) {
    if (!ADAPTERS.has(adapter)) {
      throw new Error("registry entries must be created by defineOwnedTargetAdapter");
    }
    const id = adapter.manifest.id;
    if (byId.has(id)) throw new Error(`duplicate owned-target adapter ${id}`);
    byId.set(id, adapter);
  }

  return Object.freeze({
    get(id) {
      const adapter = byId.get(String(id));
      if (!adapter) throw new Error(`unknown owned-target adapter ${String(id)}`);
      return adapter;
    },
    list() {
      return Object.freeze([...byId.values()]
        .map(({ manifest }) => manifest)
        .sort((left, right) => left.id.localeCompare(right.id)));
    },
  });
}

function normalizeManifest(manifest) {
  if (!isPlainObject(manifest)) throw new Error("owned-target adapter manifest is required");
  const allowed = new Set(["id", "version", "claimScope", "trustMode"]);
  const unknown = Object.keys(manifest).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`unknown owned-target adapter manifest field ${unknown.join(", ")}`);

  const id = String(manifest.id || "");
  if (!ADAPTER_ID.test(id) || id.length > 96) throw new Error("owned-target adapter manifest id is invalid");
  const version = String(manifest.version || "");
  if (!SEMVER.test(version)) throw new Error("owned-target adapter manifest version must be semantic version x.y.z");
  if (!Array.isArray(manifest.claimScope) || manifest.claimScope.length === 0 ||
      manifest.claimScope.some((scope) => typeof scope !== "string" || !CLAIM_SCOPE.test(scope))) {
    throw new Error("owned-target adapter claim scope must contain explicit namespace:value entries");
  }
  const claimScope = [...new Set(manifest.claimScope)].sort();
  if (claimScope.length !== manifest.claimScope.length) throw new Error("owned-target adapter claim scope contains duplicates");
  const trustMode = String(manifest.trustMode || "");
  if (!TRUST_MODES.has(trustMode)) throw new Error("owned-target adapter trust mode is invalid");

  return deepFreeze({ id, version, claimScope, trustMode });
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const child of Object.values(value)) deepFreeze(child);
  return value;
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
