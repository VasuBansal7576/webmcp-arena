import assert from "node:assert/strict";
import test from "node:test";

import { createAdapterRegistry, defineOwnedTargetAdapter } from "../src/adapter-sdk.js";

function ownedAdapter(id = "arena.checkout") {
  return defineOwnedTargetAdapter({
    manifest: {
      id,
      version: "1.0.0",
      claimScope: ["owned_fixture:checkout"],
      trustMode: "server_attested",
    },
    targetHarness: {
      establish: async () => {},
      provision: async () => {},
      release: async () => {},
    },
    routeRunner: {
      runHuman: async () => {},
      runAgent: async () => {},
    },
    createRecipe: async () => ({}),
  });
}

test("the adapter registry accepts only explicitly defined owned-target adapters", () => {
  const checkout = ownedAdapter();
  const registry = createAdapterRegistry([checkout]);

  assert.equal(registry.get("arena.checkout"), checkout);
  assert.deepEqual(registry.list(), [{
    id: "arena.checkout",
    version: "1.0.0",
    claimScope: ["owned_fixture:checkout"],
    trustMode: "server_attested",
  }]);
  assert.equal(Object.isFrozen(registry.list()[0]), true);
  assert.equal("load" in registry, false);

  assert.throws(
    () => createAdapterRegistry([{
      manifest: checkout.manifest,
      targetHarness: checkout.targetHarness,
      routeRunner: checkout.routeRunner,
      createRecipe: checkout.createRecipe,
    }]),
    /defineOwnedTargetAdapter/,
  );
});

test("the registry rejects duplicate and unknown adapter identities", () => {
  assert.throws(
    () => createAdapterRegistry([ownedAdapter(), ownedAdapter()]),
    /duplicate owned-target adapter arena\.checkout/,
  );
  const registry = createAdapterRegistry([ownedAdapter()]);
  assert.throws(() => registry.get("arena.unknown"), /unknown owned-target adapter arena\.unknown/);
});

test("adapter manifests are canonical, immutable, and narrowly scoped", () => {
  assert.throws(() => ownedAdapter("../checkout"), /manifest id/);
  assert.throws(() => defineOwnedTargetAdapter({
    manifest: {
      id: "arena.checkout",
      version: "1.0.0",
      claimScope: ["*"],
      trustMode: "server_attested",
    },
    targetHarness: { establish() {}, provision() {}, release() {} },
    routeRunner: { runHuman() {}, runAgent() {} },
    createRecipe() {},
  }), /claim scope/);

  const adapter = ownedAdapter();
  assert.equal(Object.isFrozen(adapter), true);
  assert.equal(Object.isFrozen(adapter.manifest), true);
  assert.equal(Object.isFrozen(adapter.manifest.claimScope), true);
});
