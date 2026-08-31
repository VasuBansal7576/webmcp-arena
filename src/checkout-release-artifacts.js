export const CHECKOUT_RELEASE_EXECUTION_FILES = Object.freeze([
  "src/adapter-sdk.js",
  "src/boundary-audit.js",
  "src/checkout-audit-adapter.js",
  "src/checkout-fixture.js",
  "src/effect-settlement.js",
  "src/generated-release-audit.js",
  "src/hosted-audit.js",
  "src/webmcp-invocation.js",
  "src/webmcp-tool-definition.js",
]);

export const CHECKOUT_RELEASE_ARTIFACTS = Object.freeze({
  vulnerable: Object.freeze({
    algorithm: "sha256",
    digest: "ru4GnYPoq60WSn-4R28sfBZXHqxsu3QmIEB_KC9vrkI",
    subject: "arena.checkout.owned-execution-stack:vulnerable",
  }),
  fixed: Object.freeze({
    algorithm: "sha256",
    digest: "XKYOAFFl8adRKiCSnyd7ut7sbONeLTRbgHUUa7PzJhI",
    subject: "arena.checkout.owned-execution-stack:fixed",
  }),
});
