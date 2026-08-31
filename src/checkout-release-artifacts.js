export const CHECKOUT_RELEASE_EXECUTION_FILES = Object.freeze([
  "src/adapter-sdk.js",
  "src/boundary-audit.js",
  "src/checkout-audit-adapter.js",
  "src/checkout-fixture.js",
  "src/effect-settlement.js",
  "src/generated-release-audit.js",
  "src/hosted-audit.js",
  "src/webmcp-tool-definition.js",
]);

export const CHECKOUT_RELEASE_ARTIFACTS = Object.freeze({
  vulnerable: Object.freeze({
    algorithm: "sha256",
    digest: "QKQh1-SYYSh4amawRxqrKfsVpDMcuuy-eR0qEQ8wwPg",
    subject: "arena.checkout.owned-execution-stack:vulnerable",
  }),
  fixed: Object.freeze({
    algorithm: "sha256",
    digest: "gVQpf1-gKnFFVzSI-pqR6GlSwd8f6B8ihOApQfHuUko",
    subject: "arena.checkout.owned-execution-stack:fixed",
  }),
});
