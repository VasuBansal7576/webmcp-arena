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
    digest: "SkVtDL00vaL5sgW7VIEJ4qHC_zmbrikbItom2nRLeIQ",
    subject: "arena.checkout.owned-execution-stack:vulnerable",
  }),
  fixed: Object.freeze({
    algorithm: "sha256",
    digest: "q3dxrDFxZgScxaRPR3MkIDho3Jw03QIcc94o0WC1smw",
    subject: "arena.checkout.owned-execution-stack:fixed",
  }),
});
