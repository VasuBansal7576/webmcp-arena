declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    ARENA_SIGNING_PRIVATE_JWK?: string;
    ARENA_SIGNING_PUBLIC_JWK?: string;
    ARENA_SIGNING_ARCHIVED_PUBLIC_JWKS?: string;
    ARENA_ALLOW_EPHEMERAL_SIGNING?: string;
  }
}
