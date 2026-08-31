import type { NextConfig } from "next";

const securityHeaders = [
  { key: "Content-Security-Policy", value: "base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), geolocation=(), microphone=(), payment=()" },
] as const;

const nextConfig: NextConfig = {
  async headers() {
    return [
      { source: "/", headers: [...securityHeaders] },
      { source: "/:path*", headers: [...securityHeaders] },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/.well-known/arena-signing-key.json",
        destination: "/api/signing-key",
      },
      {
        source: "/.well-known/arena-signing-keys.json",
        destination: "/api/signing-keys",
      },
    ];
  },
};

export default nextConfig;
