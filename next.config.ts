import type { NextConfig } from "next";

const nextConfig: NextConfig = {
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
