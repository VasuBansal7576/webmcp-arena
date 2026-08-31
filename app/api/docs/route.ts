import { absoluteDocsCatalog, ARENA_ERROR_CODES } from "@/src/docs-catalog.js";

export const runtime = "edge";

export function GET(request: Request) {
  const origin = new URL(request.url).origin;
  return Response.json({
    kind: "arena.documentation_index",
    version: 1,
    generatedFrom: "src/docs-catalog.js",
    docs: absoluteDocsCatalog(origin),
    machine: {
      llms: new URL("/llms.txt", origin).href,
      fullContext: new URL("/llms-full.txt", origin).href,
      proofSchema: new URL("/schemas/arena-proof-v1.schema.json", origin).href,
      signingKeys: new URL("/.well-known/arena-signing-keys.json", origin).href,
    },
    errors: ARENA_ERROR_CODES,
  }, { headers: { "cache-control": "public, max-age=300" } });
}
