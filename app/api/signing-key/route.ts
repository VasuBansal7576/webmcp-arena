import { getEvidenceSigningPublicKey } from "@/lib/evidence-signing";

export const runtime = "edge";

export async function GET() {
  try {
    const key = await getEvidenceSigningPublicKey();
    const cacheControl = key.keySource === "configured" ? "public, max-age=300" : "no-store";
    return Response.json(key, {
      headers: {
        "access-control-allow-origin": "*",
        "cache-control": cacheControl,
      },
    });
  } catch (error) {
    console.error("Arena signing key discovery failed", error);
    return Response.json({ error: "Arena signing identity is unavailable" }, {
      status: 503,
      headers: { "cache-control": "no-store", "retry-after": "30" },
    });
  }
}
