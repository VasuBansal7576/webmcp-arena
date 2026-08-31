import { getEvidenceSigningKeySet } from "@/lib/evidence-signing";

export const runtime = "edge";

export async function GET() {
  try {
    const keySet = await getEvidenceSigningKeySet();
    const cacheControl = keySet.currentKeySource === "configured" ? "public, max-age=300" : "no-store";
    return Response.json(keySet, {
      headers: {
        "access-control-allow-origin": "*",
        "cache-control": cacheControl,
      },
    });
  } catch (error) {
    console.error("Arena signing key-set discovery failed", error);
    return Response.json({ error: "Arena signing key set is unavailable" }, {
      status: 503,
      headers: { "cache-control": "no-store", "retry-after": "30" },
    });
  }
}
