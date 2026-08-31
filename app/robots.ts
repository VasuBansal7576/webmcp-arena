import type { MetadataRoute } from "next";
import { ARENA_CANONICAL_ORIGIN } from "@/src/docs-catalog.js";

export default function robots(): MetadataRoute.Robots {
  return { rules: { userAgent: "*", allow: "/" }, sitemap: new URL("/sitemap.xml", ARENA_CANONICAL_ORIGIN).href };
}
