import type { MetadataRoute } from "next";
import { absoluteDocsCatalog, ARENA_CANONICAL_ORIGIN } from "@/src/docs-catalog.js";

export default function sitemap(): MetadataRoute.Sitemap {
  const paths = ["/", "/docs", "/use-cases", "/blog", ...absoluteDocsCatalog().map(({ path }) => path)];
  return [...new Set(paths)].map((path) => ({ url: new URL(path, ARENA_CANONICAL_ORIGIN).href, changeFrequency: "weekly" }));
}
