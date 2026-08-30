import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://webmcp-arena.zippy17.chatgpt.site"),
  title: "Arena — Prove WebMCP tools preserve human protections",
  description: "A live Human-vs-Agent Boundary Audit for WebMCP tools, delayed effects, approval boundaries, and signed evidence.",
  openGraph: {
    title: "Arena — A tool description is not proof",
    description: "Watch Arena catch a WebMCP preview tool that charges after it returns.",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "Arena Human-vs-Agent Boundary Audit" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Arena — A tool description is not proof",
    description: "Behavioral verification for WebMCP tools.",
    images: ["/og.png"],
  },
  alternates: { canonical: "/" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
