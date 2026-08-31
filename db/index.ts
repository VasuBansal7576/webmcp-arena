import { env } from "cloudflare:workers";
import { createAuditDatabaseProvider } from "./runtime";

export const getAuditDb = createAuditDatabaseProvider(() => env.DB);
