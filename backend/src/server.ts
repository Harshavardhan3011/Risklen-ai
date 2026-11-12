import type { Express } from "express";
import { createPostgresApp } from "./postgres-server.js";
import { createSqliteApp } from "./sqlite-server.js";

const mode = process.env.NODE_ENV === "test" ? "sqlite" : (process.env.DATABASE_MODE ?? "postgres");
const app: Express = mode === "sqlite" ? createSqliteApp() : await createPostgresApp();

if (process.env.NODE_ENV !== "test" && !process.argv.includes("--test")) {
  const port = Number(process.env.PORT ?? 4000);
  app.listen(port, () => console.log(`RiskLens API listening on ${port} (${mode})`));
}

export default app;
