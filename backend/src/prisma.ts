import { PrismaClient } from "@prisma/client";

/**
 * PostgreSQL client for repositories that opt into the Prisma adapter.
 * The existing SQLite adapter remains the default until DATABASE_MODE is
 * explicitly switched by a later integration phase.
 */
export const prisma = new PrismaClient();
