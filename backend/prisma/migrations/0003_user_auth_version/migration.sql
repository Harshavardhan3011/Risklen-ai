-- Add token-version invalidation for PostgreSQL authentication.
ALTER TABLE "users"
ADD COLUMN "auth_version" INTEGER NOT NULL DEFAULT 0;
