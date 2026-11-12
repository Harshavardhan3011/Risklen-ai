-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "evaluation";

-- CreateSchema
CREATE SCHEMA IF NOT EXISTS "public";

-- CreateEnum
CREATE TYPE "UserRole" AS ENUM ('ADMIN', 'ANALYST', 'COMPLIANCE_REVIEWER', 'CUSTOMER');

-- CreateEnum
CREATE TYPE "AccountStatus" AS ENUM ('OPEN', 'DORMANT', 'CLOSED', 'SUSPENDED');

-- CreateEnum
CREATE TYPE "AccountType" AS ENUM ('CHECKING', 'SAVINGS', 'WALLET', 'BUSINESS');

-- CreateEnum
CREATE TYPE "KycStatus" AS ENUM ('PENDING', 'VERIFIED', 'REVIEW', 'REJECTED', 'EXPIRED');

-- CreateEnum
CREATE TYPE "DeviceStatus" AS ENUM ('ACTIVE', 'BLOCKED', 'RETIRED');

-- CreateEnum
CREATE TYPE "TransactionType" AS ENUM ('DEBIT', 'CREDIT', 'TRANSFER', 'REVERSAL', 'FEE');

-- CreateEnum
CREATE TYPE "TransactionStatus" AS ENUM ('PENDING', 'POSTED', 'DECLINED', 'REVERSED', 'FAILED');

-- CreateEnum
CREATE TYPE "TransferType" AS ENUM ('INTERNAL', 'EXTERNAL', 'INTERNATIONAL');

-- CreateEnum
CREATE TYPE "RiskSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "AlertStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'ESCALATED', 'CLOSED', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "CaseStatus" AS ENUM ('NEW', 'IN_PROGRESS', 'PENDING_REVIEW', 'ESCALATED', 'CLOSED');

-- CreateEnum
CREATE TYPE "Disposition" AS ENUM ('CONFIRMED_SUSPICIOUS', 'LEGITIMATE', 'FALSE_POSITIVE', 'FURTHER_INVESTIGATION', 'ESCALATED');

-- CreateEnum
CREATE TYPE "AnalystActionType" AS ENUM ('ASSIGNED', 'UNASSIGNED', 'COMMENTED', 'EVIDENCE_ADDED', 'DISPOSITION_RECORDED', 'STATUS_CHANGED', 'ESCALATED');

-- CreateEnum
CREATE TYPE "EventType" AS ENUM ('CREATED', 'UPDATED', 'STATUS_CHANGED', 'OWNERSHIP_STARTED', 'OWNERSHIP_ENDED', 'DEVICE_LINKED', 'DEVICE_UNLINKED', 'BALANCE_ADJUSTED', 'DISPOSITION_RECORDED');

-- CreateEnum
CREATE TYPE "EvidenceType" AS ENUM ('TRANSACTION', 'ACCOUNT', 'CUSTOMER', 'DEVICE', 'MERCHANT', 'TRANSFER', 'RULE_MATCH', 'SYSTEM');

-- CreateEnum
CREATE TYPE "GenerationStatus" AS ENUM ('STARTED', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "ValidationStatus" AS ENUM ('PASSED', 'FAILED', 'WARNING');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "role" "UserRole" NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "customers" (
    "id" TEXT NOT NULL,
    "fullName" TEXT NOT NULL,
    "email" TEXT,
    "phone" TEXT,
    "countryCode" VARCHAR(2) NOT NULL,
    "dateOfBirth" DATE,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "customers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "kyc_profiles" (
    "id" UUID NOT NULL,
    "customerId" TEXT NOT NULL,
    "status" "KycStatus" NOT NULL,
    "riskRating" "RiskSeverity",
    "verifiedAt" TIMESTAMPTZ(6),
    "expiresAt" TIMESTAMPTZ(6),
    "sourceReference" TEXT,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "kyc_profiles_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "accounts" (
    "id" TEXT NOT NULL,
    "accountType" "AccountType" NOT NULL,
    "status" "AccountStatus" NOT NULL,
    "currency" CHAR(3) NOT NULL,
    "currentBalance" DECIMAL(18,2) NOT NULL,
    "overdraftLimit" DECIMAL(18,2) NOT NULL DEFAULT 0,
    "openedAt" TIMESTAMPTZ(6) NOT NULL,
    "closedAt" TIMESTAMPTZ(6),
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account_owners" (
    "accountId" TEXT NOT NULL,
    "customerId" TEXT NOT NULL,
    "ownershipType" TEXT NOT NULL,
    "effectiveFrom" TIMESTAMPTZ(6) NOT NULL,
    "effectiveTo" TIMESTAMPTZ(6),

    CONSTRAINT "account_owners_pkey" PRIMARY KEY ("accountId","customerId","effectiveFrom")
);

-- CreateTable
CREATE TABLE "merchants" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "categoryCode" VARCHAR(8) NOT NULL,
    "countryCode" VARCHAR(2) NOT NULL,
    "riskRating" "RiskSeverity",
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "merchants_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "devices" (
    "id" TEXT NOT NULL,
    "fingerprintHash" TEXT NOT NULL,
    "deviceType" TEXT NOT NULL,
    "operatingSystem" TEXT,
    "status" "DeviceStatus" NOT NULL,
    "firstSeenAt" TIMESTAMPTZ(6) NOT NULL,
    "lastSeenAt" TIMESTAMPTZ(6) NOT NULL,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "customer_devices" (
    "customerId" TEXT NOT NULL,
    "deviceId" TEXT NOT NULL,
    "effectiveFrom" TIMESTAMPTZ(6) NOT NULL,
    "effectiveTo" TIMESTAMPTZ(6),
    "associationType" TEXT NOT NULL,

    CONSTRAINT "customer_devices_pkey" PRIMARY KEY ("customerId","deviceId","effectiveFrom")
);

-- CreateTable
CREATE TABLE "transactions" (
    "id" TEXT NOT NULL,
    "customerId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "merchantId" TEXT,
    "deviceId" TEXT,
    "transactionType" "TransactionType" NOT NULL,
    "status" "TransactionStatus" NOT NULL,
    "amount" DECIMAL(18,2) NOT NULL,
    "balanceBefore" DECIMAL(18,2) NOT NULL,
    "balanceAfter" DECIMAL(18,2) NOT NULL,
    "currency" CHAR(3) NOT NULL,
    "occurredAt" TIMESTAMPTZ(6) NOT NULL,
    "postedAt" TIMESTAMPTZ(6),
    "reference" TEXT,
    "metadata" JSONB,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "transactions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "transfer_links" (
    "id" TEXT NOT NULL,
    "transactionId" TEXT NOT NULL,
    "sourceAccountId" TEXT NOT NULL,
    "targetAccountId" TEXT NOT NULL,
    "transferType" "TransferType" NOT NULL,
    "amount" DECIMAL(18,2) NOT NULL,
    "currency" CHAR(3) NOT NULL,
    "legReference" TEXT,
    "occurredAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "transfer_links_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_rules" (
    "id" UUID NOT NULL,
    "ruleCode" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "RiskSeverity" NOT NULL,
    "weight" INTEGER NOT NULL,
    "threshold" DECIMAL(18,2),
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "effectiveFrom" TIMESTAMPTZ(6) NOT NULL,
    "effectiveTo" TIMESTAMPTZ(6),
    "configuration" JSONB,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "risk_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alerts" (
    "id" TEXT NOT NULL,
    "customerId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "transactionId" TEXT NOT NULL,
    "riskRuleId" UUID NOT NULL,
    "evaluationVersion" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "priority" "RiskSeverity" NOT NULL,
    "status" "AlertStatus" NOT NULL,
    "explanation" TEXT NOT NULL,
    "detectedAt" TIMESTAMPTZ(6) NOT NULL,
    "closedAt" TIMESTAMPTZ(6),
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "alerts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "cases" (
    "id" TEXT NOT NULL,
    "status" "CaseStatus" NOT NULL,
    "assignedToId" UUID,
    "openedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "closedAt" TIMESTAMPTZ(6),
    "disposition" "Disposition",
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "cases_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_alerts" (
    "caseId" TEXT NOT NULL,
    "alertId" TEXT NOT NULL,
    "linkedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "case_alerts_pkey" PRIMARY KEY ("caseId","alertId")
);

-- CreateTable
CREATE TABLE "analyst_actions" (
    "id" UUID NOT NULL,
    "caseId" TEXT NOT NULL,
    "actorId" UUID NOT NULL,
    "actionType" "AnalystActionType" NOT NULL,
    "fromStatus" "CaseStatus",
    "toStatus" "CaseStatus",
    "disposition" "Disposition",
    "comment" TEXT,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "analyst_actions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_evidence" (
    "id" UUID NOT NULL,
    "alertId" TEXT NOT NULL,
    "evidenceType" "EvidenceType" NOT NULL,
    "sourceId" TEXT,
    "description" TEXT NOT NULL,
    "value" JSONB,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "alert_evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "account_events" (
    "id" UUID NOT NULL,
    "accountId" TEXT NOT NULL,
    "eventType" "EventType" NOT NULL,
    "occurredAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actorId" UUID,
    "details" JSONB,

    CONSTRAINT "account_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alert_events" (
    "id" UUID NOT NULL,
    "alertId" TEXT NOT NULL,
    "eventType" "EventType" NOT NULL,
    "occurredAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actorId" UUID,
    "details" JSONB,

    CONSTRAINT "alert_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "case_events" (
    "id" UUID NOT NULL,
    "caseId" TEXT NOT NULL,
    "eventType" "EventType" NOT NULL,
    "occurredAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actorId" UUID,
    "details" JSONB,

    CONSTRAINT "case_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_events" (
    "id" UUID NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "eventType" "EventType" NOT NULL,
    "actorId" UUID,
    "details" JSONB,
    "occurredAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "generation_runs" (
    "id" UUID NOT NULL,
    "seed" BIGINT NOT NULL,
    "scale" TEXT NOT NULL,
    "status" "GenerationStatus" NOT NULL,
    "startedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMPTZ(6),
    "sourceChecksum" TEXT,
    "metadata" JSONB,

    CONSTRAINT "generation_runs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "validation_results" (
    "id" UUID NOT NULL,
    "generationRunId" UUID,
    "checkName" TEXT NOT NULL,
    "status" "ValidationStatus" NOT NULL,
    "message" TEXT NOT NULL,
    "details" JSONB,
    "checkedAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "validation_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evaluation"."ground_truth_labels" (
    "id" UUID NOT NULL,
    "transactionId" TEXT NOT NULL,
    "customerId" TEXT,
    "scenarioCode" TEXT NOT NULL,
    "isSuspicious" BOOLEAN NOT NULL,
    "expectedRuleCode" TEXT,
    "labelSource" TEXT NOT NULL,
    "createdAt" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "metadata" JSONB,

    CONSTRAINT "ground_truth_labels_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "users_role_idx" ON "users"("role");

-- CreateIndex
CREATE UNIQUE INDEX "customers_email_key" ON "customers"("email");

-- CreateIndex
CREATE INDEX "customers_countryCode_idx" ON "customers"("countryCode");

-- CreateIndex
CREATE INDEX "customers_createdAt_idx" ON "customers"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "kyc_profiles_customerId_key" ON "kyc_profiles"("customerId");

-- CreateIndex
CREATE INDEX "kyc_profiles_status_idx" ON "kyc_profiles"("status");

-- CreateIndex
CREATE INDEX "accounts_status_idx" ON "accounts"("status");

-- CreateIndex
CREATE INDEX "accounts_openedAt_idx" ON "accounts"("openedAt");

-- CreateIndex
CREATE INDEX "account_owners_customerId_effectiveFrom_idx" ON "account_owners"("customerId", "effectiveFrom");

-- CreateIndex
CREATE INDEX "account_owners_accountId_effectiveFrom_idx" ON "account_owners"("accountId", "effectiveFrom");

-- CreateIndex
CREATE INDEX "merchants_categoryCode_idx" ON "merchants"("categoryCode");

-- CreateIndex
CREATE INDEX "merchants_countryCode_idx" ON "merchants"("countryCode");

-- CreateIndex
CREATE UNIQUE INDEX "devices_fingerprintHash_key" ON "devices"("fingerprintHash");

-- CreateIndex
CREATE INDEX "devices_status_idx" ON "devices"("status");

-- CreateIndex
CREATE INDEX "devices_lastSeenAt_idx" ON "devices"("lastSeenAt");

-- CreateIndex
CREATE INDEX "customer_devices_deviceId_effectiveFrom_idx" ON "customer_devices"("deviceId", "effectiveFrom");

-- CreateIndex
CREATE INDEX "transactions_customerId_occurredAt_idx" ON "transactions"("customerId", "occurredAt");

-- CreateIndex
CREATE INDEX "transactions_accountId_occurredAt_idx" ON "transactions"("accountId", "occurredAt");

-- CreateIndex
CREATE INDEX "transactions_merchantId_occurredAt_idx" ON "transactions"("merchantId", "occurredAt");

-- CreateIndex
CREATE INDEX "transactions_deviceId_occurredAt_idx" ON "transactions"("deviceId", "occurredAt");

-- CreateIndex
CREATE INDEX "transactions_status_occurredAt_idx" ON "transactions"("status", "occurredAt");

-- CreateIndex
CREATE INDEX "transfer_links_sourceAccountId_occurredAt_idx" ON "transfer_links"("sourceAccountId", "occurredAt");

-- CreateIndex
CREATE INDEX "transfer_links_targetAccountId_occurredAt_idx" ON "transfer_links"("targetAccountId", "occurredAt");

-- CreateIndex
CREATE UNIQUE INDEX "transfer_links_transactionId_sourceAccountId_targetAccountI_key" ON "transfer_links"("transactionId", "sourceAccountId", "targetAccountId");

-- CreateIndex
CREATE INDEX "risk_rules_ruleCode_enabled_effectiveFrom_idx" ON "risk_rules"("ruleCode", "enabled", "effectiveFrom");

-- CreateIndex
CREATE UNIQUE INDEX "risk_rules_ruleCode_version_key" ON "risk_rules"("ruleCode", "version");

-- CreateIndex
CREATE INDEX "alerts_priority_status_detectedAt_idx" ON "alerts"("priority", "status", "detectedAt");

-- CreateIndex
CREATE INDEX "alerts_customerId_detectedAt_idx" ON "alerts"("customerId", "detectedAt");

-- CreateIndex
CREATE INDEX "alerts_accountId_detectedAt_idx" ON "alerts"("accountId", "detectedAt");

-- CreateIndex
CREATE UNIQUE INDEX "alerts_riskRuleId_transactionId_evaluationVersion_key" ON "alerts"("riskRuleId", "transactionId", "evaluationVersion");

-- CreateIndex
CREATE INDEX "cases_status_updatedAt_idx" ON "cases"("status", "updatedAt");

-- CreateIndex
CREATE INDEX "cases_assignedToId_status_idx" ON "cases"("assignedToId", "status");

-- CreateIndex
CREATE INDEX "case_alerts_alertId_idx" ON "case_alerts"("alertId");

-- CreateIndex
CREATE INDEX "analyst_actions_caseId_createdAt_idx" ON "analyst_actions"("caseId", "createdAt");

-- CreateIndex
CREATE INDEX "analyst_actions_actorId_createdAt_idx" ON "analyst_actions"("actorId", "createdAt");

-- CreateIndex
CREATE INDEX "alert_evidence_alertId_evidenceType_idx" ON "alert_evidence"("alertId", "evidenceType");

-- CreateIndex
CREATE INDEX "account_events_accountId_occurredAt_idx" ON "account_events"("accountId", "occurredAt");

-- CreateIndex
CREATE INDEX "alert_events_alertId_occurredAt_idx" ON "alert_events"("alertId", "occurredAt");

-- CreateIndex
CREATE INDEX "case_events_caseId_occurredAt_idx" ON "case_events"("caseId", "occurredAt");

-- CreateIndex
CREATE INDEX "audit_events_entityType_entityId_occurredAt_idx" ON "audit_events"("entityType", "entityId", "occurredAt");

-- CreateIndex
CREATE INDEX "audit_events_actorId_occurredAt_idx" ON "audit_events"("actorId", "occurredAt");

-- CreateIndex
CREATE INDEX "generation_runs_status_startedAt_idx" ON "generation_runs"("status", "startedAt");

-- CreateIndex
CREATE INDEX "validation_results_generationRunId_status_idx" ON "validation_results"("generationRunId", "status");

-- CreateIndex
CREATE INDEX "validation_results_checkName_checkedAt_idx" ON "validation_results"("checkName", "checkedAt");

-- CreateIndex
CREATE INDEX "ground_truth_labels_transactionId_idx" ON "evaluation"."ground_truth_labels"("transactionId");

-- CreateIndex
CREATE INDEX "ground_truth_labels_scenarioCode_isSuspicious_idx" ON "evaluation"."ground_truth_labels"("scenarioCode", "isSuspicious");

-- CreateIndex
CREATE UNIQUE INDEX "ground_truth_labels_transactionId_scenarioCode_key" ON "evaluation"."ground_truth_labels"("transactionId", "scenarioCode");

-- AddForeignKey
ALTER TABLE "kyc_profiles" ADD CONSTRAINT "kyc_profiles_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_owners" ADD CONSTRAINT "account_owners_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_owners" ADD CONSTRAINT "account_owners_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_devices" ADD CONSTRAINT "customer_devices_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "customer_devices" ADD CONSTRAINT "customer_devices_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "devices"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_merchantId_fkey" FOREIGN KEY ("merchantId") REFERENCES "merchants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transactions" ADD CONSTRAINT "transactions_deviceId_fkey" FOREIGN KEY ("deviceId") REFERENCES "devices"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transfer_links" ADD CONSTRAINT "transfer_links_transactionId_fkey" FOREIGN KEY ("transactionId") REFERENCES "transactions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transfer_links" ADD CONSTRAINT "transfer_links_sourceAccountId_fkey" FOREIGN KEY ("sourceAccountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "transfer_links" ADD CONSTRAINT "transfer_links_targetAccountId_fkey" FOREIGN KEY ("targetAccountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_customerId_fkey" FOREIGN KEY ("customerId") REFERENCES "customers"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_transactionId_fkey" FOREIGN KEY ("transactionId") REFERENCES "transactions"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_riskRuleId_fkey" FOREIGN KEY ("riskRuleId") REFERENCES "risk_rules"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "cases" ADD CONSTRAINT "cases_assignedToId_fkey" FOREIGN KEY ("assignedToId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_alerts" ADD CONSTRAINT "case_alerts_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_alerts" ADD CONSTRAINT "case_alerts_alertId_fkey" FOREIGN KEY ("alertId") REFERENCES "alerts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "analyst_actions" ADD CONSTRAINT "analyst_actions_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "analyst_actions" ADD CONSTRAINT "analyst_actions_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_evidence" ADD CONSTRAINT "alert_evidence_alertId_fkey" FOREIGN KEY ("alertId") REFERENCES "alerts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_events" ADD CONSTRAINT "account_events_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "accounts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_events" ADD CONSTRAINT "account_events_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_events" ADD CONSTRAINT "alert_events_alertId_fkey" FOREIGN KEY ("alertId") REFERENCES "alerts"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alert_events" ADD CONSTRAINT "alert_events_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_events" ADD CONSTRAINT "case_events_caseId_fkey" FOREIGN KEY ("caseId") REFERENCES "cases"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "case_events" ADD CONSTRAINT "case_events_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "validation_results" ADD CONSTRAINT "validation_results_generationRunId_fkey" FOREIGN KEY ("generationRunId") REFERENCES "generation_runs"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
-- Append-only protections for historical records.
-- INSERT remains permitted; UPDATE and DELETE fail at the database boundary.
CREATE OR REPLACE FUNCTION public.prevent_historical_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'Historical record % on table % is append-only', TG_OP, TG_TABLE_NAME
    USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_append_only
BEFORE UPDATE OR DELETE ON public.audit_events
FOR EACH ROW EXECUTE FUNCTION public.prevent_historical_mutation();

CREATE TRIGGER account_events_append_only
BEFORE UPDATE OR DELETE ON public.account_events
FOR EACH ROW EXECUTE FUNCTION public.prevent_historical_mutation();

CREATE TRIGGER alert_events_append_only
BEFORE UPDATE OR DELETE ON public.alert_events
FOR EACH ROW EXECUTE FUNCTION public.prevent_historical_mutation();

CREATE TRIGGER case_events_append_only
BEFORE UPDATE OR DELETE ON public.case_events
FOR EACH ROW EXECUTE FUNCTION public.prevent_historical_mutation();

CREATE TRIGGER analyst_actions_append_only
BEFORE UPDATE OR DELETE ON public.analyst_actions
FOR EACH ROW EXECUTE FUNCTION public.prevent_historical_mutation();