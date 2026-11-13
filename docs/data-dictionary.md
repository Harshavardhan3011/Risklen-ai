# Synthetic data dictionary

All records are deterministic synthetic data; no externally collected personal data is used.

## customers

Synthetic customer identity and contact record.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `fullName` | string | Yes | Synthetic customer legal-name field. |
| `email` | string | No | email value persisted on the customers record. |
| `phone` | string | No | phone value persisted on the customers record. |
| `countryCode` | char(2) | Yes | Two-character ISO 3166-1 alpha-2 country code. |
| `dateOfBirth` | date | No | Synthetic customer birth date. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the customers record. |
| `updatedAt` | timestamptz | Yes | updatedAt value persisted on the customers record. |

## accounts

Financial account and current reconciled balance.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `accountType` | enum | Yes | Financial product type. |
| `status` | enum | Yes | status value persisted on the accounts record. |
| `currency` | string | Yes | currency value persisted on the accounts record. |
| `currentBalance` | decimal(18,2) | Yes | Balance after the final generated ledger movement. |
| `overdraftLimit` | decimal(18,2) | Yes | Maximum permitted negative balance; generated accounts use zero. |
| `openedAt` | timestamptz | Yes | Account lifecycle start timestamp. |
| `closedAt` | timestamptz | No | Account closure timestamp when status is CLOSED. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the accounts record. |
| `updatedAt` | timestamptz | Yes | updatedAt value persisted on the accounts record. |

## merchants

Merchant accepting customer transactions.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `name` | string | Yes | name value persisted on the merchants record. |
| `categoryCode` | string | Yes | categoryCode value persisted on the merchants record. |
| `countryCode` | char(2) | Yes | Two-character ISO 3166-1 alpha-2 country code. |
| `riskRating` | enum | No | riskRating value persisted on the merchants record. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the merchants record. |
| `updatedAt` | timestamptz | Yes | updatedAt value persisted on the merchants record. |

## devices

Pseudonymous device fingerprint and lifecycle state.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `fingerprintHash` | string | Yes | SHA-256 pseudonymous device fingerprint; not a raw device identifier. |
| `deviceType` | enum | Yes | deviceType value persisted on the devices record. |
| `operatingSystem` | string | No | operatingSystem value persisted on the devices record. |
| `status` | enum | Yes | status value persisted on the devices record. |
| `firstSeenAt` | timestamptz | Yes | firstSeenAt value persisted on the devices record. |
| `lastSeenAt` | timestamptz | Yes | lastSeenAt value persisted on the devices record. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the devices record. |
| `updatedAt` | timestamptz | Yes | updatedAt value persisted on the devices record. |

## transactions

Posted or declined debit/credit ledger movement.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `customerId` | string | Yes | customerId value persisted on the transactions record. |
| `accountId` | string | Yes | accountId value persisted on the transactions record. |
| `merchantId` | string | No | merchantId value persisted on the transactions record. |
| `deviceId` | string | No | deviceId value persisted on the transactions record. |
| `transactionType` | enum | Yes | transactionType value persisted on the transactions record. |
| `status` | enum | Yes | status value persisted on the transactions record. |
| `amount` | decimal(18,2) | Yes | Transaction or transfer amount in the associated currency. |
| `balanceBefore` | decimal(18,2) | Yes | Ledger balance immediately before the transaction. |
| `balanceAfter` | decimal(18,2) | Yes | Ledger balance immediately after the transaction. |
| `currency` | string | Yes | currency value persisted on the transactions record. |
| `occurredAt` | timestamptz | Yes | Time the financial event occurred. |
| `postedAt` | timestamptz | No | Time a successful transaction was posted; absent for declined activity. |
| `reference` | string | No | reference value persisted on the transactions record. |
| `metadata` | json | No | Operational transaction attributes; excludes evaluation scenario and label fields. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the transactions record. |

## transfer_links

Bridge connecting paired internal transfer legs.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `transactionId` | string | Yes | transactionId value persisted on the transfer_links record. |
| `sourceAccountId` | string | Yes | sourceAccountId value persisted on the transfer_links record. |
| `targetAccountId` | string | Yes | targetAccountId value persisted on the transfer_links record. |
| `transferType` | enum | Yes | transferType value persisted on the transfer_links record. |
| `amount` | decimal(18,2) | Yes | Transaction or transfer amount in the associated currency. |
| `currency` | string | Yes | currency value persisted on the transfer_links record. |
| `legReference` | string | No | legReference value persisted on the transfer_links record. |
| `occurredAt` | timestamptz | Yes | Time the financial event occurred. |

## risk_rules

Versioned deterministic transaction risk rule.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `ruleCode` | string | Yes | Stable deterministic rule identifier. |
| `version` | integer | Yes | version value persisted on the risk_rules record. |
| `name` | string | Yes | name value persisted on the risk_rules record. |
| `description` | string | Yes | description value persisted on the risk_rules record. |
| `severity` | enum | Yes | severity value persisted on the risk_rules record. |
| `weight` | integer | Yes | weight value persisted on the risk_rules record. |
| `threshold` | string | No | threshold value persisted on the risk_rules record. |
| `enabled` | boolean | Yes | enabled value persisted on the risk_rules record. |
| `effectiveFrom` | timestamptz | Yes | Start of a relationship's validity period. |
| `effectiveTo` | timestamptz | No | End of a relationship's validity period, when ended. |
| `configuration` | json | Yes | configuration value persisted on the risk_rules record. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the risk_rules record. |
| `updatedAt` | timestamptz | Yes | updatedAt value persisted on the risk_rules record. |

## alerts

Rule-triggered transaction review record.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `customerId` | string | Yes | customerId value persisted on the alerts record. |
| `accountId` | string | Yes | accountId value persisted on the alerts record. |
| `transactionId` | string | Yes | transactionId value persisted on the alerts record. |
| `riskRuleId` | string | Yes | riskRuleId value persisted on the alerts record. |
| `evaluationVersion` | string | Yes | evaluationVersion value persisted on the alerts record. |
| `riskScore` | integer | Yes | Deterministic rule weight, capped at 100. |
| `priority` | enum | Yes | Risk band derived from the risk score. |
| `status` | enum | Yes | status value persisted on the alerts record. |
| `explanation` | string | Yes | Human-readable triggering rule and transaction reference. |
| `detectedAt` | timestamptz | Yes | detectedAt value persisted on the alerts record. |
| `closedAt` | timestamptz | No | Account closure timestamp when status is CLOSED. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the alerts record. |

## cases

Analyst review work item grouping related alerts.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `status` | enum | Yes | status value persisted on the cases record. |
| `assignedToId` | string | No | assignedToId value persisted on the cases record. |
| `openedAt` | timestamptz | Yes | Account lifecycle start timestamp. |
| `closedAt` | timestamptz | No | Account closure timestamp when status is CLOSED. |
| `disposition` | enum | No | Analyst-recorded case outcome when available. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the cases record. |
| `updatedAt` | timestamptz | Yes | updatedAt value persisted on the cases record. |

## analyst_actions

Immutable analyst workflow action record.

| Field | Type | Required | Description |
|---|---|---:|---|
| `id` | string | Yes | Immutable primary identifier. |
| `caseId` | string | Yes | caseId value persisted on the analyst_actions record. |
| `actorId` | string | Yes | actorId value persisted on the analyst_actions record. |
| `actionType` | enum | Yes | Recorded analyst workflow action. |
| `fromStatus` | string | No | fromStatus value persisted on the analyst_actions record. |
| `toStatus` | string | No | toStatus value persisted on the analyst_actions record. |
| `disposition` | string | No | Analyst-recorded case outcome when available. |
| `comment` | string | No | comment value persisted on the analyst_actions record. |
| `createdAt` | timestamptz | Yes | createdAt value persisted on the analyst_actions record. |
