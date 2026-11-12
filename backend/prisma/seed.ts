import { PrismaClient, RiskSeverity } from "@prisma/client";

const prisma = new PrismaClient();

async function main(): Promise<void> {
  const effectiveFrom = new Date("2026-01-01T00:00:00.000Z");
  const rules = [
    ["R001", 1, "High transaction velocity", RiskSeverity.HIGH, 35],
    ["R002", 1, "New device with unusual activity", RiskSeverity.HIGH, 28],
    ["R003", 1, "Circular transfers", RiskSeverity.CRITICAL, 40],
    ["R004", 1, "Dormant account reactivation", RiskSeverity.MEDIUM, 25],
    ["R005", 1, "Transaction on closed account", RiskSeverity.CRITICAL, 60],
    ["R006", 1, "Negative balance without overdraft", RiskSeverity.HIGH, 45],
    ["R007", 1, "Transfer reconciliation mismatch", RiskSeverity.CRITICAL, 55],
    ["R008", 1, "Unusual merchant activity", RiskSeverity.MEDIUM, 25],
    ["R009", 1, "Repeated suspicious transaction attempts", RiskSeverity.HIGH, 40],
    ["R010", 1, "False-positive evaluation scenario", RiskSeverity.LOW, 10],
  ] as const;

  for (const [ruleCode, version, name, severity, weight] of rules) {
    await prisma.riskRule.upsert({
      where: { ruleCode_version: { ruleCode, version } },
      update: { name, severity, weight, effectiveFrom, enabled: true },
      create: {
        ruleCode,
        version,
        name,
        description: `${name} risk rule`,
        severity,
        weight,
        effectiveFrom,
      },
    });
  }
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
