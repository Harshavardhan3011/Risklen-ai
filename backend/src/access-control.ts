import { timingSafeEqual } from "node:crypto";

export function canAccessCustomerRecord(role: string, ownCustomerId: string | null, targetCustomerId: string): boolean {
  return role !== "CUSTOMER" || (ownCustomerId !== null && ownCustomerId === targetCustomerId);
}

export function matchesExternalSecret(provided: string, configured: string): boolean {
  const actual = Buffer.from(provided);
  const expected = Buffer.from(configured);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function validProvisioningPassword(password: string): boolean {
  return password.length >= 12 && Buffer.byteLength(password, "utf8") <= 72;
}
