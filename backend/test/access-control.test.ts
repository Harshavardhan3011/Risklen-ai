import assert from "node:assert/strict";
import { test } from "node:test";
import { canAccessCustomerRecord, matchesExternalSecret, validProvisioningPassword } from "../src/access-control.js";

test("customer access is limited to the linked customer", () => {
  assert.equal(canAccessCustomerRecord("CUSTOMER", "customer-1", "customer-1"), true);
  assert.equal(canAccessCustomerRecord("CUSTOMER", "customer-1", "customer-2"), false);
  assert.equal(canAccessCustomerRecord("CUSTOMER", null, "customer-1"), false);
  assert.equal(canAccessCustomerRecord("ANALYST", null, "customer-2"), true);
});

test("administrator bootstrap secret comparison is exact and timing-safe", () => {
  assert.equal(matchesExternalSecret("outside-secret", "outside-secret"), true);
  assert.equal(matchesExternalSecret("outside-secret", "other-secret"), false);
  assert.equal(matchesExternalSecret("outside-secret", "outside-secret-extra"), false);
});

test("provisioning passwords enforce length and bcrypt byte limits", () => {
  assert.equal(validProvisioningPassword("a sufficiently long password"), true);
  assert.equal(validProvisioningPassword("short"), false);
  assert.equal(validProvisioningPassword("é".repeat(37)), false);
});
