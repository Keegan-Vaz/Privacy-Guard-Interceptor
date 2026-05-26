import { test } from "node:test";
import assert from "node:assert/strict";
import { severityFor, maxSeverity, CATEGORY_SEVERITY } from "./severity.js";

test("severityFor returns critical for credit_card", () => {
  assert.equal(severityFor("credit_card"), "critical");
});

test("severityFor returns high for iban", () => {
  assert.equal(severityFor("iban"), "high");
});

test("severityFor returns medium for address", () => {
  assert.equal(severityFor("address"), "medium");
});

test("severityFor returns low for name", () => {
  assert.equal(severityFor("name"), "low");
});

test("severityFor falls back to low for unknown category", () => {
  assert.equal(severityFor("not_a_real_category"), "low");
});

test("maxSeverity of empty findings is 'none'", () => {
  assert.equal(maxSeverity([]), "none");
});

test("maxSeverity picks the highest rank", () => {
  const findings = [
    { severity: "low" },
    { severity: "critical" },
    { severity: "medium" },
  ];
  assert.equal(maxSeverity(findings), "critical");
});

test("CATEGORY_SEVERITY covers all spec categories", () => {
  const required = [
    "credit_card", "ssn", "api_key", "private_key", "password",
    "jwt", "oauth_token", "iban", "dob", "passport_or_national_id",
    "medical_record", "address", "phone", "email", "name", "other",
  ];
  for (const c of required) {
    assert.ok(CATEGORY_SEVERITY[c], `missing severity for ${c}`);
  }
});
