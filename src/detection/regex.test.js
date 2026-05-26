import { test } from "node:test";
import assert from "node:assert/strict";
import { regexDetector, luhnValid, ibanValid } from "./regex.js";

// --- Luhn ---
test("luhnValid: real Visa test card passes", () => {
  assert.equal(luhnValid("4111111111111111"), true);
});

test("luhnValid: real Mastercard test card passes", () => {
  assert.equal(luhnValid("5500000000000004"), true);
});

test("luhnValid: invalid card fails", () => {
  assert.equal(luhnValid("1234567890123456"), false);
});

test("luhnValid: too-short string fails", () => {
  assert.equal(luhnValid("411111"), false);
});

// --- IBAN ---
test("ibanValid: valid DE IBAN passes", () => {
  assert.equal(ibanValid("DE89 3704 0044 0532 0130 00"), true);
});

test("ibanValid: invalid checksum fails", () => {
  assert.equal(ibanValid("DE00 3704 0044 0532 0130 00"), false);
});

test("ibanValid: unknown country code fails", () => {
  assert.equal(ibanValid("ZZ89 3704 0044 0532 0130 00"), false);
});

// --- regexDetector ---
test("regexDetector finds nothing in a clean log", () => {
  const findings = regexDetector("Database connection established to PostgreSQL.");
  assert.deepEqual(findings, []);
});

test("regexDetector finds a Luhn-valid Visa credit card", () => {
  // Note: some sample logs in data-generator.js use non-Luhn-valid cards on
  // purpose (e.g., 4532-1111-2222-3333). Those get rejected by regex but
  // should still be caught contextually by the LLM in the integration test.
  const msg = "Processing payment for CC: 4111-1111-1111-1111.";
  const findings = regexDetector(msg);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "credit_card");
  assert.equal(findings[0].source, "regex");
  assert.equal(findings[0].severity, "critical");
  assert.equal(msg.slice(findings[0].start, findings[0].end), "4111-1111-1111-1111");
});

test("regexDetector rejects 16-digit non-card numbers (Luhn)", () => {
  const findings = regexDetector("order id 1234567890123456 processed");
  assert.equal(findings.filter(f => f.category === "credit_card").length, 0);
});

test("regexDetector finds an SSN", () => {
  const findings = regexDetector("New customer onboarded with SSN 123-45-6789.");
  const ssns = findings.filter(f => f.category === "ssn");
  assert.equal(ssns.length, 1);
});

test("regexDetector finds an AWS access key", () => {
  const findings = regexDetector("AWS Token used: AKIAIOSFODNN7EXAMPLE.");
  const keys = findings.filter(f => f.category === "api_key");
  assert.equal(keys.length, 1);
});

test("regexDetector finds a GitHub PAT", () => {
  const findings = regexDetector("PAT: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
  assert.equal(findings.filter(f => f.category === "api_key").length, 1);
});

test("regexDetector finds a Google API key", () => {
  const findings = regexDetector("key AIzaSyD-fakekey-1234567890abcdefGHI here");
  assert.equal(findings.filter(f => f.category === "api_key").length, 1);
});

test("regexDetector finds a Stripe secret key", () => {
  const findings = regexDetector("sk_live_51HabcXYZ123abcDEFmore");
  assert.equal(findings.filter(f => f.category === "api_key").length, 1);
});

test("regexDetector finds a Slack webhook URL", () => {
  const findings = regexDetector("hook: https://hooks.slack.com/services/T00/B11/abc123secret done");
  assert.equal(findings.filter(f => f.category === "api_key").length, 1);
});

test("regexDetector finds a JWT", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123";
  const findings = regexDetector(`Authorization: Bearer ${jwt} here`);
  // The bearer pattern AND the jwt pattern both match; both are api_key/jwt.
  assert.ok(findings.some(f => f.category === "jwt"));
});

test("regexDetector deduplicates overlapping regex matches (JWT in Bearer header)", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123";
  const msg = `Authorization: Bearer ${jwt} done`;
  const findings = regexDetector(msg);
  // Exactly one finding should remain after dedup; the first PATTERN (jwt) wins.
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, "jwt");
});

test("regexDetector finds a private key block", () => {
  const findings = regexDetector("dump: -----BEGIN RSA PRIVATE KEY----- here");
  assert.equal(findings.filter(f => f.category === "private_key").length, 1);
});

test("regexDetector finds an IBAN", () => {
  const findings = regexDetector("IBAN logged: DE89 3704 0044 0532 0130 00.");
  assert.equal(findings.filter(f => f.category === "iban").length, 1);
});

test("regexDetector rejects invalid IBAN checksum", () => {
  const findings = regexDetector("IBAN logged: DE00 3704 0044 0532 0130 00.");
  assert.equal(findings.filter(f => f.category === "iban").length, 0);
});

test("regexDetector finds an email", () => {
  const findings = regexDetector("User email jane.doe@example.com bound to invoice.");
  assert.equal(findings.filter(f => f.category === "email").length, 1);
});

test("regexDetector offsets locate the exact substring", () => {
  const msg = "User email jane.doe@example.com bound";
  const findings = regexDetector(msg);
  const email = findings.find(f => f.category === "email");
  assert.equal(msg.slice(email.start, email.end), "jane.doe@example.com");
});
