import { test } from "node:test";
import assert from "node:assert/strict";
import { redact } from "./redact.js";

test("redact returns original message when findings is empty", () => {
  assert.equal(redact("hello world", []), "hello world");
});

test("redact replaces a single finding with [REDACTED_<CATEGORY>]", () => {
  const msg = "card 4111111111111111 used";
  const findings = [{ category: "credit_card", start: 5, end: 21 }];
  assert.equal(redact(msg, findings), "card [REDACTED_CREDIT_CARD] used");
});

test("redact handles multiple non-overlapping findings in any order", () => {
  // Order intentionally NOT sorted by start.
  const msg = "key AKIAIOSFODNN7EXAMPLE and email a@b.co";
  const findings = [
    { category: "email", start: 35, end: 41 },
    { category: "api_key", start: 4, end: 24 },
  ];
  assert.equal(
    redact(msg, findings),
    "key [REDACTED_API_KEY] and email [REDACTED_EMAIL]",
  );
});

test("redact uppercases category names", () => {
  const findings = [{ category: "address", start: 0, end: 5 }];
  assert.equal(redact("12345 rest", findings), "[REDACTED_ADDRESS] rest");
});

test("redact does not mutate input findings array", () => {
  const findings = [
    { category: "email", start: 0, end: 5 },
    { category: "name",  start: 10, end: 15 },
  ];
  const copy = JSON.stringify(findings);
  redact("12345 6789 ABCDE", findings);
  assert.equal(JSON.stringify(findings), copy);
});

test("redact handles a finding that ends at the last character of the message", () => {
  const msg = "token abc123";
  const findings = [{ category: "api_key", start: 6, end: 12 }];
  assert.equal(redact(msg, findings), "token [REDACTED_API_KEY]");
});

test("redact handles adjacent findings (end of one equals start of next)", () => {
  const msg = "JohnDoeAlice";
  const findings = [
    { category: "name", start: 0, end: 7 },   // "JohnDoe"
    { category: "name", start: 7, end: 12 },  // "Alice"
  ];
  assert.equal(redact(msg, findings), "[REDACTED_NAME][REDACTED_NAME]");
});

test("redact treats a zero-width span as an insertion at that position", () => {
  assert.equal(
    redact("hello", [{ category: "name", start: 3, end: 3 }]),
    "hel[REDACTED_NAME]lo",
  );
});
