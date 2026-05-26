import { test } from "node:test";
import assert from "node:assert/strict";

// detectPII reads config from process.env via config.js. Set vars BEFORE
// dynamically importing so the config module sees them.
process.env.GEMINI_API_KEY = "test-key";
process.env.SPLUNK_HEC_URL = "http://localhost:9999/services/collector";
process.env.SPLUNK_TOKEN = "test-token";

const { detectPII } = await import("./index.js");

function stubFetch(textFromLLM) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      candidates: [{ content: { parts: [{ text: textFromLLM }] } }],
    }),
  });
  return () => { globalThis.fetch = original; };
}

test("detectPII returns containsPII=false for a clean log", async () => {
  const restore = stubFetch(JSON.stringify({ findings: [] }));
  try {
    const r = await detectPII("Database connection established to PostgreSQL.");
    assert.equal(r.containsPII, false);
    assert.equal(r.severity, "none");
    assert.deepEqual(r.findings, []);
    assert.equal(r.aiAudited, true);
    assert.equal(r.aiError, null);
  } finally { restore(); }
});

test("detectPII redacts a credit card via regex even if LLM finds nothing", async () => {
  const restore = stubFetch(JSON.stringify({ findings: [] }));
  try {
    const r = await detectPII("Processing payment for CC: 4111-1111-1111-1111.");
    assert.equal(r.containsPII, true);
    assert.equal(r.severity, "critical");
    assert.ok(r.redactedMessage.includes("[REDACTED_CREDIT_CARD]"));
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].source, "regex");
  } finally { restore(); }
});

test("detectPII combines regex CC with LLM-found address", async () => {
  const restore = stubFetch(JSON.stringify({
    findings: [{ category: "address", value: "221B Baker Street" }],
  }));
  try {
    const msg = "Order at 221B Baker Street, charged 4111-1111-1111-1111.";
    const r = await detectPII(msg);
    assert.equal(r.findings.length, 2);
    assert.equal(r.severity, "critical");
    assert.ok(r.redactedMessage.includes("[REDACTED_ADDRESS]"));
    assert.ok(r.redactedMessage.includes("[REDACTED_CREDIT_CARD]"));
  } finally { restore(); }
});

test("detectPII drops LLM finding that overlaps a regex finding", async () => {
  // LLM tries to label the email span as "name" — regex already has it as email.
  const restore = stubFetch(JSON.stringify({
    findings: [{ category: "name", value: "jane.doe@example.com" }],
  }));
  try {
    const r = await detectPII("contact jane.doe@example.com now");
    assert.equal(r.findings.length, 1);
    assert.equal(r.findings[0].source, "regex");
    assert.equal(r.findings[0].category, "email");
  } finally { restore(); }
});

test("detectPII falls open to regex-only when LLM fails", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("offline"); };
  try {
    const r = await detectPII("CC: 4111-1111-1111-1111 leak");
    assert.equal(r.containsPII, true);
    assert.equal(r.aiAudited, false);
    assert.equal(r.aiError, "network");
    assert.equal(r.findings.length, 1);
    assert.ok(r.redactedMessage.includes("[REDACTED_CREDIT_CARD]"));
  } finally { globalThis.fetch = original; }
});

test("detectPII reports detection timings as numbers", async () => {
  const restore = stubFetch(JSON.stringify({ findings: [] }));
  try {
    const r = await detectPII("nothing here");
    assert.equal(typeof r.detectionMs.regex, "number");
    assert.equal(typeof r.detectionMs.llm, "number");
    assert.ok(r.detectionMs.regex >= 0);
    assert.ok(r.detectionMs.llm >= 0);
  } finally { restore(); }
});
