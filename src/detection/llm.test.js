import { test } from "node:test";
import assert from "node:assert/strict";
import { llmDetector } from "./llm.js";

const OPTIONS = { apiKey: "test-key", model: "gemini-test", timeoutMs: 1000 };

function stubFetch(response) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => response;
  return () => { globalThis.fetch = original; };
}

function geminiResponse(findings) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      candidates: [{
        content: { parts: [{ text: JSON.stringify({ findings }) }] },
      }],
    }),
  };
}

test("llmDetector returns parsed findings on success", async () => {
  const restore = stubFetch(geminiResponse([
    { category: "address", value: "Baker Street" },
  ]));
  try {
    const result = await llmDetector("user at Baker Street.", OPTIONS);
    assert.equal(result.error, null);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].category, "address");
    assert.equal(result.findings[0].source, "llm");
    assert.equal(result.findings[0].start, 8);
    assert.equal(result.findings[0].end, 20);
    assert.equal(result.findings[0].severity, "medium");
  } finally { restore(); }
});

test("llmDetector tags severity from the category map", async () => {
  const restore = stubFetch(geminiResponse([
    { category: "name", value: "Alice" },
  ]));
  try {
    const result = await llmDetector("hi Alice today.", OPTIONS);
    assert.equal(result.findings[0].severity, "low");
  } finally { restore(); }
});

test("llmDetector drops hallucinated substrings (not found in message)", async () => {
  const restore = stubFetch(geminiResponse([
    { category: "address", value: "Nowhere Place" },
    { category: "name",    value: "Alice" },
  ]));
  try {
    const result = await llmDetector("Alice was here.", OPTIONS);
    assert.equal(result.error, null);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].category, "name");
  } finally { restore(); }
});

test("llmDetector returns error=timeout when fetch throws TimeoutError", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => {
    const err = new Error("aborted");
    err.name = "TimeoutError";
    throw err;
  };
  try {
    const result = await llmDetector("any", OPTIONS);
    assert.equal(result.error, "timeout");
    assert.deepEqual(result.findings, []);
  } finally { globalThis.fetch = original; }
});

test("llmDetector returns error=network on generic fetch failure", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("offline"); };
  try {
    const result = await llmDetector("any", OPTIONS);
    assert.equal(result.error, "network");
    assert.deepEqual(result.findings, []);
  } finally { globalThis.fetch = original; }
});

test("llmDetector returns error=http_500 on non-ok response", async () => {
  const restore = stubFetch({ ok: false, status: 500, json: async () => ({}) });
  try {
    const result = await llmDetector("any", OPTIONS);
    assert.equal(result.error, "http_500");
  } finally { restore(); }
});

test("llmDetector returns error=malformed_json on bad JSON in candidate", async () => {
  const restore = stubFetch({
    ok: true,
    status: 200,
    json: async () => ({
      candidates: [{ content: { parts: [{ text: "not json {{" }] } }],
    }),
  });
  try {
    const result = await llmDetector("any", OPTIONS);
    assert.equal(result.error, "malformed_json");
  } finally { restore(); }
});

test("llmDetector returns error=empty_response when no candidates", async () => {
  const restore = stubFetch({
    ok: true,
    status: 200,
    json: async () => ({ candidates: [] }),
  });
  try {
    const result = await llmDetector("any", OPTIONS);
    assert.equal(result.error, "empty_response");
  } finally { restore(); }
});

test("llmDetector returns error=malformed_response when response.json() throws", async () => {
  const restore = stubFetch({
    ok: true,
    status: 200,
    json: async () => { throw new Error("bad json body"); },
  });
  try {
    const result = await llmDetector("any", OPTIONS);
    assert.equal(result.error, "malformed_response");
    assert.deepEqual(result.findings, []);
  } finally { restore(); }
});
