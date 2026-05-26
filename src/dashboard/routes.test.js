import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import { createStore } from "./store.js";
import { createDashboardRouter } from "./routes.js";

// Helper: boot an isolated server on an ephemeral port, return {url, close}.
async function bootApp(store, htmlPath = "/no/such/file.html") {
  const app = express();
  app.use(createDashboardRouter(store, htmlPath));
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

function makeEntry(overrides = {}) {
  return {
    ts: 1700000000000,
    level: "INFO",
    originalMessage: "raw",
    redactedMessage: "red",
    severity: "none",
    categories: [],
    sources: [],
    aiAudited: true,
    detectionMs: { regex: 0.1, llm: 5.2 },
    ...overrides,
  };
}

test("GET /api/dashboard/snapshot returns 200 and the expected shape", async () => {
  const store = createStore();
  store.record(makeEntry({ severity: "low", categories: ["email"], sources: ["regex"] }));
  store.record(makeEntry({ severity: "critical", categories: ["api_key"], sources: ["llm"] }));

  const app = await bootApp(store);
  try {
    const res = await fetch(`${app.url}/api/dashboard/snapshot`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "application/json; charset=utf-8");
    const body = await res.json();

    assert.equal(body.counters.totalProcessed, 2);
    assert.equal(body.counters.totalRedacted, 2);
    assert.equal(body.counters.llmOnlyCatches, 1);
    assert.equal(body.recent.length, 2);
    assert.equal(body.recent[0].severity, "critical"); // newest first
    assert.deepEqual(body.severityCounts, { low: 1, medium: 0, high: 0, critical: 1 });
    assert.deepEqual(body.categoryCounts, { email: 1, api_key: 1 });
  } finally { await app.close(); }
});

test("GET /api/dashboard/stream returns 200 with SSE headers and prelude", async () => {
  const store = createStore();
  const app = await bootApp(store);
  try {
    const controller = new AbortController();
    const res = await fetch(`${app.url}/api/dashboard/stream`, { signal: controller.signal });
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/event-stream");
    assert.equal(res.headers.get("cache-control"), "no-cache");

    // Read the first chunk; should contain the ": connected" prelude.
    const reader = res.body.getReader();
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    assert.ok(text.includes(": connected"), `expected prelude, got: ${text}`);

    controller.abort();
  } finally { await app.close(); }
});

test("GET /api/dashboard/stream pushes recorded events to a connected client", async () => {
  const store = createStore();
  const app = await bootApp(store);
  try {
    const controller = new AbortController();
    const res = await fetch(`${app.url}/api/dashboard/stream`, { signal: controller.signal });
    const reader = res.body.getReader();
    // Drain the prelude.
    await reader.read();

    // Record an event AFTER the stream is open.
    store.record(makeEntry({ originalMessage: "hello-sse", severity: "low" }));

    // Read the data frame.
    const { value } = await reader.read();
    const text = new TextDecoder().decode(value);
    assert.ok(text.startsWith("data: "), `expected data frame, got: ${text}`);
    const payload = JSON.parse(text.slice("data: ".length));
    assert.equal(payload.originalMessage, "hello-sse");

    controller.abort();
  } finally { await app.close(); }
});

test("closing the SSE stream unsubscribes (no leak)", async () => {
  const store = createStore();
  const app = await bootApp(store);
  try {
    const controller = new AbortController();
    const res = await fetch(`${app.url}/api/dashboard/stream`, { signal: controller.signal });
    const reader = res.body.getReader();
    await reader.read(); // prelude
    controller.abort();
    // Give the server a tick to process the close event.
    await new Promise((r) => setTimeout(r, 50));

    // After abort, calling record should not blow up the server (no dangling write).
    store.record(makeEntry());
    // Snapshot still works.
    const snap = await fetch(`${app.url}/api/dashboard/snapshot`).then((r) => r.json());
    assert.equal(snap.counters.totalProcessed, 1);
  } finally { await app.close(); }
});
