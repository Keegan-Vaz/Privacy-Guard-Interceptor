import { test } from "node:test";
import assert from "node:assert/strict";
import { createStore } from "./store.js";

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

test("record assigns monotonic ids starting at 1", () => {
  const s = createStore();
  const a = s.record(makeEntry());
  const b = s.record(makeEntry());
  const c = s.record(makeEntry());
  assert.equal(a.id, 1);
  assert.equal(b.id, 2);
  assert.equal(c.id, 3);
});

test("record increments totalProcessed on every call", () => {
  const s = createStore();
  s.record(makeEntry());
  s.record(makeEntry());
  s.record(makeEntry());
  assert.equal(s.getSnapshot().counters.totalProcessed, 3);
});

test("record increments totalRedacted only when severity !== none", () => {
  const s = createStore();
  s.record(makeEntry({ severity: "none" }));
  s.record(makeEntry({ severity: "low" }));
  s.record(makeEntry({ severity: "critical" }));
  assert.equal(s.getSnapshot().counters.totalRedacted, 2);
});

test("record increments llmOnlyCatches only when sources are llm-only (and non-empty)", () => {
  const s = createStore();
  s.record(makeEntry({ sources: [] }));                              // none
  s.record(makeEntry({ sources: ["regex"] }));                       // regex-only
  s.record(makeEntry({ sources: ["regex", "llm"] }));                // mixed
  s.record(makeEntry({ sources: ["llm"] }));                         // llm-only ✓
  s.record(makeEntry({ sources: ["llm", "llm"] }));                  // llm-only ✓
  assert.equal(s.getSnapshot().counters.llmOnlyCatches, 2);
});

test("ring buffer evicts oldest when capacity exceeded", () => {
  const s = createStore({ capacity: 3 });
  s.record(makeEntry({ originalMessage: "a" }));
  s.record(makeEntry({ originalMessage: "b" }));
  s.record(makeEntry({ originalMessage: "c" }));
  s.record(makeEntry({ originalMessage: "d" }));
  const recent = s.getSnapshot().recent;
  assert.equal(recent.length, 3);
  assert.deepEqual(recent.map((e) => e.originalMessage), ["d", "c", "b"]);
});

test("getSnapshot returns recent in newest-first order", () => {
  const s = createStore();
  s.record(makeEntry({ originalMessage: "first" }));
  s.record(makeEntry({ originalMessage: "second" }));
  const recent = s.getSnapshot().recent;
  assert.equal(recent[0].originalMessage, "second");
  assert.equal(recent[1].originalMessage, "first");
});

test("getSnapshot computes severityCounts (excludes 'none')", () => {
  const s = createStore();
  s.record(makeEntry({ severity: "none" }));
  s.record(makeEntry({ severity: "low" }));
  s.record(makeEntry({ severity: "low" }));
  s.record(makeEntry({ severity: "critical" }));
  const { severityCounts } = s.getSnapshot();
  assert.deepEqual(severityCounts, { low: 2, medium: 0, high: 0, critical: 1 });
});

test("getSnapshot computes categoryCounts across all findings", () => {
  const s = createStore();
  s.record(makeEntry({ categories: ["credit_card", "email"] }));
  s.record(makeEntry({ categories: ["credit_card"] }));
  s.record(makeEntry({ categories: ["address"] }));
  const { categoryCounts } = s.getSnapshot();
  assert.deepEqual(categoryCounts, { credit_card: 2, email: 1, address: 1 });
});

test("subscribe callback fires for every subsequent record", () => {
  const s = createStore();
  const seen = [];
  s.subscribe((entry) => seen.push(entry.id));
  s.record(makeEntry());
  s.record(makeEntry());
  s.record(makeEntry());
  assert.deepEqual(seen, [1, 2, 3]);
});

test("subscribe returns unsubscribe that stops further callbacks", () => {
  const s = createStore();
  const seen = [];
  const off = s.subscribe((entry) => seen.push(entry.id));
  s.record(makeEntry());
  off();
  s.record(makeEntry());
  assert.deepEqual(seen, [1]);
});

test("subscribers added during a record() do not receive the in-flight event", () => {
  const s = createStore();
  const seen = [];
  s.subscribe(() => {
    s.subscribe((entry) => seen.push(`late-${entry.id}`));
  });
  s.record(makeEntry()); // late subscriber added here, must NOT see id 1
  s.record(makeEntry()); // late subscriber sees id 2
  assert.deepEqual(seen, ["late-2"]);
});

test("getSnapshot returns copies (mutations don't leak into store)", () => {
  const s = createStore();
  s.record(makeEntry());
  const snap = s.getSnapshot();
  snap.recent.push("garbage");
  snap.counters.totalProcessed = 999;
  const fresh = s.getSnapshot();
  assert.equal(fresh.recent.length, 1);
  assert.equal(fresh.counters.totalProcessed, 1);
});

test("a throwing subscriber does not prevent later subscribers from receiving the event", () => {
  const s = createStore();
  const seen = [];
  s.subscribe(() => { throw new Error("boom"); });
  s.subscribe((entry) => seen.push(entry.id));
  // Silence the expected warning.
  const originalWarn = console.warn;
  console.warn = () => {};
  try {
    s.record(makeEntry());
    s.record(makeEntry());
  } finally {
    console.warn = originalWarn;
  }
  assert.deepEqual(seen, [1, 2]);
});
