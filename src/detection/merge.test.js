import { test } from "node:test";
import assert from "node:assert/strict";
import { merge } from "./merge.js";

const rf = (start, end, category = "credit_card") =>
  ({ category, source: "regex", start, end, severity: "critical" });
const lf = (start, end, category = "address") =>
  ({ category, source: "llm", start, end, severity: "medium" });

test("merge with both empty returns empty", () => {
  assert.deepEqual(merge([], []), []);
});

test("merge returns regex findings when LLM is empty", () => {
  const r = [rf(0, 4)];
  assert.deepEqual(merge(r, []), r);
});

test("merge returns LLM findings when regex is empty", () => {
  const l = [lf(0, 4)];
  assert.deepEqual(merge([], l), l);
});

test("merge keeps non-overlapping LLM findings", () => {
  const r = [rf(0, 4)];
  const l = [lf(10, 20)];
  const out = merge(r, l);
  assert.equal(out.length, 2);
});

test("merge drops LLM finding fully contained by a regex finding", () => {
  const r = [rf(0, 20)];
  const l = [lf(5, 10)];
  const out = merge(r, l);
  assert.equal(out.length, 1);
  assert.equal(out[0].source, "regex");
});

test("merge drops LLM finding that contains a regex finding", () => {
  const r = [rf(5, 10)];
  const l = [lf(0, 20)];
  const out = merge(r, l);
  assert.equal(out.length, 1);
  assert.equal(out[0].source, "regex");
});

test("merge drops LLM finding on partial overlap", () => {
  const r = [rf(5, 15)];
  const l = [lf(10, 20)];
  const out = merge(r, l);
  assert.equal(out.length, 1);
  assert.equal(out[0].source, "regex");
});

test("merge keeps adjacent (touching, non-overlapping) findings", () => {
  // [0,5) ends at 5; [5,10) starts at 5 — no overlap by half-open interval rules.
  const r = [rf(0, 5)];
  const l = [lf(5, 10)];
  const out = merge(r, l);
  assert.equal(out.length, 2);
});

test("merge sorts the final list by start ascending", () => {
  const r = [rf(20, 25), rf(0, 4)];
  const l = [lf(10, 15)];
  const out = merge(r, l);
  assert.deepEqual(out.map(f => f.start), [0, 10, 20]);
});
