// Unit tests for caps.js — run with: node src/caps.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  CapExceeded,
  EVENT_CAP,
  WASM_INPUT_CAP,
  checkCap,
  measureJsonBytes,
  readTextCapped,
  truncateBytes,
  utf8Len,
} from "./caps.js";

test("over-cap rejected", () => {
  assert.throws(() => checkCap(EVENT_CAP + 1, EVENT_CAP, "probe"), CapExceeded);
});

test("at-cap accepted", () => {
  checkCap(EVENT_CAP, EVENT_CAP, "probe");
});

test("zero accepted", () => {
  checkCap(0, EVENT_CAP, "probe");
});

test("wasm cap is 1 MiB", () => {
  assert.equal(WASM_INPUT_CAP, 1048576);
  checkCap(WASM_INPUT_CAP, WASM_INPUT_CAP, "wasm input");
  assert.throws(
    () => checkCap(WASM_INPUT_CAP + 1, WASM_INPUT_CAP, "wasm input"),
    CapExceeded,
  );
});

test("error is machine-readable JSON, never truncated", () => {
  try {
    checkCap(20000, EVENT_CAP, "queue message body");
    assert.fail("should have thrown");
  } catch (e) {
    assert.ok(e instanceof CapExceeded);
    const j = JSON.parse(e.message); // must parse: machine-readable
    assert.equal(j.error, "cap_exceeded");
    assert.equal(j.what, "queue message body");
    assert.equal(j.bytes, 20000);
    assert.equal(j.cap, EVENT_CAP);
    assert.equal(j.policy, "reject-never-truncate");
  }
});

test("readTextCapped rejects over-limit mid-stream, cancels reader", async () => {
  // pull-based source (like a network body): still open when the violation
  // hits, so reader.cancel() must propagate and stop the producer
  let cancelled = false;
  let produced = 0;
  const stream = new ReadableStream({
    pull(c) {
      produced++;
      c.enqueue(new TextEncoder().encode("x".repeat(10000)));
    },
    cancel() {
      cancelled = true;
    },
  });
  await assert.rejects(() => readTextCapped(stream, EVENT_CAP, "t"), CapExceeded);
  assert.ok(cancelled, "reader must be cancelled immediately");
  assert.ok(produced <= 2, `producer stopped early, produced ${produced} chunks`);
});

test("readTextCapped accepts at-cap across chunk boundaries", async () => {
  const data = new TextEncoder().encode("y".repeat(EVENT_CAP));
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(data.subarray(0, 5000));
      c.enqueue(data.subarray(5000));
      c.close();
    },
  });
  const out = await readTextCapped(stream, EVENT_CAP, "t");
  assert.equal(utf8Len(out), EVENT_CAP);
});

test("truncated JSON never parses silently", () => {
  const full = JSON.stringify({ claim: { id: "w-1" } });
  const truncated = full.slice(0, 10);
  assert.throws(() => JSON.parse(truncated), SyntaxError);
});

test("event envelope at 16 KiB boundary: realistic push event passes", () => {
  const event = {
    type: "cf.artifacts.repo.pushed",
    source: { type: "artifacts.repo", namespace: "wreck", repoName: "task-0042" },
    payload: { ref: "refs/heads/main", before: "a".repeat(40), after: "b".repeat(40) },
  };
  checkCap(utf8Len(JSON.stringify(event)), EVENT_CAP, "push event payload");
});

// ---------- L4: measure-before-materialize ----------

test("L4: measureJsonBytes agrees with JSON.stringify length", () => {
  const v = {
    a: "héllo wörld",
    n: 42,
    f: 1.5,
    b: true,
    z: null,
    arr: [1, "x", null, false],
    nested: { deep: { deeper: [1, 2, 3] } },
    undef: undefined, // dropped by JSON.stringify; measured conservatively
  };
  const measured = measureJsonBytes(v, EVENT_CAP, "probe");
  const actual = utf8Len(JSON.stringify(v));
  assert.ok(measured >= actual, `measured ${measured} < actual ${actual}`);
  assert.ok(measured - actual < 100, `too conservative: ${measured} vs ${actual}`);
});

test("L4: over-cap object throws CapExceeded without full materialization", () => {
  // a 1MB nested object: the measurer must throw CapExceeded (16 KiB cap)
  // without ever building the 1MB string
  const big = { chunks: Array.from({ length: 2000 }, (_, i) => "x".repeat(500) + i) };
  assert.throws(() => measureJsonBytes(big, EVENT_CAP, "probe"), CapExceeded);
});

test("L4: over-cap string measured directly by byte length", () => {
  const s = "y".repeat(EVENT_CAP + 1);
  assert.throws(() => checkCap(utf8Len(s), EVENT_CAP, "probe"), CapExceeded);
  checkCap(utf8Len("y".repeat(EVENT_CAP)), EVENT_CAP, "probe");
});

test("L4: unicode string length counted in UTF-8 bytes, not chars", () => {
  const s = "é".repeat(9000); // 9000 chars = 18000 bytes > 16 KiB
  assert.throws(() => measureJsonBytes({ s }, EVENT_CAP, "probe"), CapExceeded);
  const ok = { s: "é".repeat(8000) }; // 16000 bytes < 16 KiB
  measureJsonBytes(ok, EVENT_CAP, "probe");
});

test("L4: scalars and empty structures measured", () => {
  assert.equal(measureJsonBytes(null, EVENT_CAP, "p"), 4);
  assert.equal(measureJsonBytes(true, EVENT_CAP, "p"), 4);
  assert.equal(measureJsonBytes(false, EVENT_CAP, "p"), 5);
  assert.equal(measureJsonBytes(42, EVENT_CAP, "p"), 2);
  assert.equal(measureJsonBytes("", EVENT_CAP, "p"), 2);
  assert.equal(measureJsonBytes([], EVENT_CAP, "p"), 2);
  assert.equal(measureJsonBytes({}, EVENT_CAP, "p"), 2);
});

// ---------- L-A (cycle-11): undefined array elements count as null ----------

test("L-A: undefined array elements are measured as 4 bytes (JSON null)", () => {
  // JSON.stringify([undefined, undefined]) === "[null,null]" (11 bytes).
  // The old code measured 3 — a large undefined array could pass the cap
  // while materializing a much larger string downstream.
  assert.equal(utf8Len(JSON.stringify([undefined, undefined])), 11);
  assert.equal(measureJsonBytes([undefined, undefined], EVENT_CAP, "p"), 11);
  assert.equal(measureJsonBytes({ a: [undefined] }, EVENT_CAP, "p"), utf8Len(JSON.stringify({ a: [undefined] })));
});

test("L-A: large undefined array trips the cap", () => {
  const arr = new Array(5000).fill(undefined); // 5000*4 + commas + brackets > 16 KiB
  assert.throws(() => measureJsonBytes(arr, EVENT_CAP, "p"), CapExceeded);
  // and a small one still passes
  measureJsonBytes(new Array(10).fill(undefined), EVENT_CAP, "p");
});

test("L-A: undefined object values stay conservatively counted (dropped by stringify)", () => {
  // {a: undefined} stringifies to "{}" — the key is counted, never under.
  const measured = measureJsonBytes({ a: undefined }, EVENT_CAP, "p");
  assert.ok(measured >= utf8Len(JSON.stringify({ a: undefined })));
});

// ---------- L-B (cycle-11): truncateBytes ----------

test("L-B: truncateBytes keeps short strings untouched", () => {
  assert.equal(truncateBytes("hello", 4096), "hello");
  assert.equal(truncateBytes("x".repeat(4096), 4096), "x".repeat(4096));
});

test("L-B: truncateBytes caps at the byte budget", () => {
  const out = truncateBytes("x".repeat(10000), 4096);
  assert.equal(utf8Len(out), 4096);
});

test("L-B: truncateBytes never splits a UTF-8 sequence", () => {
  // "é" is 2 bytes; cutting mid-character must decode safely, not throw
  const s = "é".repeat(3000); // 6000 bytes
  const out = truncateBytes(s, 4095); // odd cut lands mid-character
  assert.ok(utf8Len(out) <= 4095, `got ${utf8Len(out)} bytes`);
  assert.doesNotThrow(() => JSON.stringify(out));
});
