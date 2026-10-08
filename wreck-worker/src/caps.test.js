// Unit tests for caps.js — run with: node src/caps.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  CapExceeded,
  EVENT_CAP,
  WASM_INPUT_CAP,
  checkCap,
  readTextCapped,
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
