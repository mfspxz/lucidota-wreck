// Unit tests for lease.js — run with: node src/lease.test.js
import test from "node:test";
import assert from "node:assert/strict";
import {
  LeaseBusy,
  LeaseStoreError,
  MemoryStore,
  MergeLease,
  StaleToken,
} from "./lease.js";

/** Manual clock: deterministic nowMs + advance. */
function manualClock(start = 1_000_000) {
  let now = start;
  return {
    nowMs: () => now,
    advance: (ms) => {
      now += ms;
    },
  };
}

function makeLease(clock, store) {
  return new MergeLease({ store: store ?? new MemoryStore(), nowMs: clock.nowMs });
}

test("acquire returns generation 1 with expiry", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const tok = await lease.acquire("worker-a", 60_000);
  assert.equal(tok.generation, 1);
  assert.equal(tok.expiresAt, clock.nowMs() + 60_000);
});

test("second acquire while held throws LeaseBusy with machine-readable body", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  await lease.acquire("worker-a", 60_000);
  await assert.rejects(lease.acquire("worker-b", 60_000), LeaseBusy);
  try {
    await lease.acquire("worker-b", 60_000);
    assert.fail("should have thrown");
  } catch (err) {
    assert.equal(err.name, "LeaseBusy");
    const body = JSON.parse(err.message);
    assert.equal(body.error, "lease_busy");
    assert.equal(body.holder, "worker-a");
  }
});

test("ttl must be positive", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  await assert.rejects(lease.acquire("w", 0), RangeError);
  await assert.rejects(lease.acquire("w", -5), RangeError);
  const tok = await lease.acquire("w", 1000);
  await assert.rejects(lease.renew(tok.generation, 0), RangeError);
});

test("fencing: stale token refused after re-acquire", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const a = await lease.acquire("worker-a", 1000);
  clock.advance(2000); // A's lease expires
  const b = await lease.acquire("worker-b", 1000);
  assert.equal(b.generation, 2); // generation moves forward, never reused
  await assert.rejects(lease.assertHolder(a.generation), StaleToken);
  assert.equal(await lease.assertHolder(b.generation), true);
});

test("ttl expiry refuses holder", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const tok = await lease.acquire("worker-a", 1000);
  clock.advance(1001);
  await assert.rejects(lease.assertHolder(tok.generation), StaleToken);
  await assert.rejects(lease.renew(tok.generation, 1000), StaleToken);
});

test("renewal extends a live lease", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const tok = await lease.acquire("worker-a", 1000);
  clock.advance(800);
  const r = await lease.renew(tok.generation, 1000);
  assert.equal(r.expiresAt, clock.nowMs() + 1000);
  clock.advance(500); // past the ORIGINAL expiry
  assert.equal(await lease.assertHolder(tok.generation), true);
});

test("renew with wrong generation throws StaleToken", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  await lease.acquire("worker-a", 1000);
  await assert.rejects(lease.renew(999, 1000), StaleToken);
});

test("release frees the lease; old token goes stale", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const a = await lease.acquire("worker-a", 60_000);
  assert.equal(await lease.release(a.generation), true);
  const b = await lease.acquire("worker-b", 60_000);
  assert.equal(b.generation, 2);
  await assert.rejects(lease.assertHolder(a.generation), StaleToken);
  assert.equal(await lease.assertHolder(b.generation), true);
});

test("release refuses to evict another holder's live lease", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const tok = await lease.acquire("worker-a", 60_000);
  await assert.rejects(lease.release(999), StaleToken);
  // the real holder is untouched
  assert.equal(await lease.assertHolder(tok.generation), true);
});

test("release of expired lease succeeds and leaves an expired tombstone", async () => {
  const clock = manualClock();
  const store = new MemoryStore();
  const lease = makeLease(clock, store);
  const tok = await lease.acquire("worker-a", 1000);
  clock.advance(2000);
  assert.equal(await lease.release(tok.generation), true);
  const rec = await store.get("wreck:merge-lease");
  assert.ok(rec, "tombstone keeps the generation counter monotonic");
  assert.equal(rec.generation, tok.generation);
  assert.ok(rec.expiresAt <= clock.nowMs(), "tombstone is immediately expired");
  // the next acquire is free to take it, with a fresh generation
  const next = await lease.acquire("worker-b", 1000);
  assert.equal(next.generation, tok.generation + 1);
});

test("fail-closed: store get failure blocks acquire and assertHolder", async () => {
  const clock = manualClock();
  const bad = { get: async () => { throw new Error("kv down"); }, put: async () => {}, del: async () => {} };
  const lease = makeLease(clock, bad);
  await assert.rejects(lease.acquire("w", 1000), LeaseStoreError);
  await assert.rejects(lease.assertHolder(1), LeaseStoreError);
});

test("fail-closed: store put failure blocks acquire", async () => {
  const clock = manualClock();
  const bad = { get: async () => null, put: async () => { throw new Error("kv down"); }, del: async () => {} };
  const lease = makeLease(clock, bad);
  await assert.rejects(lease.acquire("w", 1000), LeaseStoreError);
});

test("concurrent acquirers: exactly one holder", async () => {
  const clock = manualClock();
  const lease = makeLease(clock);
  const attempts = Array.from({ length: 8 }, (_, i) => lease.acquire(`worker-${i}`, 60_000));
  const results = await Promise.allSettled(attempts);
  const won = results.filter((r) => r.status === "fulfilled");
  const lost = results.filter((r) => r.status === "rejected");
  assert.equal(won.length, 1);
  assert.equal(lost.length, 7);
  for (const l of lost) assert.ok(l.reason instanceof LeaseBusy);
  assert.equal(await lease.assertHolder(won[0].value.generation), true);
});

test("injected store is used", async () => {
  const clock = manualClock();
  const calls = [];
  const store = {
    get: async (k) => { calls.push(["get", k]); return null; },
    put: async (k, v) => { calls.push(["put", k, v.holder]); },
    del: async (k) => { calls.push(["del", k]); },
  };
  const lease = makeLease(clock, store);
  await lease.acquire("worker-a", 1000);
  assert.deepEqual(calls[0], ["get", "wreck:merge-lease"]);
  assert.deepEqual(calls[1], ["put", "wreck:merge-lease", "worker-a"]);
});

test("custom lease key is honored", async () => {
  const clock = manualClock();
  const store = new MemoryStore();
  const lease = new MergeLease({ store, nowMs: clock.nowMs, key: "wreck:merge-lease:repo-x" });
  await lease.acquire("worker-a", 1000);
  assert.ok(await store.get("wreck:merge-lease:repo-x"));
  assert.equal(await store.get("wreck:merge-lease"), null);
});
