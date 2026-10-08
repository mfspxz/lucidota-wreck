// Unit tests for worker.js event handling — run with: node --test src/worker.test.js
// Covers C1 (nested official event shape), H2 (fail-closed stubs),
// H3 (dedup-after-success), H1 (no key_hex in WASM inputs).
import test from "node:test";
import assert from "node:assert/strict";
import { InvalidEvent, dedupKey, parseEvent } from "./event.js";
import {
  activePolicy,
  claimFromCommit,
  handlePush,
  inFlightViews,
  mergedIds,
} from "./worker.js";

// The official cf.artifacts.repo.pushed shape (nested), per
// wreck-adapters/src/artifacts.rs PushedEvent — the reference shape.
function officialEvent(repoName = "task-0042") {
  return {
    type: "cf.artifacts.repo.pushed",
    source: { type: "artifacts.repo", namespace: "wreck", repoName },
    payload: {
      ref: "refs/heads/main",
      before: "a".repeat(40),
      after: "b".repeat(40),
      commits: [],
      totalCommitsCount: 1,
      commitsTruncated: false,
    },
    metadata: { accountId: "aid", eventSubscriptionId: "es", eventSchemaVersion: 1, eventTimestamp: "t" },
  };
}

function mockEnv(order) {
  const kv = new Map();
  const calls = { get: [], put: [] };
  return {
    calls,
    GOVERNOR_KV: {
      async get(k) { calls.get.push(k); return kv.get(k) ?? null; },
      async put(k, v, opts) { calls.put.push(k); order.push("kv.put"); kv.set(k, v); },
    },
    ARTIFACTS: {
      get(repoName) {
        assert.ok(repoName && !repoName.includes("undefined"), `bad repoName: ${repoName}`);
        return {
          async readCommit(sha) {
            assert.ok(sha && !sha.includes("undefined"), `bad sha: ${sha}`);
            return { message: "do it", author: { name: "agent-x" } };
          },
          async readTree() { return []; },
          async readBlob() { throw new Error("no blobs in this test"); },
        };
      },
    },
  };
}

// ---------- C1: nested official shape ----------

test("C1: dedupKey on the official nested shape has no undefined", () => {
  const ev = parseEvent(officialEvent());
  const key = dedupKey(ev);
  assert.ok(!key.includes("undefined"), `key: ${key}`);
  assert.equal(
    key,
    `wreck:seen:wreck:task-0042:refs/heads/main:${"a".repeat(40)}:${"b".repeat(40)}`,
  );
});

test("C1: flat legacy-shaped event is InvalidEvent (poison)", () => {
  // the OLD worker.js read e.namespace/e.repo/e.before directly — that
  // shape must now be rejected at the boundary, not silently mis-parsed
  const flat = { namespace: "wreck", repo: "task-0042", ref: "refs/heads/main", before: "a", after: "b" };
  assert.throws(() => parseEvent(flat), InvalidEvent);
});

test("C1: missing payload fields are InvalidEvent", () => {
  for (const bad of [
    { source: { namespace: "w", repoName: "r" } },                       // no payload
    { payload: { ref: "x", before: "y", after: "z" } },                  // no source
    { source: { namespace: "", repoName: "r" }, payload: { ref: "x", before: "y", after: "z" } },
    { source: { namespace: "w", repoName: "r" }, payload: { ref: "x", before: "y", after: "" } },
    null,
    "not-an-object",
  ]) {
    assert.throws(() => parseEvent(bad), InvalidEvent, `input: ${JSON.stringify(bad)}`);
  }
});

test("C1: baseline exclusion fires before any KV I/O", async () => {
  const order = [];
  const env = mockEnv(order);
  await handlePush(officialEvent("baseline"), env, null, {
    decide: () => { throw new Error("decide must not run for baseline"); },
  });
  assert.equal(env.calls.get.length, 0, "KV.get must not be touched for baseline");
  assert.equal(env.calls.put.length, 0, "KV.put must not be touched for baseline");
  assert.deepEqual(order, []);
});

test("C1: claimFromCommit uses normalized nested fields", () => {
  const ev = parseEvent(officialEvent("task-9"));
  const claim = claimFromCommit(ev, { message: "do it", author: { name: "agent-x" } });
  assert.equal(claim.change_id, "task-9");
  assert.equal(claim.base, "a".repeat(40));
  assert.equal(claim.head, "b".repeat(40));
  assert.ok(!claim.change_id.includes("undefined"));
});

// ---------- M4: trailer whitelist + server-derived identity ----------

test("M4: trailer cannot override identity fields", () => {
  const ev = parseEvent(officialEvent("task-9"));
  const trailer = {
    agent_id: "mallory",
    change_id: "../../evil",
    task_id: "t2",
    status: "MERGED",
    intent: "legit intent",
    scope: ["src/a.rs"],
  };
  const after = {
    message: `do it\n\nWreck-Claim: ${JSON.stringify(trailer)}`,
    author: { name: "mallory" },
  };
  const claim = claimFromCommit(ev, after);
  // identity is ALWAYS server-derived
  assert.equal(claim.change_id, "task-9");
  assert.equal(claim.agent_id, "repo:task-9");
  assert.equal(claim.task_id, "task-9");
  assert.equal(claim.status, "PROPOSED");
  assert.equal(claim.base, "a".repeat(40));
  assert.equal(claim.head, "b".repeat(40));
  // whitelisted semantic fields ARE honored
  assert.equal(claim.intent, "legit intent");
  assert.deepEqual(claim.scope, ["src/a.rs"]);
});

test("M4: author.name is never used as identity", () => {
  const ev = parseEvent(officialEvent("task-9"));
  const claim = claimFromCommit(ev, { message: "do it", author: { name: "mallory" } });
  assert.equal(claim.agent_id, "repo:task-9");
});

test("M4: mistyped trailer fields discard the whole trailer", () => {
  const ev = parseEvent(officialEvent("task-9"));
  for (const bad of [{ intent: 42 }, { scope: "not-an-array" }, { claims: { id: "x" } }, ["array"]]) {
    const after = {
      message: `do it\n\nWreck-Claim: ${JSON.stringify(bad)}`,
      author: {},
    };
    const claim = claimFromCommit(ev, after);
    assert.deepEqual(claim.scope, [], `trailer must be dropped: ${JSON.stringify(bad)}`);
    assert.equal(claim.intent, "do it", `intent falls back to subject: ${JSON.stringify(bad)}`);
  }
});

test("M4: repoName failing the change_id charset is InvalidEvent", () => {
  const ev = {
    type: "x",
    source: { type: "artifacts.repo", namespace: "wreck", repoName: "../../evil" },
    payload: { ref: "r", before: "a", after: "b" },
  };
  assert.throws(() => parseEvent(ev), InvalidEvent);
});

// ---------- M5: pre-merge re-check ----------

test("M5: duplicate delivery after a completed merge never re-merges", async () => {
  let merges = 0;
  const depsFor = (mergedList) => ({
    inFlight: async () => [],
    merged: async () => mergedList,
    policy: async () => ({ rules: [] }),
    decide: () => ({ outcome: "accept_pending", draft: { change_id: "task-7" }, claim: {} }),
    merge: async () => { merges++; return "f".repeat(40); },
    complete: () => ({ decision: { verdict: "Accept" } }),
    record: async () => {},
    notify: async () => {},
  });
  // first delivery: not yet merged -> merge runs once
  await handlePush(officialEvent("task-7"), mockEnv([]), null, depsFor([]));
  assert.equal(merges, 1);
  // second delivery: KV key "lost" (fresh env, simulating the check-then-set
  // race), but the merged set now contains the change -> no second merge
  await handlePush(officialEvent("task-7"), mockEnv([]), null, depsFor(["task-7"]));
  assert.equal(merges, 1, "the duplicate delivery must not re-merge");
});

// ---------- H2: fail-closed stubs ----------

test("H2: inFlightViews/mergedIds/activePolicy throw fail-closed", async () => {
  for (const [name, fn] of [["inFlightViews", inFlightViews], ["mergedIds", mergedIds], ["activePolicy", activePolicy]]) {
    await assert.rejects(fn({}, "wreck"), /unwired/, `${name} must throw`);
  }
});

// ---------- H3: dedup written only after success ----------

test("H3: KV.put happens after recordDecision, never before", async () => {
  const order = [];
  const env = mockEnv(order);
  const decision = { verdict: "Accept" };
  await handlePush(officialEvent("task-7"), env, null, {
    inFlight: async () => [],
    merged: async () => [],
    policy: async () => ({ rules: [] }),
    decide: (input) => {
      order.push("decide");
      // H1: no key material in the WASM input
      assert.ok(!("key_hex" in input), "key_hex must not cross the JS→WASM boundary");
      return { outcome: "decided", decision };
    },
    record: async () => { order.push("record"); },
    notify: async () => { order.push("notify"); },
  });
  assert.deepEqual(order, ["decide", "record", "notify", "kv.put"]);
  assert.equal(env.calls.put.length, 1);
  assert.ok(!env.calls.put[0].includes("undefined"), `put key: ${env.calls.put[0]}`);
});

test("H3: failed processing never writes the dedup key (redelivery safe)", async () => {
  const order = [];
  const env = mockEnv(order);
  await assert.rejects(
    handlePush(officialEvent("task-8"), env, null, {
      // no state-source overrides: the real H2 stubs throw here, which is
      // exactly the path under test — processing fails, so no dedup key
      // may be written.
    }),
    /unwired/,
  );
  assert.equal(env.calls.put.length, 0, "KV.put must not happen on failure");
});
