/**
 * wreck-worker: the Cloudflare-side event shell for the wreck governor.
 *
 * Flow:  cf.artifacts.repo.pushed -> Queue -> this consumer
 *        -> boundary-validate the NESTED official shape (event.js)
 *        -> baseline exclusion (the governor's own merges are never re-governed)
 *        -> dedup check (KV)
 *        -> retry-read until `after` SHA is visible via the Artifacts binding
 *        -> build ChangeView (tree diff before/after)
 *        -> wreck_decide (WASM: the Rust governor core — the ONLY decision logic)
 *        -> ACCEPT: merge via the Artifacts merge port, then wreck_complete (seal)
 *           REJECT/BLOCKED: sealed immediately, agent notified with machine reason
 *        -> dedup key written ONLY after successful processing (H3)
 *        -> receipt appended to the decision chain (D1), dashboard updated (KV/R2)
 *
 * The Worker never decides anything itself. It is IO: events in, git out.
 * All verdict logic lives in wreck-wasm (Rust), one implementation.
 *
 * Fail-closed posture (cycle-06 audit): unwired state sources THROW rather
 * than returning empty (H2); malformed events are poison, never retried (C1);
 * the authority key is installed once into WASM-static memory and never
 * crosses the JS→WASM boundary again (H1).
 */

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
import { InvalidEvent, dedupKey, parseEvent } from "./event.js";
import { IdempotencyGate } from "./idempotency.js";

// One gate per isolate: the in-flight set is isolate memory, so a crash
// loses it (safe — the H3 KV key is only written after success).
const defaultGate = new IdempotencyGate();

let wasm = null;
let memory = null;

async function getWasm() {
  if (wasm) return wasm;
  // Lazy: the .wasm module is produced by `cargo build -p wreck-wasm`;
  // importing it statically would break node-based unit tests.
  const { default: wasmBytes } = await import("./wreck_wasm.wasm");
  const mod = await WebAssembly.instantiate(wasmBytes, {});
  wasm = mod.instance.exports;
  memory = wasm.memory;
  return wasm;
}

/**
 * M6 (cycle-06 audit): per-call allocation via the WASM module's own
 * wreck_alloc/wreck_free — no fixed regions, no cross-call aliasing.
 * Buffers are freed after every call (success or failure). A null alloc
 * or a missing export fails closed: the call never proceeds.
 */
function callWasm(w, fn, inputObj, outCap = 65536) {
  const input = new TextEncoder().encode(JSON.stringify(inputObj));
  // cap before the WASM boundary: 1 MiB, reject-never-truncate
  checkCap(input.length, WASM_INPUT_CAP, `wasm ${fn} input`);
  if (!w.wreck_alloc || !w.wreck_free) {
    throw new Error("wreck: wreck_alloc/wreck_free not exported — refusing fixed-region I/O (M6)");
  }
  const inPtr = w.wreck_alloc(input.length);
  if (!inPtr) throw new Error(`wreck: wasm alloc failed for ${fn} input (${input.length} bytes)`);
  const outPtr = w.wreck_alloc(outCap);
  if (!outPtr) {
    w.wreck_free(inPtr, input.length);
    throw new Error(`wreck: wasm alloc failed for ${fn} output (${outCap} bytes)`);
  }
  try {
    // fresh view per use: memory.buffer detaches if the module grows it
    new Uint8Array(w.memory.buffer, inPtr, input.length).set(input);
    const rc = w[fn](inPtr, input.length, outPtr, outCap);
    const mem = () => new Uint8Array(w.memory.buffer);
    if (rc === -2) {
      // output buffer too small: the Rust side wrote nothing; fail closed
      // with a clear message so the caller retries with a larger outCap
      throw new Error(`wreck: ${fn} failed: output too small (${outCap} bytes) — retry with larger outCap`);
    }
    if (rc < 0) {
      // error envelope is a NUL-terminated {"error":...} (see wreck-wasm call())
      const raw = new TextDecoder().decode(mem().subarray(outPtr, outPtr + outCap));
      throw new Error(`wreck: ${fn} failed (${rc}): ${raw.split("\0")[0]}`);
    }
    return JSON.parse(new TextDecoder().decode(mem().subarray(outPtr, outPtr + rc)));
  } finally {
    w.wreck_free(inPtr, input.length);
    w.wreck_free(outPtr, outCap);
  }
}

/**
 * H1: install the authority signing key ONCE into WASM-static memory via
 * wreck_init_key. The key never crosses the JS→WASM boundary again —
 * decide/complete inputs carry no key material. Requires the M6
 * per-call allocator (wreck_alloc/wreck_free).
 */
async function initAuthorityKey(w, env) {
  const raw = env.GOVERNOR_KEY; // Uint8Array secret bytes; never logged
  if (!w.wreck_alloc || !w.wreck_init_key) {
    throw new Error("scaffold: wreck_alloc/wreck_init_key not exported yet (see M6)");
  }
  const ptr = w.wreck_alloc(raw.length);
  try {
    new Uint8Array(w.memory.buffer, ptr, raw.length).set(raw);
    const rc = w.wreck_init_key(ptr, raw.length);
    if (rc !== 0) throw new Error(`wreck_init_key failed: ${rc}`);
  } finally {
    if (w.wreck_free) w.wreck_free(ptr, raw.length);
  }
}

export default {
  /**
   * Queue consumer for artifact push events.
   * env bindings: ARTIFACTS (artifacts), GOVERNOR_KV, CHAIN_D1, GOVERNOR_KEY (secret)
   */
  async queue(batch, env) {
    const w = await getWasm();
    // H1: install the authority key once per isolate startup. Re-installing
    // zeroizes the previous key inside WASM before replacing it.
    await initAuthorityKey(w, env);
    for (const msg of batch.messages) {
      await handleMessage(msg, env, w);
    }
  },

  /** Manual trigger / health. L1 (cycle-06 audit): no unauthenticated
   * catch-all — unknown paths 404 instead of 200, so probing learns nothing
   * beyond the health endpoint's existence. */
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/v1/health") {
      return Response.json({ ok: true });
    }
    return new Response("not found", { status: 404 });
  },
};

/** One queue message: poison (CapExceeded/InvalidEvent) is acked, never retried. */
async function handleMessage(msg, env, w) {
  try {
    // L4: cap the queue message body BEFORE touching it (16 KiB,
    // reject-never-truncate). String bodies are measured directly;
    // objects are measured without materializing a second full copy.
    let body;
    if (typeof msg.body === "string") {
      checkCap(utf8Len(msg.body), EVENT_CAP, "queue message body");
      body = JSON.parse(msg.body);
    } else {
      measureJsonBytes(msg.body, EVENT_CAP, "queue message body");
      body = msg.body;
    }
    await handlePush(body, env, w);
    msg.ack();
  } catch (err) {
    if (err instanceof CapExceeded || err instanceof InvalidEvent) {
      // poison message: retry can never succeed
      console.error("wreck: poison message, acking", err.message);
      msg.ack();
    } else {
      // at-least-once: retry later; dedup key makes reprocessing safe
      console.error("wreck: handlePush failed, will retry", err);
      msg.retry();
    }
  }
}

async function handlePush(event, env, w, deps = {}) {
  const {
    decide = (o) => callWasm(w, "wreck_decide", o),
    complete = (o) => callWasm(w, "wreck_complete", o),
    merge = mergePort,
    record = recordDecision,
    notify = notifyAgent,
    // state sources are injectable so the decided path is unit-testable;
    // in production these are the fail-closed H2 stubs until wired.
    inFlight = (e, n) => inFlightViews(e, n),
    merged = (e, n) => mergedIds(e, n),
    policy = (e) => activePolicy(e),
    // M5: atomic idempotency gate (injectable for tests; the module-level
    // default is the per-isolate production gate).
    idempotency = defaultGate,
  } = deps;

  // C1: validate the nested official shape at the boundary. Throws
  // InvalidEvent (poison) on any deviation — never process a half-shape.
  const ev = parseEvent(event);

  // baseline repo pushes are the governor's own merges — never re-govern.
  if (ev.repoName === "baseline") return;

  // M5: atomic claim. "processed" → skip (ack); "inflight" → another call
  // in this isolate owns it, so do NOT ack (it might crash) — throw and
  // retry later. Cross-isolate double-claim remains possible until the
  // Durable Object merge lease lands; see idempotency.js.
  const key = dedupKey(ev);
  const claimState = await idempotency.claim(key, env.GOVERNOR_KV);
  if (claimState === "processed") return;
  if (claimState === "inflight") {
    throw new Error(`wreck: event ${key} already in flight in this isolate — retry`);
  }
  try {
    // retry-read: the event can arrive before the commit is readable
    const after = await waitVisible(env, ev, 5);

    // build the mechanical view: tree diff before/after
    const view = await buildView(env, ev, after);

    // the claim: agents submit claims with their push (commit trailer
    // `Wreck-Claim: <json>`); without one the governor still runs on the
    // measured diff, with zero declared semantics.
    const claim = claimFromCommit(ev, after);

    // ---- the decision: 100% Rust, via WASM ----
    // H1: no key_hex — the authority key lives in WASM-static memory.
    const decideOut = decide({
      claim,
      view,
      in_flight: await inFlight(env, ev.namespace),
      merged: await merged(env, ev.namespace),
      policy: await policy(env),
      actor: "wreck-governor",
      ts: new Date().toISOString(),
    });

    if (decideOut.outcome === "decided") {
      await record(env, decideOut.decision);
      await notify(env, claim, decideOut.decision);
    } else {
      // M5 (cycle-06 audit): the KV dedup gate is check-then-set — advisory
      // only, because KV has no CAS (the Durable Object single-writer lease
      // is the real fix, still planned). A duplicate consumer can reach this
      // point, so re-check the merged set immediately before merging: a
      // double-merge is impossible. Worst case is a wasted duplicate decide,
      // never a spurious MERGE-FAILED after a real merge.
      const mergedNow = await merged(env, ev.namespace);
      if (!mergedNow.includes(ev.repoName)) {
        // ACCEPT pending: merge, then seal.
        const mergeSha = await merge(env, ev, decideOut.draft);
        const completeOut = complete({
          draft: decideOut.draft,
          claim: decideOut.claim,
          merge_sha: mergeSha,
          port: "artifacts",
          // M3: the persisted chain head (D1). Null until recordDecision is
          // wired — the WASM core then self-attests (documented gap).
          expected_parent_seal: null,
          actor: "wreck-governor",
          ts: new Date().toISOString(),
        });
        await record(env, completeOut.decision);
        await notify(env, claim, completeOut.decision);
      }
      // else: another consumer already governed and merged this change —
      // idempotent no-op; the dedup key is still written below.
    }

    // H3: the dedup key is written ONLY after successful processing. A crash
    // before this line redelivers the event (safe: reprocessing is
    // idempotent); a crash after is covered by the key. Writing it earlier
    // would silently drop the change on crash.
    await env.GOVERNOR_KV.put(key, "1", { expirationTtl: 86400 });
  } finally {
    // M5: always release the in-isolate claim — success (KV key now
    // covers it), failure, or throw (H2). A leaked claim would wedge
    // every redelivery of this event into "inflight" forever.
    idempotency.release(key);
  }
}

/** Poll the binding until `after` is readable (usually immediate).
 *
 * M-C (cycle-11): bounded, then poison. The old shape threw a generic
 * Error here, so a permanently invisible commit burned ~7.5s per
 * redelivery FOREVER (each retry re-ran the full sleep loop). Now the
 * attempts are bounded to one 7.5s window and a never-visible commit is
 * InvalidEvent — acked, never retried. Tradeoff, documented: a commit
 * that becomes visible later than ~7.5s after its push event is dropped;
 * the retry-read window covers normal propagation, and the alternative
 * is unbounded isolate burn.
 */
async function waitVisible(env, ev, tries, sleepMs = (ms) => new Promise((r) => setTimeout(r, ms))) {
  const repo = env.ARTIFACTS.get(ev.repoName); // throws until status === "ready"
  for (let i = 0; i < tries; i++) {
    const c = await repo.readCommit(ev.after); // metadata | null
    if (c) return c;
    await sleepMs(500 * (i + 1));
  }
  throw new InvalidEvent(`commit ${ev.after} never became visible after ${tries} attempts`);
}

async function buildView(env, ev, after) {
  // No server-side diff: walk both trees, compare blob hashes, diff locally.
  const repo = env.ARTIFACTS.get(ev.repoName);
  const oldBlobs = await treeBlobs(repo, ev.before);
  const newBlobs = await treeBlobs(repo, ev.after);
  const files = [];
  // Cycle-19 (observation-log pattern): emit one Blob provenance entry
  // per blob whose bytes were actually read — old and new sides each get
  // an entry, absent sides get none. The hash binds the exact bytes the
  // diff consumed (UTF-8 of the decoded text); the governor consumes
  // these entries verbatim into the decision's provenance.
  const blobProvenance = [];
  const paths = [...new Set([...oldBlobs.keys(), ...newBlobs.keys()])].sort();
  for (const path of paths) {
    const oh = oldBlobs.get(path);
    const nh = newBlobs.get(path);
    if (oh === nh) continue;
    // M-B: blob reads are byte-capped (32 MiB) — the old code read every
    // changed blob fully into isolate memory.
    const oldText = oh ? await readBlobCapped(repo, oh) : "";
    const newText = nh ? await readBlobCapped(repo, nh) : "";
    if (oh) blobProvenance.push({ kind: "blob", id: path, hash: await sha256Hex(oldText) });
    if (nh) blobProvenance.push({ kind: "blob", id: path, hash: await sha256Hex(newText) });
    files.push({ path, ...diffRanges(oldText, newText) });
  }
  return { change_id: ev.repoName, files, symbols: [], invariants: [], contracts: [], dependencies: [], blob_provenance: blobProvenance };
}

/** Hex sha256 of a string's UTF-8 bytes — the bytes the diff consumed. */
async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Recursive tree walk via readTree (immediate children only).
 *
 * M-B (cycle-11): capped like the Rust walk_tree (M2: depth 64, 100k
 * entries). The Worker path had no cap — a hostile tree could OOM the
 * isolate. Fail-closed: over-limit trees throw, never partially walk.
 */
const TREE_MAX_DEPTH = 64;
const TREE_MAX_ENTRIES = 100_000;
/** Per-blob byte cap — same 32 MiB as the Rust read_capped (L3). */
const BLOB_MAX_BYTES = 32 * 1024 * 1024;

async function treeBlobs(repo, hash, prefix = "", out = new Map(), depth = 0) {
  if (depth > TREE_MAX_DEPTH) {
    throw new Error(`wreck: tree depth exceeds ${TREE_MAX_DEPTH}`);
  }
  if (out.size > TREE_MAX_ENTRIES) {
    throw new Error(`wreck: tree entries exceed ${TREE_MAX_ENTRIES}`);
  }
  const entries = (await repo.readTree(hash)) || [];
  for (const e of entries) {
    const path = prefix ? `${prefix}/${e.path}` : e.path;
    if (e.type === "tree") await treeBlobs(repo, e.hash, path, out, depth + 1);
    else {
      out.set(path, e.hash);
      if (out.size > TREE_MAX_ENTRIES) {
        throw new Error(`wreck: tree entries exceed ${TREE_MAX_ENTRIES}`);
      }
    }
  }
  return out;
}

/**
 * Read one blob with a byte cap (M-B). Prefers streaming through
 * readTextCapped when the binding returns a stream-capable Response;
 * falls back to a measured .text() for non-Response shapes (test
 * doubles). The fallback materializes the blob — acceptable only
 * outside production, where readBlob returns a real Response.
 */
async function readBlobCapped(repo, hash) {
  const resp = await repo.readBlob(hash);
  if (resp && resp.body && typeof resp.body.getReader === "function") {
    return readTextCapped(resp.body, BLOB_MAX_BYTES, `blob ${hash}`);
  }
  const text = await resp.text();
  checkCap(utf8Len(text), BLOB_MAX_BYTES, `blob ${hash}`);
  return text;
}

/** Minimal -U0 hunk parser (mirrors the Rust parse_unified_zero). */
function diffRanges(oldText, newText) {
  // TODO: implement or ship a tiny LCS; the Rust LocalGit::diff_view is the
  // reference. For the scaffold, call out to a diff helper.
  return { added: [], removed: [], _todo: "line ranges" };
}

/**
 * M4 (cycle-06 audit): the Wreck-Claim trailer is agent-controlled input.
 * Only a whitelist of semantic fields is honored; identity fields are
 * ALWAYS server-derived and can never be overridden by the trailer:
 *   change_id <- repo name (charset-validated at the event boundary)
 *   agent_id  <- "repo:<repoName>" — the repo was minted by the governor
 *                for this task. The git author.name is unauthenticated
 *                (adapter spec: never use for authorization) and a
 *                trailer agent_id is self-asserted. Attribution to a real
 *                agent identity requires the repo→agent lease map (TODO).
 * Each whitelisted field is type-checked; any violation discards the
 * whole trailer (the measured diff is still governed, with zero
 * declared semantics — the documented fallback).
 */
const TRAILER_ALLOWLIST = ["intent", "scope", "claims", "evidence", "dependencies"];
/**
 * L-B (cycle-11): the commit-message first line is agent-controlled free
 * text embedded in the claim → decide input. Cap it at 4 KiB (truncate,
 * never reject — the measured diff is the real decision input; the
 * intent is a summary). The WASM 1 MiB cap is the backstop, not the policy.
 */
const INTENT_CAP = 4096;

function claimFromCommit(ev, after) {
  // The claim rides the push: parse the `Wreck-Claim:` trailer from the
  // commit message (present in the push event's commits[] — zero extra reads).
  // The event's `after` SHA stays authoritative for the head; the trailer
  // carries the semantic proposal (intent/scope/claims/evidence).
  // Without a trailer the governor still runs on the measured diff,
  // with zero declared semantics.
  const msg = (after.message || "");
  const line = msg.split("\n").find((l) => l.startsWith("Wreck-Claim:"));
  // cap the claim trailer before parsing: 16 KiB, reject-never-truncate
  if (line) checkCap(utf8Len(line), EVENT_CAP, "Wreck-Claim trailer");
  const base = {
    change_id: ev.repoName,
    agent_id: `repo:${ev.repoName}`,
    task_id: ev.repoName,
    base: ev.before,
    head: ev.after,
    intent: truncateBytes(msg.split("\n")[0] || "", INTENT_CAP),
    scope: [],
    claims: [],
    evidence: [],
    dependencies: [],
    status: "PROPOSED",
  };
  if (!line) return base;
  let claimed;
  try {
    claimed = JSON.parse(line.slice("Wreck-Claim:".length).trim());
  } catch {
    return base;
  }
  if (!claimed || typeof claimed !== "object" || Array.isArray(claimed)) return base;
  const picked = {};
  if ("intent" in claimed) {
    if (typeof claimed.intent !== "string") return base; // type violation: drop trailer
    picked.intent = truncateBytes(claimed.intent, INTENT_CAP); // L-B: same cap as the subject line
  }
  for (const f of ["scope", "claims", "evidence", "dependencies"]) {
    if (f in claimed) {
      if (!Array.isArray(claimed[f])) return base; // type violation: drop trailer
      picked[f] = claimed[f];
    }
  }
  // identity fields stay server-derived: anything the trailer smuggled in
  // (change_id, agent_id, task_id, base, head, status) is ignored.
  return { ...base, ...picked };
}

async function inFlightViews(env, namespace) {
  // H2 (cycle-06 audit): fail-closed default-deny. Until the KV in-flight
  // index is wired, deciding with an empty list would ACCEPT every
  // well-formed change. Throwing retries the event instead.
  throw new Error("wreck: inFlightViews unwired — refusing to decide without in-flight state");
}

async function mergedIds(env, namespace) {
  // H2: same as inFlightViews — an empty merged set breaks the dependency
  // gate, so this must throw until the D1 query is wired.
  throw new Error("wreck: mergedIds unwired — refusing to decide without merged state");
}

async function activePolicy(env) {
  // H2: same — an empty policy ACCEPTs everything. Throw until the CANON
  // rules are loaded from D1.
  throw new Error("wreck: activePolicy unwired — refusing to decide without policy");
}

async function mergePort(env, ev, draft) {
  // Single-writer merge onto baseline main.
  // Production shape: a Durable Object lease around this section —
  // never parallel pushes to the shared ref (failed pushes grow
  // quadratically with contending agents).
  //
  // Mechanism (no write path in the binding or REST — all mutations are
  // git pushes): the Worker shells nothing, so the merge is a git
  // smart-HTTP push sequence via fetch() against the repo's git remote,
  // authenticated with the governor's repo-scoped token:
  //   remote = `https://${accountId}.artifacts.cloudflare.net/git/${namespace}/baseline.git`
  //   header = `Authorization: Bearer ${governorTokenSecret}`
  // (token secret = art_v1_... part before `?expires=`).
  // The minimal honest v1: fetch baseline tip, create the merge commit
  // client-side (git merge --no-ff semantics over the two trees), push.
  // TODO(live-verify): prove the smart-HTTP push sequence against a real
  // Artifacts repo once Workers Paid lands; fall back to a merge-service
  // container if the Worker sandbox blocks it.
  throw new Error("scaffold: mergePort not yet implemented");
}

async function recordDecision(env, decision) {
  // TODO: append sealed receipt to CHAIN_D1, verify parent seal matches head
}

async function notifyAgent(env, claim, decision) {
  // TODO: machine-readable verdict back to the agent (queue / webhook / PR comment)
}

// Named exports for unit tests (node --test). The default export above is
// the Worker entrypoint.
export { handlePush, handleMessage, claimFromCommit, treeBlobs, readBlobCapped, buildView, waitVisible, inFlightViews, mergedIds, activePolicy, initAuthorityKey, callWasm };
