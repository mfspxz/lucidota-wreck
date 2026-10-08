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
  utf8Len,
} from "./caps.js";
import { InvalidEvent, dedupKey, parseEvent } from "./event.js";

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

function callWasm(fn, inputObj, outCap = 65536) {
  const input = new TextEncoder().encode(JSON.stringify(inputObj));
  // cap before the WASM boundary: 1 MiB, reject-never-truncate
  checkCap(input.length, WASM_INPUT_CAP, `wasm ${fn} input`);
  const inPtr = 0; // NOTE: real impl needs an allocator export; scaffold uses fixed regions
  // ---- TODO(hardening): export wreck_alloc from the wasm module instead ----
  throw new Error("scaffold: wire the wasm allocator before deploy");
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

  /** Manual trigger / health */
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/v1/health") {
      return Response.json({ ok: true, service: "wreck-governor", mode: "scaffold" });
    }
    return new Response("wreck governor scaffold", { status: 200 });
  },
};

/** One queue message: poison (CapExceeded/InvalidEvent) is acked, never retried. */
async function handleMessage(msg, env, w) {
  try {
    // cap the queue message body before touching it: 16 KiB, reject-never-truncate
    checkCap(utf8Len(JSON.stringify(msg.body)), EVENT_CAP, "queue message body");
    await handlePush(msg.body, env, w);
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
    decide = (o) => callWasm("wreck_decide", o),
    complete = (o) => callWasm("wreck_complete", o),
    merge = mergePort,
    record = recordDecision,
    notify = notifyAgent,
    // state sources are injectable so the decided path is unit-testable;
    // in production these are the fail-closed H2 stubs until wired.
    inFlight = (e, n) => inFlightViews(e, n),
    merged = (e, n) => mergedIds(e, n),
    policy = (e) => activePolicy(e),
  } = deps;

  // C1: validate the nested official shape at the boundary. Throws
  // InvalidEvent (poison) on any deviation — never process a half-shape.
  const ev = parseEvent(event);

  // baseline repo pushes are the governor's own merges — never re-govern.
  if (ev.repoName === "baseline") return;

  const key = dedupKey(ev);
  if (await env.GOVERNOR_KV.get(key)) return; // already processed

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
    // ACCEPT pending: merge, then seal.
    const mergeSha = await merge(env, ev, decideOut.draft);
    const completeOut = complete({
      draft: decideOut.draft,
      claim: decideOut.claim,
      merge_sha: mergeSha,
      port: "artifacts",
      actor: "wreck-governor",
      ts: new Date().toISOString(),
    });
    await record(env, completeOut.decision);
    await notify(env, claim, completeOut.decision);
  }

  // H3: the dedup key is written ONLY after successful processing. A crash
  // before this line redelivers the event (safe: reprocessing is
  // idempotent); a crash after is covered by the key. Writing it earlier
  // would silently drop the change on crash.
  await env.GOVERNOR_KV.put(key, "1", { expirationTtl: 86400 });
}

/** Poll the binding until `after` is readable (usually immediate). */
async function waitVisible(env, ev, tries) {
  const repo = env.ARTIFACTS.get(ev.repoName); // throws until status === "ready"
  for (let i = 0; i < tries; i++) {
    const c = await repo.readCommit(ev.after); // metadata | null
    if (c) return c;
    await new Promise((r) => setTimeout(r, 500 * (i + 1)));
  }
  throw new Error(`commit ${ev.after} never became visible`);
}

async function buildView(env, ev, after) {
  // No server-side diff: walk both trees, compare blob hashes, diff locally.
  const repo = env.ARTIFACTS.get(ev.repoName);
  const oldBlobs = await treeBlobs(repo, ev.before);
  const newBlobs = await treeBlobs(repo, ev.after);
  const files = [];
  const paths = [...new Set([...oldBlobs.keys(), ...newBlobs.keys()])].sort();
  for (const path of paths) {
    const oh = oldBlobs.get(path);
    const nh = newBlobs.get(path);
    if (oh === nh) continue;
    const oldText = oh ? await (await repo.readBlob(oh)).text() : "";
    const newText = nh ? await (await repo.readBlob(nh)).text() : "";
    files.push({ path, ...diffRanges(oldText, newText) });
  }
  return { change_id: ev.repoName, files, symbols: [], invariants: [], contracts: [], dependencies: [] };
}

/** Recursive tree walk via readTree (immediate children only). */
async function treeBlobs(repo, hash, prefix = "", out = new Map()) {
  const entries = (await repo.readTree(hash)) || [];
  for (const e of entries) {
    const path = prefix ? `${prefix}/${e.path}` : e.path;
    if (e.type === "tree") await treeBlobs(repo, e.hash, path, out);
    else out.set(path, e.hash);
  }
  return out;
}

/** Minimal -U0 hunk parser (mirrors the Rust parse_unified_zero). */
function diffRanges(oldText, newText) {
  // TODO: implement or ship a tiny LCS; the Rust LocalGit::diff_view is the
  // reference. For the scaffold, call out to a diff helper.
  return { added: [], removed: [], _todo: "line ranges" };
}

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
    agent_id: (after.author && after.author.name) || "unknown",
    task_id: "unknown",
    base: ev.before,
    head: ev.after,
    intent: msg.split("\n")[0] || "",
    scope: [],
    claims: [],
    evidence: [],
    dependencies: [],
    status: "PROPOSED",
  };
  if (!line) return base;
  try {
    const claimed = JSON.parse(line.slice("Wreck-Claim:".length).trim());
    return { ...base, ...claimed, base: ev.before, head: ev.after, status: "PROPOSED" };
  } catch {
    return base;
  }
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
export { handlePush, handleMessage, claimFromCommit, inFlightViews, mergedIds, activePolicy, initAuthorityKey };
