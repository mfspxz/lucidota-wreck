/**
 * wreck-worker: the Cloudflare-side event shell for the wreck governor.
 *
 * Flow:  cf.artifacts.repo.pushed -> Queue -> this consumer
 *        -> dedup (KV, keyed on namespace/repo/ref/before/after)
 *        -> retry-read until `after` SHA is visible via the Artifacts binding
 *        -> build ChangeView (tree diff before/after)
 *        -> wreck_decide (WASM: the Rust governor core — the ONLY decision logic)
 *        -> ACCEPT: merge via the Artifacts merge port, then wreck_complete (seal)
 *           REJECT/BLOCKED: sealed immediately, agent notified with machine reason
 *        -> receipt appended to the decision chain (D1), dashboard updated (KV/R2)
 *
 * The Worker never decides anything itself. It is IO: events in, git out.
 * All verdict logic lives in wreck-wasm (Rust), one implementation.
 */

import wasmBytes from "./wreck_wasm.wasm";

let wasm = null;
let memory = null;

async function getWasm() {
  if (wasm) return wasm;
  const mod = await WebAssembly.instantiate(wasmBytes, {});
  wasm = mod.instance.exports;
  memory = wasm.memory;
  return wasm;
}

function callWasm(fn, inputObj, outCap = 65536) {
  const input = new TextEncoder().encode(JSON.stringify(inputObj));
  const inPtr = 0; // NOTE: real impl needs an allocator export; scaffold uses fixed regions
  // ---- TODO(hardening): export wreck_alloc from the wasm module instead ----
  throw new Error("scaffold: wire the wasm allocator before deploy");
}

function dedupKey(e) {
  return `wreck:seen:${e.namespace}:${e.repo}:${e.ref}:${e.before}:${e.after}`;
}

export default {
  /**
   * Queue consumer for artifact push events.
   * env bindings: ARTIFACTS (artifacts), GOVERNOR_KV, CHAIN_D1, GOVERNOR_KEY (secret)
   */
  async queue(batch, env) {
    const w = await getWasm();
    for (const msg of batch.messages) {
      try {
        await handlePush(msg.body, env, w);
        msg.ack();
      } catch (err) {
        // at-least-once: retry later; dedup key makes reprocessing safe
        console.error("wreck: handlePush failed, will retry", err);
        msg.retry();
      }
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

async function handlePush(event, env, w) {
  // event shape: { namespace, repo, ref, before, after, commits[] }
  // baseline repo pushes are the governor's own merges — never re-govern.
  if (event.repo === "baseline") return;

  const key = dedupKey(event);
  if (await env.GOVERNOR_KV.get(key)) return; // already processed
  await env.GOVERNOR_KV.put(key, "1", { expirationTtl: 86400 });

  // retry-read: the event can arrive before the commit is readable
  const after = await waitVisible(env, event, 5);

  // build the mechanical view: tree diff before/after
  const view = await buildView(env, event, after);

  // the claim: agents submit claims with their push (commit trailer
  // `Wreck-Claim: <json>`); without one the governor still runs on the
  // measured diff, with zero declared semantics.
  const claim = claimFromCommit(event, after);

  // ---- the decision: 100% Rust, via WASM ----
  const decideOut = callWasm("wreck_decide", {
    claim,
    view,
    in_flight: await inFlightViews(env, event.namespace),
    merged: await mergedIds(env, event.namespace),
    policy: await activePolicy(env),
    key_hex: env.GOVERNOR_KEY_HEX,
    actor: "wreck-governor",
    ts: new Date().toISOString(),
  });

  if (decideOut.outcome === "decided") {
    await recordDecision(env, decideOut.decision);
    await notifyAgent(env, claim, decideOut.decision);
    return;
  }

  // ACCEPT pending: merge, then seal.
  // TODO(adapter-spec): the Artifacts merge mechanism lands here —
  // currently documented as "git push over HTTPS with the governor's
  // repo-scoped token"; the adapter researcher confirms the exact call.
  const mergeSha = await mergePort(env, event, decideOut.draft);

  const completeOut = callWasm("wreck_complete", {
    draft: decideOut.draft,
    claim: decideOut.claim,
    merge_sha: mergeSha,
    port: "artifacts",
    key_hex: env.GOVERNOR_KEY_HEX,
    actor: "wreck-governor",
    ts: new Date().toISOString(),
  });
  await recordDecision(env, completeOut.decision);
  await notifyAgent(env, claim, completeOut.decision);
}

/** Poll the binding until `after` is readable (usually immediate). */
async function waitVisible(env, event, tries) {
  const repo = env.ARTIFACTS.get(event.repo); // throws until status === "ready"
  for (let i = 0; i < tries; i++) {
    const c = await repo.readCommit(event.after); // metadata | null
    if (c) return c;
    await new Promise((r) => setTimeout(r, 500 * (i + 1)));
  }
  throw new Error(`commit ${event.after} never became visible`);
}

async function buildView(env, event, after) {
  // No server-side diff: walk both trees, compare blob hashes, diff locally.
  const repo = env.ARTIFACTS.get(event.repo);
  const oldBlobs = await treeBlobs(repo, event.before);
  const newBlobs = await treeBlobs(repo, event.after);
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
  return { change_id: event.repo, files, symbols: [], invariants: [], contracts: [], dependencies: [] };
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

function claimFromCommit(event, after) {
  // TODO: parse `Wreck-Claim:` trailer from the commit message.
  throw new Error("scaffold: claimFromCommit not yet implemented");
}

async function inFlightViews(env, namespace) {
  // TODO: KV index of proposed-but-undecided changes per namespace
  return [];
}

async function mergedIds(env, namespace) {
  // TODO: D1 query of merged change ids
  return [];
}

async function activePolicy(env) {
  // TODO: CANON rules from D1 -> { rules: [{id, forbidden_contract, reason}] }
  return { rules: [] };
}

async function mergePort(env, event, draft) {
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
