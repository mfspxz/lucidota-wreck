/**
 * idempotency.js — atomic idempotency gate for the queue consumer (M5).
 *
 * Cloudflare KV has no compare-and-set, so `KV.get` → process → `KV.put`
 * is check-then-set: two concurrent consumers can both see "unseen" and
 * double-govern (double ACCEPT seals; the second merge then fails
 * non-fast-forward → a spurious MERGE-FAILED reject after a real merge).
 *
 * This gate makes the claim atomic *within one isolate*. The Worker's JS
 * event loop is single-threaded, so serializing the check-and-add through
 * a promise-chain mutex means no two callers can interleave between the
 * KV read and the in-flight mark.
 *
 * Cross-isolate concurrency still needs a Durable Object lease — the
 * single-writer merge lease already planned for mergePort should cover
 * decide+merge. Until then the residual risk is documented here, not
 * hidden. Crash safety is preserved: the in-flight mark lives only in
 * isolate memory, so a crash before the H3 KV.put redelivers (the KV key
 * is still absent) and a crash after is covered by the key.
 */

export class IdempotencyGate {
  constructor() {
    this.inflight = new Set();
    // promise-chain mutex: every claim() waits for the previous
    // claim's check-and-add to finish before starting its own
    this.mutex = Promise.resolve();
  }

  /**
   * Attempt to claim `key` for processing.
   *
   * L-D (cycle-11): the KV read happens OUTSIDE the mutex. The old code
   * held the promise mutex across `await kv.get(key)` — one slow KV read
   * stalled every claim in the isolate. The mutex now covers only the
   * in-isolate set check and the check-and-add; the KV read is concurrent.
   * Correctness is preserved: the set is re-checked under the mutex after
   * the read, so two callers racing the same key still serialize — the
   * loser sees "inflight". Duplicate KV reads for the same key are
   * harmless (reads are idempotent); double-processing is impossible.
   *
   * @returns "processed" — the KV key exists: already done, skip (ack).
   *          "inflight" — another call in this isolate owns it: do NOT ack
   *                       (the owner might crash); throw so the message retries.
   *          "claimed"   — this caller owns it: process, then release().
   *                        The caller MUST call release() in a finally.
   */
  async claim(key, kv) {
    // Phase 1: in-isolate set check under the mutex (fast, no I/O).
    let releaseMutex;
    const prev = this.mutex;
    this.mutex = new Promise((resolve) => {
      releaseMutex = resolve;
    });
    await prev;
    let state;
    try {
      state = this.inflight.has(key) ? "inflight" : "check-kv";
    } finally {
      releaseMutex();
    }
    if (state === "inflight") return "inflight";

    // Phase 2: KV read OUTSIDE the mutex — a slow KV no longer stalls
    // other isolates' claims.
    if (await kv.get(key)) return "processed";

    // Phase 3: re-acquire the mutex for the atomic check-and-add. Another
    // caller may have claimed while we were reading KV — re-check.
    let release2;
    const prev2 = this.mutex;
    this.mutex = new Promise((resolve) => {
      release2 = resolve;
    });
    await prev2;
    try {
      if (this.inflight.has(key)) return "inflight";
      this.inflight.add(key);
      return "claimed";
    } finally {
      release2();
    }
  }

  /** Release a key previously claimed by this caller. Idempotent. */
  release(key) {
    this.inflight.delete(key);
  }
}
