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
   * @returns "processed" — the KV key exists: already done, skip (ack).
   *          "inflight" — another call in this isolate owns it: do NOT ack
   *                       (the owner might crash); throw so the message retries.
   *          "claimed"   — this caller owns it: process, then release().
   *                        The caller MUST call release() in a finally.
   */
  async claim(key, kv) {
    let releaseMutex;
    const prev = this.mutex;
    this.mutex = new Promise((resolve) => {
      releaseMutex = resolve;
    });
    await prev;
    try {
      if (this.inflight.has(key)) return "inflight";
      if (await kv.get(key)) return "processed";
      this.inflight.add(key);
      return "claimed";
    } finally {
      releaseMutex();
    }
  }

  /** Release a key previously claimed by this caller. Idempotent. */
  release(key) {
    this.inflight.delete(key);
  }
}
