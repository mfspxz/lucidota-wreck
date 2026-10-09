/**
 * lease.js — single-writer merge lease (M5 residual fix, cycle-18, thread 6).
 *
 * The KV dedup gate (idempotency.js) is advisory: two isolates can both see
 * "unseen" and double-govern. The real fix is a single-writer lease over the
 * merge path — one holder at a time, fenced by a monotonic generation token
 * that every merge request must carry. Stale tokens are refused, so a slow
 * or crashed ex-holder can never merge after its lease died.
 *
 * Protocol:
 * - acquire(holder, ttlMs): takes the lease if free or expired. Returns the
 *   fencing token { generation, expiresAt }. Throws LeaseBusy if live.
 * - renew(generation, ttlMs): extends a LIVE lease held by this token.
 *   Renewing an expired lease throws StaleToken — re-acquire instead (the
 *   generation must move forward; never resurrect a dead lease).
 * - release(generation): frees the lease. Refuses (StaleToken) to release
 *   someone else's live lease. Releasing an absent/expired lease succeeds.
 * - assertHolder(generation): the merge-path gate. Call before every merge;
 *   throws StaleToken unless the token is the current live holder.
 * - All store failures throw LeaseStoreError and fail the operation:
 *   no lease = no merge. Never swallow, never default to "free".
 *
 * The store is injectable ({ get, put, del }, all async, KV-shaped);
 * default is an in-memory Map. The clock is injectable (nowMs). Mutations
 * are serialized through a promise-chain mutex so the default store is
 * race-free within one isolate — same shape as IdempotencyGate.
 *
 * DO MAPPING (production):
 * - The store: in-memory Map -> Durable Object storage. The DO's
 *   single-threaded input queue replaces _serialized: one DO instance per
 *   lease key is the atomicity domain, exactly as the in-isolate mutex is
 *   here.
 * - The clock: Date.now -> DO's Date.now (same).
 * - TTL expiry notification: not implemented (callers observe expiry
 *   lazily via StaleToken); a DO would use alarms to proactively release
 *   or notify. Lazy expiry is sufficient for fencing because assertHolder
 *   re-checks the clock on every merge.
 * - Already faithful to the DO design: the fencing-token protocol
 *   (monotonic generation, stale tokens refused), fail-closed store
 *   errors, release refusal on generation mismatch, lazy TTL expiry.
 * - What the DO adds and this module cannot: cross-isolate atomicity.
 *   Behind a shared KV store, two isolates' acquires can still interleave
 *   (the documented M5 residual). The DO eliminates that by construction.
 *
 * Intended wiring: worker.js calls `await lease.assertHolder(token)` right
 * before the merge port executes; the token is minted at acquire time when
 * the decision becomes ELIGIBLE.
 */

export class LeaseBusy extends Error {
  constructor(holder, expiresAt) {
    super(
      JSON.stringify({
        error: "lease_busy",
        holder,
        expiresAt,
        policy: "single-writer",
      }),
    );
    this.name = "LeaseBusy";
    this.holder = holder;
    this.expiresAt = expiresAt;
  }
}

export class StaleToken extends Error {
  constructor(presented, current) {
    super(
      JSON.stringify({
        error: "stale_lease_token",
        presented,
        current,
        policy: "fencing",
      }),
    );
    this.name = "StaleToken";
    this.presented = presented;
    this.current = current;
  }
}

export class LeaseStoreError extends Error {
  constructor(op, cause) {
    super(
      JSON.stringify({
        error: "lease_store_error",
        op,
        policy: "fail-closed",
      }),
    );
    this.name = "LeaseStoreError";
    this.op = op;
    this.cause = cause;
  }
}

/** Default store: in-memory Map with the async KV-shaped interface. */
export class MemoryStore {
  constructor() {
    this.map = new Map();
  }
  async get(key) {
    return this.map.has(key) ? this.map.get(key) : null;
  }
  async put(key, value) {
    this.map.set(key, value);
  }
  async del(key) {
    this.map.delete(key);
  }
}

function checkTtl(ttlMs) {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new RangeError(`lease ttl must be a positive number of ms, got ${ttlMs}`);
  }
}

export class MergeLease {
  constructor({ store = new MemoryStore(), nowMs = () => Date.now(), key = "wreck:merge-lease" } = {}) {
    this.store = store;
    this.nowMs = nowMs;
    this.key = key;
    // In-isolate serializer for mutations. In production the Durable
    // Object's input queue plays this role across isolates.
    this.mutex = Promise.resolve();
  }

  async _serialized(fn) {
    let release;
    const prev = this.mutex;
    this.mutex = new Promise((resolve) => {
      release = resolve;
    });
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  _live(rec, now) {
    return rec !== null && rec !== undefined && now < rec.expiresAt;
  }

  _currentGeneration(rec) {
    return rec && typeof rec.generation === "number" ? rec.generation : null;
  }

  /**
   * Take the lease if free or expired. Returns the fencing token
   * { generation, expiresAt } the holder must carry on every merge.
   * Throws LeaseBusy if a live lease exists.
   */
  async acquire(holder, ttlMs) {
    checkTtl(ttlMs);
    return this._serialized(async () => {
      const now = this.nowMs();
      let rec;
      try {
        rec = await this.store.get(this.key);
      } catch (cause) {
        throw new LeaseStoreError("get", cause);
      }
      if (this._live(rec, now)) {
        throw new LeaseBusy(rec.holder, rec.expiresAt);
      }
      const generation = (this._currentGeneration(rec) ?? 0) + 1;
      const next = { holder, generation, expiresAt: now + ttlMs, acquiredAt: now };
      try {
        await this.store.put(this.key, next);
      } catch (cause) {
        throw new LeaseStoreError("put", cause);
      }
      return { generation, expiresAt: next.expiresAt };
    });
  }

  /**
   * Extend a live lease held by `generation`. Throws StaleToken if the
   * lease is absent, expired, or held by another generation — an expired
   * lease is dead; re-acquire to get a new generation.
   */
  async renew(generation, ttlMs) {
    checkTtl(ttlMs);
    return this._serialized(async () => {
      const now = this.nowMs();
      let rec;
      try {
        rec = await this.store.get(this.key);
      } catch (cause) {
        throw new LeaseStoreError("get", cause);
      }
      if (!this._live(rec, now) || rec.generation !== generation) {
        throw new StaleToken(generation, this._currentGeneration(rec));
      }
      rec.expiresAt = now + ttlMs;
      try {
        await this.store.put(this.key, rec);
      } catch (cause) {
        throw new LeaseStoreError("put", cause);
      }
      return { expiresAt: rec.expiresAt };
    });
  }

  /**
   * Free the lease. Refuses (StaleToken) to release another holder's live
   * lease — a stale holder must never evict the current one. Releasing an
   * absent or expired lease succeeds (the intent "I hold nothing" is
   * already true).
   *
   * Fencing note: release writes an EXPIRED TOMBSTONE, never deletes the
   * record. Deleting would reset the generation counter, letting a later
   * acquire re-issue a generation a stale token still carries — a real
   * fencing hole. The tombstone keeps generations monotonic per key
   * forever; acquire treats it as free (it is not live).
   */
  async release(generation) {
    return this._serialized(async () => {
      const now = this.nowMs();
      let rec;
      try {
        rec = await this.store.get(this.key);
      } catch (cause) {
        throw new LeaseStoreError("get", cause);
      }
      if (rec && this._live(rec, now) && rec.generation !== generation) {
        throw new StaleToken(generation, rec.generation);
      }
      const tombstone = {
        holder: null,
        generation: this._currentGeneration(rec) ?? 0,
        expiresAt: now, // immediately expired: free for the next acquire
        releasedAt: now,
      };
      try {
        await this.store.put(this.key, tombstone);
      } catch (cause) {
        throw new LeaseStoreError("put", cause);
      }
      return true;
    });
  }

  /**
   * Merge-path gate: every merge request carries its fencing token.
   * Returns true only if `generation` is the current live holder.
   * Read-only (no mutex needed); store failures fail closed.
   */
  async assertHolder(generation) {
    const now = this.nowMs();
    let rec;
    try {
      rec = await this.store.get(this.key);
    } catch (cause) {
      throw new LeaseStoreError("get", cause);
    }
    if (!this._live(rec, now) || rec.generation !== generation) {
      throw new StaleToken(generation, this._currentGeneration(rec));
    }
    return true;
  }
}
