/**
 * event.js — push-event boundary validation (C1, cycle-06 audit).
 *
 * The official `cf.artifacts.repo.pushed` shape is NESTED:
 *   source.{namespace, repoName} + payload.{ref, before, after}
 * (see wreck-adapters/src/artifacts.rs PushedEvent, the reference shape).
 * Everything downstream works on the normalized flat record returned by
 * parseEvent. Anything that fails validation throws InvalidEvent — poison,
 * never retried.
 */

/** The event failed boundary shape validation: ack, log, never retry. */
export class InvalidEvent extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidEvent";
  }
}

/**
 * Validate the official nested push-event shape at the boundary.
 * Returns a normalized flat record; throws InvalidEvent on any deviation
 * (missing source/payload, non-string or empty fields).
 */
export function parseEvent(event) {
  const fail = (why) => {
    throw new InvalidEvent(`wreck: invalid push event: ${why}`);
  };
  if (!event || typeof event !== "object") fail("not an object");
  const src = event.source;
  const pay = event.payload;
  if (!src || typeof src !== "object") fail("missing source");
  if (!pay || typeof pay !== "object") fail("missing payload");
  for (const f of ["namespace", "repoName"]) {
    if (typeof src[f] !== "string" || src[f].length === 0) {
      fail(`source.${f} missing or empty`);
    }
  }
  for (const f of ["ref", "before", "after"]) {
    if (typeof pay[f] !== "string" || pay[f].length === 0) {
      fail(`payload.${f} missing or empty`);
    }
  }
  return {
    namespace: src.namespace,
    repoName: src.repoName,
    ref: pay.ref,
    before: pay.before,
    after: pay.after,
  };
}

/**
 * Idempotency key over the normalized official shape:
 * (namespace, repo, ref, before, after). A key containing "undefined"
 * means the boundary was bypassed — treat as a bug, not data.
 */
export function dedupKey(ev) {
  return `wreck:seen:${ev.namespace}:${ev.repoName}:${ev.ref}:${ev.before}:${ev.after}`;
}
