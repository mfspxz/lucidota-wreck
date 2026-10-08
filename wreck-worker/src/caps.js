/**
 * wreck input caps — the cloudflare-os #668 readTextCapped pattern
 * (cycle-03, thread 6): reject-never-truncate, Content-Length as early
 * check only, never the authority.
 *
 * - WASM_INPUT_CAP (1 MiB): the JSON ABI into wreck_decide/wreck_complete.
 *   Must match wreck-wasm MAX_INPUT_BYTES. Claims and views are small by
 *   design; anything larger is a bug or an attack.
 * - EVENT_CAP (16 KiB): claim/event envelopes on the queue and in push
 *   payloads. #668 routed connect-form parsing through 16 KiB because
 *   parsing before the cap let anyone buffer an arbitrarily large body
 *   into the isolate. Same logic here: cap before JSON.parse.
 */

export const WASM_INPUT_CAP = 1_048_576; // 1 MiB
export const EVENT_CAP = 16_384; // 16 KiB

export class CapExceeded extends Error {
  constructor(what, bytes, cap) {
    super(
      JSON.stringify({
        error: "cap_exceeded",
        what,
        bytes,
        cap,
        policy: "reject-never-truncate",
      }),
    );
    this.name = "CapExceeded";
    this.what = what;
    this.bytes = bytes;
    this.cap = cap;
  }
}

/** Throw CapExceeded (machine-readable) if byteLength > cap. Never truncates. */
export function checkCap(byteLength, cap, what) {
  if (byteLength > cap) throw new CapExceeded(what, byteLength, cap);
}

export function utf8Len(str) {
  return new TextEncoder().encode(str).length;
}

/**
 * L4 (cycle-06 audit): measure the JSON encoding length of a value WITHOUT
 * materializing the full string. The old handleMessage did
 * utf8Len(JSON.stringify(msg.body)) — building a second full copy of the
 * body before the cap check, deviating from the #668 "cap before touch"
 * pattern. This walks the value incrementally and throws CapExceeded the
 * moment the running total exceeds cap: the accumulator never holds more
 * than cap + one JSON atom. Slightly conservative around undefined-valued
 * object keys (counted, then dropped by JSON.stringify) — fail-closed
 * direction, never under-counts.
 */
export function measureJsonBytes(value, cap, what) {
  const enc = new TextEncoder();
  let total = 0;
  const add = (n) => {
    total += n;
    if (total > cap) throw new CapExceeded(what, total, cap);
  };
  (function walk(v) {
    if (v === null || v === undefined) return add(v === null ? 4 : 0);
    switch (typeof v) {
      case "boolean":
        return add(v ? 4 : 5);
      case "number":
        return add(enc.encode(String(v)).length);
      case "string":
        return add(enc.encode(JSON.stringify(v)).length);
      case "object":
        if (Array.isArray(v)) {
          add(2); // [ ]
          for (let i = 0; i < v.length; i++) {
            if (i > 0) add(1);
            walk(v[i]);
          }
          return;
        }
        add(2); // { }
        let first = true;
        for (const k of Object.keys(v)) {
          if (!first) add(1);
          first = false;
          add(enc.encode(JSON.stringify(k)).length + 1); // "k":
          walk(v[k]);
        }
        return;
      default:
        return; // function/symbol/bigint: dropped by JSON.stringify
    }
  })(value);
  return total;
}

/**
 * Stream-decode a WHATWG byte stream with a byte cap — the readTextCapped
 * shape: rejects (never truncates) over-limit bodies, cancels the reader
 * immediately on violation. For future fetch surfaces on this Worker.
 */
export async function readTextCapped(stream, maxBytes, what) {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let out = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        throw new CapExceeded(what, bytes, maxBytes);
      }
      out += decoder.decode(value, { stream: true });
    }
    out += decoder.decode();
    return out;
  } finally {
    reader.releaseLock();
  }
}
