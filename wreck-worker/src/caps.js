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
