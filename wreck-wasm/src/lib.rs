//! wreck-wasm: the governor core compiled for Cloudflare Workers.
//!
//! JSON-in / JSON-out ABI (no wasm-bindgen needed):
//!   wreck_init_key(key_ptr, key_len) -> i32 (0 ok, negative on error)
//!   wreck_alloc(size) -> *mut u8 (null on exhaustion; M6)
//!   wreck_free(ptr, size) -> i32 (0 ok, -1 invalid; M6)
//!   wreck_decide(in_ptr, in_len, out_ptr, out_cap) -> i32 (bytes written, or -1)
//!   wreck_complete(in_ptr, in_len, out_ptr, out_cap) -> i32
//!
//! Host buffer contract (M6): allocate input/output buffers per call with
//! wreck_alloc, free both with wreck_free (exact sizes) after the call
//! returns. Never use fixed regions. On -1 the output buffer holds a
//! NUL-terminated {"error":...} envelope.
//!
//! AUTHORITY KEY (H1, cycle-06 audit): the sealing key is installed ONCE via
//! wreck_init_key into WASM-static memory. It NEVER crosses the JS→WASM
//! boundary again — decide/complete inputs carry no key material. Re-init
//! zeroizes the previous key before installing the new one.
//!
//! INPUT CAP (thread 6, cloudflare-os #668 readTextCapped pattern):
//! inputs over MAX_INPUT_BYTES (1 MiB) are rejected with {"error":...} —
//! reject-never-truncate, never process partial. The cap is checked BEFORE
//! the input slice is even viewed, so oversized memory is never touched.
//!
//! Input (decide):
//!   { "claim": ChangeClaim, "view": ChangeView, "in_flight": [ChangeView],
//!     "merged": [change_id], "policy": Policy, "actor": "...", "ts": "..." }
//! Output (decide): { "claim": ChangeClaim, "outcome": "accept_pending"|"decided",
//!                    "draft": DecisionRecord|null, "decision": DecisionRecord|null }
//! Input (complete): { "draft": DecisionRecord, "claim": ChangeClaim,
//!                     "merge_sha": "...", "port": "...",
//!                     "expected_parent_seal": "..."|null,  // M3: D1 head
//!                     "actor": "...", "ts": "..." }
//! Output (complete): { "claim": ChangeClaim, "decision": DecisionRecord }

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::slice;
use std::sync::Mutex;
use wreck_governor::{DecideOutcome, Governor};
use wreck_graph::{ChangeView, Policy};
use wreck_protocol::{ChangeClaim, DecisionRecord, Sha};

/// The installed authority key. Installed once via wreck_init_key;
/// cloned out per decision (the Governor takes ownership).
static AUTHORITY_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Max authority-key size: HMAC keys are small; anything larger is a bug.
const MAX_KEY_BYTES: usize = 256;

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    // keep the compiler from optimizing the wipe away
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn install_key(key: &[u8]) -> Result<(), String> {
    if key.is_empty() {
        return Err("wreck: refusing to install an empty authority key".into());
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(format!(
            "wreck: authority key {} bytes exceeds {} byte cap",
            key.len(),
            MAX_KEY_BYTES
        ));
    }
    let mut guard = AUTHORITY_KEY
        .lock()
        .map_err(|_| "wreck: authority key lock poisoned".to_string())?;
    // zeroize the previous key before replacing it
    if let Some(mut old) = guard.take() {
        zeroize(&mut old);
    }
    *guard = Some(key.to_vec());
    Ok(())
}

fn authority_key() -> Result<Vec<u8>, String> {
    AUTHORITY_KEY
        .lock()
        .map_err(|_| "wreck: authority key lock poisoned".to_string())?
        .clone()
        .ok_or_else(|| "wreck: authority key not installed — call wreck_init_key first".to_string())
}

#[derive(Deserialize)]
struct DecideInput {
    claim: ChangeClaim,
    view: ChangeView,
    in_flight: Vec<ChangeView>,
    merged: Vec<String>,
    policy: Policy,
    actor: String,
    ts: String,
}

#[derive(Serialize)]
struct DecideOutput {
    claim: ChangeClaim,
    outcome: String,
    draft: Option<DecisionRecord>,
    decision: Option<DecisionRecord>,
}

#[derive(Deserialize)]
struct CompleteInput {
    draft: DecisionRecord,
    claim: ChangeClaim,
    merge_sha: String,
    port: String,
    /// M3 (cycle-06 audit): the persisted chain head (D1). When supplied,
    /// the draft's parent must equal it or sealing is refused (no forks).
    /// When absent, the check is self-attested against the draft's own
    /// parent — the Worker MUST supply the D1 head before deploy.
    #[serde(default)]
    expected_parent_seal: Option<String>,
    actor: String,
    ts: String,
}

#[derive(Serialize)]
struct CompleteOutput {
    claim: ChangeClaim,
    decision: DecisionRecord,
}

fn run_decide(input: &[u8]) -> Result<Vec<u8>, String> {
    let inp: DecideInput =
        serde_json::from_slice(input).map_err(|e| format!("decide input: {}", e))?;
    // H1: the key comes from WASM-static memory, never from the input.
    // A "key_hex" field in the JSON is ignored by serde (unknown field).
    let key = authority_key()?;
    let mut gov = Governor::new(inp.policy, key, &inp.actor);
    let mut claim = inp.claim;
    let merged: HashSet<String> = inp.merged.into_iter().collect();
    let out = match gov.decide(&mut claim, &inp.view, &inp.in_flight, &merged, &inp.ts)? {
        DecideOutcome::AcceptPending { draft } => DecideOutput {
            claim,
            outcome: "accept_pending".into(),
            draft: Some(draft),
            decision: None,
        },
        DecideOutcome::Decided(decision) => DecideOutput {
            claim,
            outcome: "decided".into(),
            draft: None,
            decision: Some(decision),
        },
    };
    serde_json::to_vec(&out).map_err(|e| e.to_string())
}

fn run_complete(input: &[u8]) -> Result<Vec<u8>, String> {
    let inp: CompleteInput =
        serde_json::from_slice(input).map_err(|e| format!("complete input: {}", e))?;
    // H1: same as decide — key from static memory, never the input.
    let key = authority_key()?;
    // M3: seed the chain at the caller-supplied head so Governor::seal
    // enforces continuity against the persisted head. Without it the
    // check is self-attested (documented gap until the Worker wires D1).
    let head = inp
        .expected_parent_seal
        .clone()
        .unwrap_or_else(|| inp.draft.parent_decision.clone());
    let mut gov = Governor::with_head(Policy::default(), key, &inp.actor, &head);
    let sha = Sha::new(&inp.merge_sha)?;
    let mut claim = inp.claim;
    // claim must be at ELIGIBLE for the merge to be recorded honestly
    let decision = gov.complete_merge(inp.draft, &sha, &inp.port, &inp.ts)?;
    claim.status = wreck_protocol::ChangeStatus::Merged;
    let out = CompleteOutput { claim, decision };
    serde_json::to_vec(&out).map_err(|e| e.to_string())
}

/// 1 MiB cap on every JSON ABI input — mirrors the cloudflare-os
/// readTextCapped "1 MiB default" (cycle-03, thread 6). Claims and views
/// are small by design; anything larger is a bug or an attack.
pub const MAX_INPUT_BYTES: usize = 1_048_576;

/// Pure cap check, unit-testable. Called before the input slice is viewed.
fn check_input_cap(input_len: usize) -> Result<(), String> {
    if input_len > MAX_INPUT_BYTES {
        return Err(format!(
            "wreck: input {} bytes exceeds {} byte cap (reject-never-truncate)",
            input_len, MAX_INPUT_BYTES
        ));
    }
    Ok(())
}

fn call(
    input_ptr: *const u8,
    input_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    f: fn(&[u8]) -> Result<Vec<u8>, String>,
) -> i32 {
    let result = (|| -> Result<Vec<u8>, String> {
        if input_ptr.is_null() || out_ptr.is_null() {
            return Err("null pointer".into());
        }
        check_input_cap(input_len)?;
        let input = unsafe { slice::from_raw_parts(input_ptr, input_len) };
        f(input)
    })();
    match result {
        Ok(bytes) => {
            if bytes.len() > out_cap {
                return -2; // output buffer too small
            }
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len());
            }
            bytes.len() as i32
        }
        Err(e) => {
            let msg = format!("{{\"error\":{}}}", serde_json::Value::String(e));
            let b = msg.as_bytes();
            if b.len() <= out_cap {
                unsafe {
                    // NUL-fill first: the host reads the error as a
                    // NUL-terminated string without knowing its length.
                    std::ptr::write_bytes(out_ptr, 0, out_cap);
                    std::ptr::copy_nonoverlapping(b.as_ptr(), out_ptr, b.len());
                }
            }
            -1
        }
    }
}

/// Decide without merging. Returns bytes written to out_ptr, or negative.
#[no_mangle]
pub extern "C" fn wreck_decide(
    input_ptr: *const u8,
    input_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    call(input_ptr, input_len, out_ptr, out_cap, run_decide)
}

/// Seal an accepted draft after the substrate merged it.
#[no_mangle]
pub extern "C" fn wreck_complete(
    input_ptr: *const u8,
    input_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
) -> i32 {
    call(input_ptr, input_len, out_ptr, out_cap, run_complete)
}

/// Install the authority signing key into WASM-static memory (H1).
/// Call once at worker startup; the key never crosses the JS→WASM
/// boundary again. Re-installing zeroizes the previous key first.
/// Returns 0 on success, negative on error.
///
/// # Safety
/// `key_ptr` must point to `key_len` readable bytes (standard WASM ABI
/// contract: the host copies the key into linear memory first).
#[no_mangle]
pub unsafe extern "C" fn wreck_init_key(key_ptr: *const u8, key_len: usize) -> i32 {
    if key_ptr.is_null() {
        return -1;
    }
    let key = unsafe { slice::from_raw_parts(key_ptr, key_len) };
    match install_key(key) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Test-only: uninstall the key (with zeroize) so tests can assert the
/// fail-closed "not installed" path regardless of execution order.
#[cfg(test)]
fn uninstall_key_for_tests() {
    if let Ok(mut guard) = AUTHORITY_KEY.lock() {
        if let Some(mut old) = guard.take() {
            zeroize(&mut old);
        }
    }
}

/// Serializes all tests that touch the process-global AUTHORITY_KEY or
/// drain the allocator heap (M6 exhaustion test).
#[cfg(test)]
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------------
// Minimal per-call allocator (M6, cycle-06 audit).
//
// ABI contract (host = the Worker):
//   - allocate input/output buffers per call with wreck_alloc;
//   - pass the EXACT size given to wreck_alloc back to wreck_free;
//   - free both buffers after the call returns (success or failure);
//   - a null return from wreck_alloc means the heap is exhausted —
//     the call must not proceed.
// The heap is a fixed 16 MiB Box<[u8]> (stable address: Box never moves
// its pointee), managed as a free list with coalescing, 8-byte aligned.
// The Worker's JS event loop is single-threaded per isolate, but the
// Mutex makes concurrent host calls memory-safe anyway. This closes the
// fixed-region `inPtr = 0` race: no call ever shares an input region.
// ---------------------------------------------------------------------------

const HEAP_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy)]
struct FreeBlock {
    offset: usize,
    len: usize,
}

struct WasmHeap {
    mem: Option<Box<[u8]>>,
    free: Vec<FreeBlock>,
}

impl WasmHeap {
    fn base(&mut self) -> *mut u8 {
        if self.mem.is_none() {
            self.mem = Some(vec![0u8; HEAP_BYTES].into_boxed_slice());
            self.free = vec![FreeBlock {
                offset: 0,
                len: HEAP_BYTES,
            }];
        }
        self.mem.as_mut().unwrap().as_mut_ptr()
    }
}

static HEAP: Mutex<WasmHeap> = Mutex::new(WasmHeap {
    mem: None,
    free: vec![],
});

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// Allocate `size` bytes (8-byte aligned). Returns null on exhaustion.
#[no_mangle]
pub extern "C" fn wreck_alloc(size: usize) -> *mut u8 {
    let size = align8(size.max(1));
    let mut heap = match HEAP.lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    let base = heap.base();
    // first-fit
    let idx = match heap.free.iter().position(|b| b.len >= size) {
        Some(i) => i,
        None => return std::ptr::null_mut(), // exhausted: caller must not proceed
    };
    let block = heap.free.remove(idx);
    if block.len > size {
        heap.free.push(FreeBlock {
            offset: block.offset + size,
            len: block.len - size,
        });
    }
    // SAFETY: base is a stable Box<[u8]> pointee; offset+size <= HEAP_BYTES
    // by construction of the free list.
    let ptr = unsafe { base.add(block.offset) };
    // Zero the block on alloc: the JS side reads error envelopes (rc == -1)
    // up to the first NUL byte, and stale bytes from a previous occupant
    // must never leak across calls (key-material hygiene, cf. H1).
    unsafe { std::ptr::write_bytes(ptr, 0, size) };
    ptr
}

/// Free a buffer previously returned by wreck_alloc. `size` must be the
/// exact size passed to wreck_alloc. Returns 0 on success, -1 on an
/// invalid pointer/size (out of range) — never corrupts the free list.
#[no_mangle]
pub extern "C" fn wreck_free(ptr: *mut u8, size: usize) -> i32 {
    let size = align8(size.max(1));
    let mut heap = match HEAP.lock() {
        Ok(g) => g,
        Err(_) => return -1,
    };
    if heap.mem.is_none() || ptr.is_null() {
        return -1;
    }
    let base = heap.mem.as_mut().unwrap().as_mut_ptr() as usize;
    let p = ptr as usize;
    if p < base || p + size > base + HEAP_BYTES || p < base {
        return -1;
    }
    let offset = p - base;
    heap.free.push(FreeBlock { offset, len: size });
    // coalesce adjacent blocks
    heap.free.sort_by_key(|b| b.offset);
    let mut merged: Vec<FreeBlock> = Vec::with_capacity(heap.free.len());
    for b in heap.free.drain(..) {
        if let Some(last) = merged.last_mut() {
            if last.offset + last.len == b.offset {
                last.len += b.len;
                continue;
            }
        }
        merged.push(b);
    }
    heap.free = merged;
    0
}

#[cfg(test)]
mod cap_tests {
    use super::*;

    #[test]
    fn at_cap_accepted() {
        assert!(check_input_cap(MAX_INPUT_BYTES).is_ok());
    }

    #[test]
    fn zero_accepted() {
        assert!(check_input_cap(0).is_ok());
    }

    #[test]
    fn over_cap_rejected() {
        let err = check_input_cap(MAX_INPUT_BYTES + 1).unwrap_err();
        assert!(err.contains("exceeds"), "err: {}", err);
        assert!(err.contains("reject-never-truncate"), "err: {}", err);
    }

    #[test]
    fn call_rejects_oversized_input_with_error_envelope() {
        // real oversized buffer: the cap fires before the slice is viewed
        let big = vec![b'x'; MAX_INPUT_BYTES + 1];
        let mut out = vec![0u8; 4096];
        let rc = call(big.as_ptr(), big.len(), out.as_mut_ptr(), out.len(), |_| {
            Ok(b"should never run".to_vec())
        });
        assert_eq!(rc, -1);
        let msg = std::str::from_utf8(&out[..256]).unwrap();
        assert!(msg.starts_with("{\"error\":"), "out: {}", msg);
        assert!(msg.contains("exceeds"), "out: {}", msg);
    }

    #[test]
    fn truncated_json_never_parsed_silently() {
        // a caller that passes a truncated length gets a JSON parse error,
        // never a silently-accepted partial document
        let full = b"{\"claim\":";
        let mut out = vec![0u8; 4096];
        let rc = call(
            full.as_ptr(),
            full.len(),
            out.as_mut_ptr(),
            out.len(),
            run_decide,
        );
        assert_eq!(rc, -1);
        let msg = std::str::from_utf8(&out[..512]).unwrap();
        assert!(msg.starts_with("{\"error\":"), "out: {}", msg);
        assert!(
            msg.contains("decide input"),
            "must be a JSON parse error, not silent: {}",
            msg
        );
        assert!(!msg.contains("exceeds"), "must not be a cap error: {}", msg);
    }

    #[test]
    fn under_cap_invalid_json_still_reaches_parser() {
        // small garbage input: cap passes, serde rejects with its own error
        let junk = b"not json at all";
        let mut out = vec![0u8; 4096];
        let rc = call(
            junk.as_ptr(),
            junk.len(),
            out.as_mut_ptr(),
            out.len(),
            run_decide,
        );
        assert_eq!(rc, -1);
        let msg = std::str::from_utf8(&out[..512]).unwrap();
        assert!(msg.contains("decide input"), "out: {}", msg);
    }
}

#[cfg(test)]
mod m6_alloc_tests {
    use super::*;

    #[test]
    fn alloc_free_roundtrip() {
        let p = wreck_alloc(64);
        assert!(!p.is_null());
        // 8-byte aligned
        assert_eq!(p as usize % 8, 0);
        unsafe { std::ptr::write_bytes(p, 0xAB, 64) };
        assert_eq!(wreck_free(p, 64), 0);
    }

    #[test]
    fn alloc_reuses_freed_blocks() {
        let a = wreck_alloc(128);
        let b = wreck_alloc(128);
        assert!(!a.is_null() && !b.is_null() && a != b);
        assert_eq!(wreck_free(a, 128), 0);
        let c = wreck_alloc(128);
        assert!(!c.is_null());
        // freed block reused (first-fit)
        assert_eq!(c, a);
        assert_eq!(wreck_free(b, 128), 0);
        assert_eq!(wreck_free(c, 128), 0);
    }

    #[test]
    fn alloc_exhaustion_returns_null() {
        // drains the whole heap: serialize against other allocator tests
        let _guard = TEST_SERIAL.lock().unwrap();
        // drain the 16 MiB heap in 1 MiB chunks
        let mut ptrs = vec![];
        loop {
            let p = wreck_alloc(1024 * 1024);
            if p.is_null() {
                break;
            }
            ptrs.push(p);
            if ptrs.len() > 32 {
                break; // safety: never loop forever
            }
        }
        assert!(
            ptrs.len() >= 16,
            "heap smaller than expected: {}",
            ptrs.len()
        );
        for p in ptrs {
            assert_eq!(wreck_free(p, 1024 * 1024), 0);
        }
        // coalesced back: a 1 MiB alloc works again
        let p = wreck_alloc(1024 * 1024);
        assert!(!p.is_null());
        assert_eq!(wreck_free(p, 1024 * 1024), 0);
    }

    #[test]
    fn free_invalid_pointer_fails() {
        assert_eq!(wreck_free(std::ptr::null_mut(), 64), -1);
        let stack_var = 0u8;
        assert_eq!(wreck_free(&stack_var as *const u8 as *mut u8, 64), -1);
    }

    #[test]
    fn concurrent_allocs_do_not_overlap() {
        // the fixed-region bug this replaces: two live allocations must
        // never alias the same memory
        let ps: Vec<*mut u8> = (0..16).map(|_| wreck_alloc(4096)).collect();
        assert!(ps.iter().all(|p| !p.is_null()));
        for (i, a) in ps.iter().enumerate() {
            for b in ps.iter().skip(i + 1) {
                let (a, b) = (*a as usize, *b as usize);
                assert!(a + 4096 <= b || b + 4096 <= a, "overlap: {:x} {:x}", a, b);
            }
        }
        for p in ps {
            assert_eq!(wreck_free(p, 4096), 0);
        }
    }

    #[test]
    fn alloc_zeroes_blocks() {
        // stale bytes from a previous occupant must never leak: the JS
        // side reads error envelopes up to the first NUL, and key-adjacent
        // data must not survive across calls (cf. H1).
        let p = wreck_alloc(64);
        assert!(!p.is_null());
        unsafe { std::ptr::write_bytes(p, 0xAB, 64) };
        assert_eq!(wreck_free(p, 64), 0);
        // re-allocate (first-fit reuses the freed block): must be zeroed
        let q = wreck_alloc(64);
        assert!(!q.is_null());
        let mem = unsafe { std::slice::from_raw_parts(q, 64) };
        assert!(
            mem.iter().all(|&b| b == 0),
            "reused block not zeroed — stale bytes leak"
        );
        assert_eq!(wreck_free(q, 64), 0);
    }
}

#[cfg(test)]
mod m3_complete_tests {
    use super::*;

    fn complete_input_json(expected_parent_seal: Option<&str>) -> Vec<u8> {
        let key = b"m3-test-key-32-bytes-padded!!!!!!";
        uninstall_key_for_tests();
        let rc = unsafe { wreck_init_key(key.as_ptr(), key.len()) };
        assert_eq!(rc, 0);
        // build a real accept-pending draft through the governor:
        // claim with evidence + scope, no conflicts -> ELIGIBLE draft
        // whose parent is GENESIS
        let mut c = ChangeClaim::propose(
            "w-m3",
            "agent-1",
            "task-1",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "test",
        )
        .expect("valid change_id");
        c.scope.push(wreck_protocol::ScopeItem::File {
            path: "src/x.rs".into(),
        });
        c.claims.push(wreck_protocol::Claim {
            id: "C1".into(),
            statement: "s".into(),
            kind: wreck_protocol::ClaimKind::PreservesApi,
        });
        c.evidence.push(wreck_protocol::Evidence {
            id: "C1-E1".into(),
            kind: wreck_protocol::EvidenceKind::Test,
            reference: "C1: t".into(),
            digest: "sha256:x".into(),
        });
        let mut gov = Governor::new(Policy::default(), key.to_vec(), "test");
        let draft = match gov
            .decide(
                &mut c,
                &ChangeView::default(),
                &[],
                &std::collections::HashSet::new(),
                "2026-10-08T00:00:00Z",
            )
            .unwrap()
        {
            DecideOutcome::AcceptPending { draft } => draft,
            DecideOutcome::Decided(_) => panic!("expected accept-pending"),
        };
        let mut v = serde_json::json!({
            "draft": draft,
            "claim": c,
            "merge_sha": "f".repeat(40),
            "port": "test",
            "actor": "test",
            "ts": "2026-10-08T00:00:00Z",
        });
        match expected_parent_seal {
            Some(s) => {
                v.as_object_mut().unwrap().insert(
                    "expected_parent_seal".into(),
                    serde_json::Value::String(s.into()),
                );
            }
            None => {
                v.as_object_mut()
                    .unwrap()
                    .insert("expected_parent_seal".into(), serde_json::Value::Null);
            }
        }
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn complete_with_matching_head_seals() {
        let _guard = TEST_SERIAL.lock().unwrap();
        let input = complete_input_json(Some("GENESIS"));
        let out = run_complete(&input).expect("complete must seal");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(v["decision"]["receipt"]["seal"].is_string());
        let merge = &v["decision"]["merge"];
        assert_eq!(merge["port"], "test");
    }

    #[test]
    fn complete_with_wrong_head_is_refused() {
        let _guard = TEST_SERIAL.lock().unwrap();
        let input = complete_input_json(Some("WRONG-HEAD"));
        let err = run_complete(&input).unwrap_err();
        assert!(
            err.contains("fork") || err.contains("replay"),
            "unexpected error: {}",
            err
        );
    }
}

#[cfg(test)]
mod h1_key_tests {
    use super::*;

    fn decide_input_json(extra_key_hex: Option<&str>) -> Vec<u8> {
        let claim = ChangeClaim::propose(
            "w-h1",
            "agent-1",
            "task-1",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "test intent",
        )
        .expect("valid change_id");
        let mut v = serde_json::json!({
            "claim": claim,
            "view": ChangeView::default(),
            "in_flight": [],
            "merged": [],
            "policy": Policy::default(),
            "actor": "test",
            "ts": "2026-10-08T00:00:00Z",
        });
        if let Some(kh) = extra_key_hex {
            v.as_object_mut()
                .unwrap()
                .insert("key_hex".into(), serde_json::Value::String(kh.into()));
        }
        serde_json::to_vec(&v).unwrap()
    }

    fn install(key: &[u8]) {
        let rc = unsafe { wreck_init_key(key.as_ptr(), key.len()) };
        assert_eq!(rc, 0, "wreck_init_key failed");
    }

    #[test]
    fn decide_without_installed_key_is_fail_closed() {
        let _guard = TEST_SERIAL.lock().unwrap();
        uninstall_key_for_tests();
        let err = run_decide(&decide_input_json(None)).unwrap_err();
        assert!(err.contains("not installed"), "err: {}", err);
        assert!(err.contains("wreck_init_key"), "err: {}", err);
    }

    #[test]
    fn init_key_then_decide_works() {
        let _guard = TEST_SERIAL.lock().unwrap();
        uninstall_key_for_tests();
        install(b"test-authority-key-32-bytes!!!!!!!");
        let out = run_decide(&decide_input_json(None)).expect("decide must work");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["outcome"], "decided"); // evidence gate rejects, but it SEALS
        assert!(v["decision"]["receipt"]["seal"].is_string());
    }

    #[test]
    fn key_hex_in_input_is_ignored() {
        // H1 core: key material smuggled in the decide input must have no
        // effect — the installed static key is the only one ever used.
        let _guard = TEST_SERIAL.lock().unwrap();
        uninstall_key_for_tests();
        install(b"installed-key-abc");
        // garbage key_hex that the OLD code path would have choked on
        // (odd length → "odd hex length" error before H1)
        let out = run_decide(&decide_input_json(Some("zz"))).expect("decide must work");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["outcome"], "decided");
        // and a well-formed-but-wrong key_hex is equally ignored
        let out2 =
            run_decide(&decide_input_json(Some(&"ab".repeat(32)))).expect("decide must work");
        let v2: serde_json::Value = serde_json::from_slice(&out2).unwrap();
        assert_eq!(v2["outcome"], "decided");
    }

    #[test]
    fn init_key_rejects_empty_and_oversized() {
        let _guard = TEST_SERIAL.lock().unwrap();
        assert_eq!(unsafe { wreck_init_key(b"".as_ptr(), 0) }, -1);
        let big = vec![7u8; MAX_KEY_BYTES + 1];
        assert_eq!(unsafe { wreck_init_key(big.as_ptr(), big.len()) }, -1);
        assert_eq!(unsafe { wreck_init_key(std::ptr::null(), 10) }, -1);
    }

    #[test]
    fn reinit_replaces_key_without_poison() {
        let _guard = TEST_SERIAL.lock().unwrap();
        uninstall_key_for_tests();
        install(b"first-key");
        install(b"second-key-longer!!");
        let out = run_decide(&decide_input_json(None)).expect("decide after re-init");
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["outcome"], "decided");
    }
}

