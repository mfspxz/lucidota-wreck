//! wreck-wasm: the governor core compiled for Cloudflare Workers.
//!
//! JSON-in / JSON-out ABI (no wasm-bindgen needed):
//!   wreck_decide(in_ptr, in_len, out_ptr, out_cap) -> i32 (bytes written, or -1)
//!   wreck_complete(in_ptr, in_len, out_ptr, out_cap) -> i32
//!
//! Input (decide):
//!   { "claim": ChangeClaim, "view": ChangeView, "in_flight": [ChangeView],
//!     "merged": [change_id], "policy": Policy, "key_hex": "...", "actor": "...", "ts": "..." }
//! Output (decide): { "claim": ChangeClaim, "outcome": "accept_pending"|"decided",
//!                    "draft": DecisionRecord|null, "decision": DecisionRecord|null }
//! Input (complete): { "draft": DecisionRecord, "claim": ChangeClaim,
//!                     "merge_sha": "...", "port": "...", "key_hex": "...",
//!                     "actor": "...", "ts": "..." }
//! Output (complete): { "claim": ChangeClaim, "decision": DecisionRecord }

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::slice;
use wreck_governor::{DecideOutcome, Governor};
use wreck_graph::{ChangeView, Policy};
use wreck_protocol::{ChangeClaim, DecisionRecord, Sha};

#[derive(Deserialize)]
struct DecideInput {
    claim: ChangeClaim,
    view: ChangeView,
    in_flight: Vec<ChangeView>,
    merged: Vec<String>,
    policy: Policy,
    key_hex: String,
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
    key_hex: String,
    actor: String,
    ts: String,
}

#[derive(Serialize)]
struct CompleteOutput {
    claim: ChangeClaim,
    decision: DecisionRecord,
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn run_decide(input: &[u8]) -> Result<Vec<u8>, String> {
    let inp: DecideInput =
        serde_json::from_slice(input).map_err(|e| format!("decide input: {}", e))?;
    let key = hex_to_bytes(&inp.key_hex)?;
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
    let key = hex_to_bytes(&inp.key_hex)?;
    let mut gov = Governor::new(Policy::default(), key, &inp.actor);
    // NOTE: the chain parent seal comes from the draft itself; the Worker's
    // persisted chain head must match draft.parent_decision (checked by caller).
    let sha = Sha::new(&inp.merge_sha)?;
    let mut claim = inp.claim;
    // claim must be at ELIGIBLE for the merge to be recorded honestly
    let decision = gov.complete_merge(inp.draft, &sha, &inp.port, &inp.ts)?;
    claim.status = wreck_protocol::ChangeStatus::Merged;
    let out = CompleteOutput { claim, decision };
    serde_json::to_vec(&out).map_err(|e| e.to_string())
}

fn call(input_ptr: *const u8, input_len: usize, out_ptr: *mut u8, out_cap: usize, f: fn(&[u8]) -> Result<Vec<u8>, String>) -> i32 {
    let result = (|| -> Result<Vec<u8>, String> {
        if input_ptr.is_null() || out_ptr.is_null() {
            return Err("null pointer".into());
        }
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
