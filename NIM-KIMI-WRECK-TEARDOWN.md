# Wreck Teardown — NIM / Kimi K3.1 Pro (INTERIM)

**INTERIM VERSION — NOT the K-EXAONE teardown.** This review was produced by
Moonshot Kimi K3.1 Pro via NVIDIA NIM because no K-EXAONE path was available
on 2026-11-20 (Friendli: 0 credits, no EXAONE on serverless; direct LG API:
region-gated signup pending). The K-EXAONE re-run happens when a key lands.
Treat this as the interim teardown, not the final word.

**Model:** moonshotai/kimi-k3.1-pro (2.8T MoE, 104B active, 1M-token context)
via NVIDIA NIM, streaming chat completions.
**Date:** 2026-11-20.
**Method:** the full source of the 6 Rust crates + the Cloudflare Worker was
packed verbatim (22 files, 280,336 chars, ~70K tokens) and given to the model
in a single call with Zack's teardown brief: 5 biggest holes ranked with
file+function; attestation vs real verification in the evidence gate; whether
the in-memory-only sealed receipt chain + Worker stubs make the seal worth
anything; the ONE fix to do first this week. No flattery.
**Code reviewed:** lucidota-wreck at git HEAD
`c411bca2f660224b6b49bb0193bf88391272a7dc` (working tree clean for all
reviewed crates; untracked files present are OpenCode/Friendli docs only).
Code pack sha256: `950b212b603e8e5d…` (full hash in the run record below).
**Files in the pack:** wreck-protocol/src/lib.rs (832 lines),
wreck-graph/src/lib.rs (611), wreck-governor/src/lib.rs (1494),
wreck-canon/src/lib.rs (171), wreck-adapters/src/artifacts.rs (1333),
wreck-adapters/src/lib.rs (15), wreck-adapters/src/local.rs (321),
wreck-adapters/src/token_custodian.rs (819), wreck-wasm/src/lib.rs (985),
wreck-worker/src/worker.js (546), wreck-worker/src/caps.js (142),
wreck-worker/src/event.js (73), wreck-worker/src/idempotency.js (90),
wreck-worker/src/lease.js (266), wreck-worker/wrangler.toml (14),
workspace Cargo.toml + 6 crate manifests.
**NOT in the pack:** the `pl` envelope/canon implementation
(`../../proof-ledger/rs`, a path dependency) — the seal's crypto lives there
and was not reviewed. Any claim about the seal's strength is conditional on
that unreviewed code. Test files (`.test.js`, `#[cfg(test)]` modules were
included where they live inside the reviewed `lib.rs` files; standalone
worker test files were excluded).

**How to read this:** the model wrote the teardown below. Every finding cites
file+function. A parent-agent cross-check against the real code follows the
model's text: findings confirmed, findings that need a second look, and
anything the model missed that the code shows.

---

## 1. The 5 biggest holes, ranked

### 1. The governor can ACCEPT a change with zero claims, zero evidence, and no declared files

**Where:** `wreck-governor/src/lib.rs`, `Governor::check_evidence`, `Governor::check_scope_attestation`, and `Governor::decide`.

`check_evidence` iterates over `change.claims`. If `claims` is empty, that loop does nothing; an empty `evidence` vector is only rejected *inside* that loop. Therefore this passes:

- `scope`: one `ScopeItem::Symbol`
- `claims`: `[]`
- `evidence`: `[]`

`check_scope_attestation` then explicitly returns `Ok(())` when no files are declared. A symbol-only scope therefore disables file-scope attestation while satisfying the non-empty-scope requirement. With no conflicts and no matching policy rule, `Governor::decide` advances the claim through `Proven` and `Eligible` and returns `AcceptPending`.

The per-claim linkage logic is also broken. For claim `C1`, evidence referenced as `C2: anything` produces:

- `linked == false`
- `unattached == false`
- `ev.is_empty() == true`

The rejection requires `!ev.is_empty()`, so it does not fire. Unrelated evidence satisfies the gate.

**Impact:** on the Rust governor path today, an agent can reach merge with no evidence at all and without attesting to the files changed. Adding one unrelated evidence string is enough when claims are present. This is a direct governance bypass, not a theoretical hardening opportunity.

---

### 2. Code is merged before the decision is sealed, and neither merge port enforces `claim.base`

**Where:** `wreck-governor/src/lib.rs`, `Governor::evaluate` and `Governor::complete_merge`; `wreck-adapters/src/local.rs`, `LocalMergePort::merge`; `wreck-adapters/src/artifacts.rs`, `ArtifactsMergePort::merge`.

`Governor::evaluate` executes `merger.merge(change)` first. Only after it succeeds does it mark the claim `Merged` and call `complete_merge` to seal the decision. If sealing fails, or the process crashes between those operations, the code is already merged but there is no sealed decision. The chain-fork guard in `Governor::seal` therefore detects some concurrent forks **after the irreversible operation has already happened**.

Both merge ports merge `change.head` into the baseline's *current* `main`; neither checks that the baseline still equals `change.base`. An approval computed against one baseline can consequently be applied to another without recomputing the view or conflicts.

There is an even uglier failure in `ArtifactsMergePort::merge`: it pushes before running `rev-parse HEAD`. If the push succeeds and `rev-parse` fails, `merge` returns `Err`; `Governor::evaluate` then seals a `MERGE-FAILED` rejection for code that was actually pushed.

**Impact:** stale approvals can land on a newer baseline, concurrent approvals can merge before fork detection, and crashes or post-push errors produce merged code with no receipt—or worse, a receipt saying the merge failed.

---

### 3. The Worker’s “measured” view has empty diffs and drops dependency semantics

**Where:** `wreck-worker/src/worker.js`, `diffRanges`, `buildView`, and `claimFromCommit`; `wreck-graph/src/lib.rs`, `FileChange::overlaps`; `wreck-governor/src/lib.rs`, `Governor::decide`.

`diffRanges` is a TODO that always returns:

```js
{ added: [], removed: [], _todo: "line ranges" }
```

Every changed file therefore has empty line ranges. `FileChange::overlaps` cannot find a textual conflict between empty ranges, so two agents editing the same lines look compatible.

`buildView` also hardcodes `symbols`, `invariants`, `contracts`, and `dependencies` to empty arrays. Meanwhile, `claimFromCommit` puts trailer-supplied dependencies on the **claim**, but `Governor::decide` reads dependencies from the **view**. Trailer dependencies consequently have no effect on this path.

**Impact:** as shipped, the Worker does not reach a verdict anyway: `inFlightViews`, `mergedIds`, and `activePolicy` all throw. But wiring those state sources without fixing `buildView` would create a governor that accepts overlapping edits and ignores declared dependencies. The Worker is nonfunctional now and unsafe to wire as-is.

---

### 4. The Worker has no continuous chain, and `wreck_complete` seals caller-supplied drafts against a self-attested parent

**Where:** `wreck-wasm/src/lib.rs`, `run_decide` and `run_complete`; `wreck-worker/src/worker.js`, `handlePush` and `recordDecision`; `wreck-governor/src/lib.rs`, `Governor::new` and `Governor::with_head`.

Every `run_decide` call constructs `Governor::new`, whose chain starts at `GENESIS`. Rejections and blocked decisions are therefore sealed as independent genesis records. Accepted drafts also start there.

For completion, `run_complete` uses `expected_parent_seal` when supplied; otherwise it uses `inp.draft.parent_decision`—the draft's own claim about its parent. `handlePush` always passes `expected_parent_seal: null`. Two drafts with the same parent can therefore both complete without triggering the fork guard. `recordDecision` is an async no-op, so nothing repairs this afterward.

`run_complete` also does not verify that:

- the draft came from `run_decide`;
- the claim is `ELIGIBLE`, despite its comment saying it must be;
- the claimed merge actually happened;
- `merge_sha` identifies that merge.

It simply seals the supplied draft and forcibly sets `claim.status = Merged`.

**Impact:** there is no durable ordering, replay protection, or reliable fork detection. A caller able to invoke the WASM completion ABI can obtain a validly signed `Accept` receipt for an arbitrary draft and arbitrary 40-hex merge SHA. The provided Worker's `fetch` handler does not expose that ABI publicly, so an unauthenticated Internet route is **not demonstrated by the code provided**; the host/ABI boundary itself is nevertheless trusting forged input.

---

### 5. Oversized blobs disappear from the measurements used for scope and policy decisions

**Where:** `wreck-adapters/src/artifacts.rs`, `resolve_file`, `ArtifactsClient::diff_view`, and `diff_ranges`; `wreck-governor/src/lib.rs`, `Governor::decide` and `Governor::check_scope_attestation`.

On a per-blob cap rejection, `resolve_file` returns `FileOutcome::Skipped`. `ArtifactsClient::diff_view` records that path only in `view.skipped`; it does not add it to `view.files`. The governor never rejects a view because `skipped` is non-empty.

An agent can therefore declare an innocuous file while also changing an additional over-cap blob. That additional blob is absent from:

- the measured files checked by `check_scope_attestation`;
- the files tested against policy `file_patterns`;
- textual conflict measurement.

Sealing the skip reason into the view's provenance does not prevent the resulting ACCEPT.

The same adapter's `diff_ranges` also ignores the git process exit status. Any git failure other than a spawn failure is parsed as whatever stdout was produced—normally empty ranges—rather than rejected.

**Impact:** measurement failure becomes missing evidence against the change instead of a failed decision. Oversized content can hide files from exactly the checks meant to catch concealed or forbidden modifications.

## 2. Attestation vs real verification in the evidence gate

It is **attestation only**, and the attestation is optional because of the empty-claims hole above.

### What `Governor::check_evidence` actually does

In `wreck-governor/src/lib.rs`, it checks only that:

- scope is non-empty;
- some string-based evidence-linkage conditions hold;
- every supplied `Evidence.digest` is not empty or whitespace.

It does **not**:

- parse or validate the digest format;
- fetch `Evidence.reference`;
- recompute a digest over an artifact;
- compare a recomputed digest with `Evidence.digest`;
- run tests, oracles, or static analysis;
- verify signatures;
- verify `EvidenceKind::Receipt` receipts;
- bind evidence to `change.head`.

`EvidenceKind` is never used to select verification behavior.

### What `Governor::decide` records

`Governor::decide` copies each agent-supplied `e.digest` directly into a `ProvenanceEntry`. That records what digest the agent supplied; it does not establish that the digest is correct.

It then sets:

- `claims_checked = change.claims.len()`;
- `proofs = change.evidence.len()`;
- `tests = 0`.

Those are object counts, not checks or proofs. `DecisionRecord::seal` in `wreck-protocol/src/lib.rs` subsequently labels an `Accept` envelope `"established"`, so unverified agent input becomes an “established” decision.

### The hashing that does exist does not rescue the gate

- `wreck_protocol::content_hash` hashes claims, views, and policy rules for provenance.
- `blob_provenance_entry` and `sha256_hex` hash bytes supplied by an adapter.
- `resolve_file` in `wreck-adapters/src/artifacts.rs` genuinely hashes the bytes it received.
- The governor consumes `view.blob_provenance` verbatim; it does not fetch the blobs or recompute those hashes.
- The Worker's `buildView` hashes UTF-8 encoded **decoded text**, not necessarily the original raw blob bytes.

`DecisionRecord::compute_hash`, `DecisionRecord::seal`, and `verify_receipt_with` concern integrity of the **decision envelope**, not correctness of the evidence behind the verdict.

Whether `pl::envelope::verify_with` performs sound cryptographic verification **cannot be determined from the code provided**, because the `pl` implementation was not included. No call to it verifies test, oracle, static-analysis, or receipt evidence in the governor.

## 3. Is the seal worth anything?

Only as a **process-local signing format**. As a durable governance chain, it is currently worth nothing.

Within one live `Governor`, `Governor::seal` checks the parent against its in-memory `chain`, and `DecisionRecord::seal` refuses a stale `decision_hash`. That can detect certain receipt mutations and forks while the same process and records survive.

Outside that narrow setting:

- `Governor.chain` is only a `Vec<String>`; restart resets it to `GENESIS`.
- `run_decide` creates a fresh governor per call.
- `handlePush` supplies no persisted parent to completion.
- `recordDecision` silently does nothing.
- After a hypothetical successful merge, the Worker can call that no-op, write the dedup key, and acknowledge the event without any durable decision existing.

**What breaks first:** in the Worker as shipped, `inFlightViews` throws before any decision. Once the state stubs are wired, the next break is persistence and continuity: decisions are dropped, accepts self-attest their parent, and independent genesis records accumulate.

**What a crash does:** a crash after merge but before completion or durable recording leaves merged code without a receipt. A local governor restart loses the head needed to continue the old chain. A crash before the KV dedup write permits redelivery, but there is no persisted chain state with which to reconcile the previous attempt.

**What tampering does:** `DecisionRecord::verify_receipt_with` in `wreck-protocol/src/lib.rs` verifies only `self.receipt`. It does not recompute `self.compute_hash()`, compare `decision_hash`, or compare the outer struct fields with the sealed payload. Someone editing stored `DecisionRecord` JSON can alter outer fields such as `verdict`, `merge`, or `provenance` while leaving the receipt untouched; this method still only verifies the untouched envelope.

The seal proves, at most, that some key holder signed some payload. It does not prove the evidence was real, the merge happened as described, or that the record belongs to a durable unique history.

## 4. The ONE fix to do first this week

**Turn `Governor::check_evidence` into a fail-closed verification gate, and make `Governor::decide` refuse `AcceptPending` until that verification succeeds.**

**Where:** `wreck-governor/src/lib.rs`, `Governor::check_evidence` and its call site in `Governor::decide`.

Acceptance must require evidence bound to `change.head` and the measured change, with artifact digests recomputed and test/receipt evidence actually executed or cryptographically validated. Empty claims/evidence, unrelated evidence, unavailable artifacts, or an unconfigured verifier must produce rejection or an error—not `Proven`, `Eligible`, or `AcceptPending`. If real verification cannot be landed immediately, disable ACCEPT rather than continuing to seal attestations as `"established"`.

This comes first because it stops the direct path from agent-supplied strings to merged code. A durable chain and a real diff are still necessary, but neither makes an unverified ACCEPT safe; they would merely preserve a better-signed record of bad merges.
---

# Parent-agent cross-check (verified against the real code, 2026-11-20)

Every finding above was checked line-by-line against the source at HEAD
`c411bca2`. Nothing below is taken on the model's word.

## Verdicts on the model's findings

| Finding | Verdict | Evidence |
|---|---|---|
| Hole 1 — empty claims/evidence bypass | **CONFIRMED** | `check_evidence` (governor:125): the `evidence.is_empty()` rejection sits *inside* the `for claim` loop — zero claims means zero checks. `check_scope_attestation` (governor:160) returns `Ok(())` on empty declared files. `advance_to` loops to target, so a Proposed claim reaches `AcceptPending` cleanly. The linkage condition `!linked && !unattached && !ev.is_empty()` fails to fire exactly when `ev` is empty — unrelated evidence passes. |
| Hole 2 — merge before seal, no base check | **CONFIRMED** | `evaluate` (governor:198): `merger.merge()` runs before `complete_merge()` seals. Neither `LocalMergePort::merge` (local.rs:243) nor `ArtifactsMergePort::merge` (artifacts.rs:887) references `change.base`. Artifacts merge pushes (line ~937) *before* `rev-parse HEAD` (line 938); a rev-parse failure returns `Err` and `evaluate` seals a `MERGE-FAILED` rejection for code that was pushed. |
| Hole 3 — Worker view has empty diffs, dead deps | **CONFIRMED** | `diffRanges` (worker.js:418) returns `{added: [], removed: [], _todo: "line ranges"}` verbatim. `buildView` (worker.js:333) hardcodes `symbols/invariants/contracts/dependencies: []`. `claimFromCommit` puts trailer `dependencies` on the claim (allowlisted), but the governor never reads `change.dependencies` — only `view.dependencies` (governor:317). |
| Hole 4 — no continuous chain, self-attested parent | **CONFIRMED** | `run_decide` (wasm:130) builds `Governor::new` per call (fresh `GENESIS` chain). `run_complete` (wasm:164) falls back to `inp.draft.parent_decision` when the head is null; `handlePush` (worker.js:285) always passes `null`. `recordDecision` (worker.js:535) is an empty TODO. `run_complete` seals any well-formed draft and forces `claim.status = Merged` with no ELIGIBLE check despite its own comment. The model's hedge is also correct: the Worker's `fetch` handler serves only `/v1/health`, so no public ABI route is demonstrated. |
| Hole 5 — skipped blobs invisible; `diff_ranges` ignores exit status | **CONFIRMED** | `resolve_file` → `FileOutcome::Skipped` lands only in `view.skipped` (artifacts.rs:800); no governor/wasm code reads `view.skipped`. `diff_ranges` (artifacts.rs:711) shells to `git diff --no-index` and never checks `out.status` — only spawn failure errors. (Exit 1 is the legitimate "differences found" case, so the correct check is `code == 0 \|\| code == 1`; there is no check at all.) A git failure parses as empty ranges. |
| §2 — attestation only | **CONFIRMED** | `EvidenceKind` appears in production code only as a struct field; all other uses are tests. `decide` copies `e.digest.clone()` verbatim into provenance and seals `claims_checked = claims.len()`, `proofs = evidence.len()`, `tests = 0`. `seal` labels `Accept` as `"established"` (protocol:511). The Worker hashes UTF-8 of decoded text (`sha256Hex`, worker.js:362), not raw blob bytes. |
| §3 — seal is process-local only | **CONFIRMED** | `Governor.chain` is `Vec<String>`, reset to `GENESIS` on restart. `verify_receipt_with` receives only `&self.receipt`, so it *cannot* compare outer struct fields — editing stored `DecisionRecord` JSON (verdict, merge, provenance) while leaving the receipt untouched passes verification. The `pl` envelope internals are outside the reviewed code, so the model's "cannot determine" hedge on the crypto itself is correct. |
| §4 — the ONE fix | **ENDORSED** | Follows directly from Hole 1 + §2: the evidence gate is the only thing between agent-supplied strings and merged code, and it verifies nothing. |

## Findings the model missed (verified from the code)

- **M1 — CanonStore "append-only" is unenforced.** `CanonStore::insert`
  (wreck-canon/src/lib.rs) is a plain `HashMap::insert`: re-inserting an
  existing id silently overwrites the rule — statement, authority,
  `forbids_contract`, and `contract_file_patterns` all replaceable. A rule
  can be neutered (set `forbids_contract: None`, empty the patterns) while
  keeping its id and active status. `from_json` loads unsigned JSON;
  duplicate ids resolve by array order (last wins). Self-supersede and
  supersession cycles are unchecked — a cycle makes `active()` return
  nothing and `to_policy()` yield an empty `Policy`, i.e. default-allow.
- **M2 — `build_candidate`'s policy check is declaration-only.**
  (wreck-graph/src/lib.rs) It checks only `v.contracts.contains(...)` and
  lacks the file-pattern measurement that `classify` and `decide` have
  (the REDTEAM A2 fix). **Caveat:** its only caller is its own test, so
  this is latent, not live — but anyone wiring it into a real path
  re-opens the A2 bypass.
- **M3 — Semantic conflicts run on declarations on every production path.**
  Symbols/invariants come from the claim via `from_scope`; `buildView`
  hardcodes them empty; the only measured-symbols implementation,
  `LocalGit::measure_symbols` (local.rs:204), is called only from
  `wreck-demo/src/main.rs:321`. An agent that omits a shared invariant
  avoids semantic conflict detection everywhere except the demo.
- **M4 — The merge lease is never wired.** `MergeLease` (lease.js) is a
  sound fencing-token design, but worker.js never imports it and never
  calls `assertHolder` — the module's own "Intended wiring" comment
  describes wiring that does not exist. Cross-isolate double-govern
  (the documented M5 residual) stands.
- **M5 — Symmetric seal, self-asserted actor.** The authority key is an
  HMAC key (wreck-wasm comment: "HMAC keys are small"); `actor` is a
  caller-supplied string in the envelope. Anyone holding the key can forge
  any actor's receipt — the seal proves key possession, never authorship.
  (The model said "some key holder signed some payload"; this is the
  sharper form.)
- **M6 — Accepts seal `PolicyResult { pass: true, rule: "default-allow" }`.**
  The sealed record literally says default-allow. Cosmetic, but the
  framing is honest about what the gate is.

## Run record

- Model: `moonshotai/kimi-k3.1-pro` via NVIDIA NIM (streaming).
- Prompt tokens: 69,574. Completion tokens: 20,408 (17,591 reasoning +
  2,817 content). Total: 89,982. Finish reason: `stop` (clean, not cut off).
- Wall time: 1,459s (~24 min). First token: 36.3s.
- Code pack sha256: `950b212b603e8e5d9f4773a6d9adf2bef2f1cb6cc60e92d935590a308ee2ce28`
- Full prompt sha256: `b36ca74abfc2fe6ba04bc9c8460c0b920f3d889c815e0fee6d7a10e1a3791aa4`
- Model content sha256: `5551835e14a483153b136a1aeda88dc9756efdd1b5ce3fc386d6c89d504321fd`
- Method note: the stock `nvidia-nim` CLI (non-streaming) failed twice
  with `RemoteDisconnected` at ~275s — the reasoning model thinks for
  minutes before responding and the connection is killed. A streaming
  client using the same vault-surrogate credential path
  (`~/workspace/wreck-teardown/nim-stream.py`) fixed it; raw SSE and the
  full reasoning trace are saved at `~/workspace/wreck-teardown/`.
- A per-crate smoke test (wreck-canon, 4,096 max tokens) burned its whole
  budget on reasoning and returned zero content — the full-pack call used
  65,536 max tokens with a reason-efficiently instruction and completed.
