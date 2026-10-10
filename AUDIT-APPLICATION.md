# Brutal-audit application — wreck (slice 2/8, 2026-10-10)

## 1. Scope + commits

Repo `~/workspace/wreck`; commits `ed888fd` (R-2 honest-bounds doc on contract_file_patterns), `3489aa0` (R-12: HJ-02 root-cause marked UNVERIFIED).

## 2. R-1

SPREE-REDTEAM-A2 RT-A2-001 "PROVEN → HARDENED" is instance-only: one failing-then-passing test (`redteam_contract_bypass::contract_policy_bypass_proven`), no dedicated re-attack wave since 2026-10-09. RT-A2-003 and RT-A2-004 DISPROVEN verdicts are instance-only for the investigated flows. HJ-03 demo PASS is instance-only (5-agent demo with hardcoded claims, 0 human merges, 5 decisions sealed).

## 3. R-2

HONEST BOUNDS doc added on `CanonRule::contract_file_patterns`: it is a HEURISTIC, not a proof of contract impact. Catches: the obvious case — an agent touching files under the listed patterns while omitting the contract from scope (RT-A2-001 class). Misses: contract violations via files outside the listed patterns (behavioral coupling), violations with no diff at all (config/env/runtime changes), an agent that declares the contract but violates its spirit. Patterns are operator-curated; coverage beyond the listed patterns is UNKNOWN, never assumed.

## 4. R-3

`oob-heads/wreck.json` created. Measured 2026-10-10: no persisted production decision chain exists in this repo. wreck-governor seals DecisionRecords chained to their parent, but persistence is the caller's job ("seed the chain at the persisted head" — caller supplies it); no decision log file exists on disk. Nothing here is called tamper-evident until a persisted decision log exists AND a head copy of it is recorded in oob-heads. Same-VM limitation documented.

## 5. R-4

Backlog triage.

- RT-A2-002 residual (local demo change_id collision: a malicious local agent could collide the hardcoded change_ids) → WONT-FIX: the local flow is a demo, not a security boundary; in production the change_id derives from Artifacts repo names, unique per namespace.
- HJ-01 (README test count undercounted 25 vs 119) → FIXED during the spree (README now says 119).
- HJ-02 (pre-existing wreck-wasm flake `m6_alloc_tests::alloc_free_roundtrip`) → FIXED during the spree (passes now).
- HJ-04 (WASM build) → accepted as documented environment configuration, not a code issue.

## 6. R-5

N/A — no signature/denylist/strip games in wreck. `contract_file_patterns` is a policy heuristic with documented bounds, not an expanding denylist.

## 7. R-6

No advisory-only detectors found. The governor's checks are gates by construction: `decide()` returns `AcceptPending` or `Decided`, `Reject` is terminal, every verdict becomes a sealed DecisionRecord. Grep over wreck-governor, wreck-graph, wreck-protocol found no warn/flag/tripwire advisory-only paths.

## 8. R-7

Tests are inline unit tests. The `redteam_contract_bypass` module is property-style (attack scenario against the public decide path; invariant: policy violation yields Reject) — labeled PROPERTY in the second sweep. Canon/graph inline tests pin demo fixtures (change-detection character). Policy documented: property expectations must never be rewritten to match behavior changes without adversarial sign-off.

## 9. R-8

`ProvenanceEntry` carries content hashes (sha256 of the canonical bytes consumed), UNSIGNED. The DecisionRecord seal is a content hash, not a signature. No signature claims exist anywhere in wreck docs; none added.

## 10. R-9

Schema frozen in Rust enums: `ChangeStatus` (Proposed, Observed, Checked, Proven, Eligible, Merged, Rejected terminal), `Verdict` (Accept, Reject, NeedsRebase, Blocked), `ProvenanceKind` (Blob, Diff, Claim, Policy). Legal transitions enforced in code (`rank` + `advance_to`). No prose-status fields; no verdict-less decision records possible by construction.

## 11. R-10

SPREE-REDTEAM-A2.md and SPREE-SUMMARY-A1.md are dated post-hoc records (archival after 2026-10-09). NOTES-orgmap-agency.md is working notes, live while the OrganEyes/agency bridge work continues.

## 12. R-11

UNKNOWN list:

- (a) current test count — README says 119, measured 2026-10-09; cannot re-measure today;
- (b) whether wreck builds at all right now — pre-existing build failure in upstream `~/workspace/organelles` organelle-host: hmac 0.12.1 removed the `NewMac` import the code still uses; breaks all wreck builds; unrelated to this pass;
- (c) HJ-02 flake root cause — UNVERIFIED;
- (d) production Worker boundary validation (event.js) — mentioned in SPREE docs but not in this tree; out of scope, UNKNOWN.

## 13. R-12

Fixed one unsourced footnote this pass: HJ-02 "Root cause was likely test parallelism or allocator state" had no evidence; now marked UNVERIFIED (commit `3489aa0`). No other probably/likely/seems footnotes found in repo docs.

## 14. Commits

`ed888fd`, `3489aa0` (both doc-only). Tests: NOT RUN this pass — pre-existing upstream build failure (see R-11b). Last measured: 119/119 green on 2026-10-09 (SPREE-SUMMARY-A1).

## 15. Wont-fix list

RT-A2-002 demo residual (demo is not a security boundary).
