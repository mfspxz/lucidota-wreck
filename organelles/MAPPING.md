# wreck — organelle mapping decisions

Decomposition reviewed 2026-10-10 under the corrected doctrine
(decompose ACTUAL capabilities; map-or-design per unit, justified).

## What the code actually does

`wreck` is a deterministic merge-governance substrate: agents file CHANGE
CLAIMs (intent + semantic claims + evidence); a deterministic governor walks
them PROPOSED → OBSERVED → CHECKED → PROVEN → ELIGIBLE → MERGED (or
REJECTED); every decision is sealed in the `lucidota-receipt/1` envelope.
The codebase's own architectural seam — stated in `wreck-adapters/src/lib.rs`
— is: **"The governor core never touches a network."** Decisions
(protocol + graph + governor + canon rules) are pure/deterministic; execution
(git workspaces, token custody, artifact pushes) has side effects. That seam
is the decomposition:

## Capability units → organelles

| Unit | Source | Organelle / ops | Decision |
|---|---|---|---|
| Deterministic merge authority: claim lifecycle, policy classification, sealed decisions, canon rule store | `wreck-protocol` (ChangeClaim::propose/validate, status machine), `wreck-graph` (classify, ChangeView, Policy), `wreck-governor` (Governor::decide/evaluate/complete_merge), `wreck-canon` (CanonStore: append-only rules, supersession) | **wreck-govern** (`wg`): `propose`, `validate_change_id`, `classify`, `decide`, `canon_insert` (Write, `wg.canon.write`), `canon_get`, `canon_active`, `canon_to_policy` — all ReadOnly except canon_insert | **Bespoke** (`wg`). Justification: the computation is a domain decision pipeline (claim → policy check → evidence gate → sealed verdict). No ref organelle adjudicates change claims. `ref-ledger-append` would record decisions but not MAKE them — the wrong half of the unit. The four crates share one indivisible decision core (the governor consumes graph views and canon policy); splitting them would manufacture shared-state organelles. |
| Substrate execution ports: local git workspaces (init/fork/commit/diff/merge) + capability-token custody | `wreck-adapters` (LocalGit, LocalMergePort, TokenCustodian) | **wreck-ports** (`wp`): `workspace_init`, `workspace_fork`, `workspace_commit`, `workspace_diff` (ReadOnly), `workspace_merge` (Write, `wp.merge`), `token_for`, `token_adjudicate`, `token_revoke` (Write, `wp.tokens`) | **Bespoke** (`wp`). Justification: git workspace execution + token custody is not any ref organelle's computation. The decision/execution split is the codebase's own seam — keeping them in one organelle would mix Proven-deterministic decisions with side-effecting execution under one authority block. |

## Why two organelles, not one or five

- Not one: decisions are Proven/ReadOnly; execution is Write/ExternalEffect
  with real side effects (git repos, token material). One authority block
  cannot honestly cover both.
- Not five (protocol/graph/governor/canon/adapters separately): protocol,
  graph, governor, and canon form one decision pipeline with a single
  data flow (claim → view → policy → verdict). The ledger-graph pilot's
  "indivisible core" argument applies: splitting them duplicates the pipeline
  or forces artificial shared state.

## Deliberate exclusions

- `wreck-demo` (demo binary + dashboard): developer demo harness, not a
  capability consumers invoke (same exclusion class as ledger-graph's bench).
- `wreck-wasm` (WASM bindings): platform binding for the WASM boundary, not
  callable in this environment; would be Tier C declared at most.
- `wreck-worker` (JS Cloudflare worker): non-Rust; would be Tier B
  surface-adapted in a follow-up. Not Tier A material.
- `wreck-adapters/src/artifacts.rs` (ArtifactsClient, ArtifactsMergePort):
  the Artifacts binding is implemented against a future paid tier ("implements
  the same traits when Workers Paid lands"); the organelle exposes the
  working `LocalGit`/`LocalMergePort` today. Documented, not hidden.

## Reference-organelle check (all 12 considered)

- `ref-ledger-append`: records; wreck-govern DECIDES. Wrong half.
- `ref-hash-seal`: the receipt envelope already exists (`lucidota-receipt/1`
  via the `pl` crate); wreck invents no new envelope and neither does this
  migration.
- `ref-kv-store`: the canon rule store is id-addressed with supersession,
  not a blind KV.
- Others: no overlap.
- Verdict: genuinely bespoke. Nothing reinvented that already existed.

## Execution facts

- wreck-govern: Proven (deterministic decisions); fs none; network none;
  secrets: sealing key via `WRECK_SEAL_KEY` env (64-hex) — never in the
  manifest, never in receipts (receipts carry hashes). Stateless apart from
  the canon rule store (`Mutex<CanonStore>`): suspend = no-op, kill = drop.
- wreck-ports: Candidate (side effects: local git, token material);
  `workspace_merge` Write/`wp.merge`, token ops Write/`wp.tokens`.
  fs: temp workspaces owned by the organelle. Suspend = no-op, kill = drop
  workspaces (declared ephemeral).
- Envelopes: 1 cpu / 512 MB / 120 s wall-time each.
- Receipts: content-addressed sha256, chained; `verify_chain` green in tests.
