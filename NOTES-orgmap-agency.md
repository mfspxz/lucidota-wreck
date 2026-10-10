# Notes to WRECK development — OrganEyes + agency intel (2026-10-10)

From Zack: feed the org-mapping/agency work into wreck where it overlaps. This file
is the bridge; update as results land.

## What's being built that touches wreck

**OrganEyes** (`~/workspace/organeyes/`, builder agent running — renamed from orgmap
per Zack 2026-10-10 ~11:38 PDT): deterministic 95/5 org-mapping app in Rust. Deterministic core: typed entity-graph store (nodes/edges
JSONL, controlled relationship vocabulary, 6-level confidence scale, per-edge source
attribution), query engine (reachability, leverage-chain traversal, diligence-gap
listing, neighborhood queries), hash-chained append-only finding log. The 5% AI lives
behind a trait boundary at exactly two judgment points (hypothesis scoring,
brief generation) — never in the core. CLI: ingest, query, gaps, chains, brief.

**Overlap with wreck (use or steal):**
- orgmap's confidence scale + source-per-edge is the same provenance problem as
  wreck's `Wreck-Claim:` trailers and SCOPE-01 attestation gate — consider converging
  on one attestation vocabulary.
- orgmap's leverage-chain traversal (finding→finding, e.g. `no-dmarc → amplifies →
  login-sink`) is a special case of wreck-graph's conflict/dependency graph. If
  wreck-graph gains a generic traversal query, orgmap should use it instead of its own.
- The agency graph dataset (`~/workspace/growth-agency/graph/`: 72 nodes, 88 edges,
  build-graph.py as source of truth) is a real-world dogfood dataset for wreck's
  governor: multi-source intel with conflicting confidence levels is exactly the
  merge-conflict domain. Candidate: run wreck-governor over two intel snapshots and
  demo conflict classification on them.
- Hash-chained finding log in orgmap should use the same chain format as the ledger
  (`~/ledger/`) if one exists — don't invent a second chain.

## Intel that matters for wreck's competition story (deadline Oct 14)

- The ManageStrata dossier (14 lanes, 72 atomic findings, evidence-indexed) was
  produced by deterministic pipelines + AI only at judgment points — it's a worked
  example of the 95/5 thesis wreck's pitch needs. `~/workspace/managestrata-audit/`.
- Global strata-SOTA sweep + cross-domain playbook transfer running now
  (`~/workspace/growth-agency/sota-strata-global.md`, `cross-domain.md`) — watch for
  "deterministic substrate" competitive claims from rivals to position against.

## Don't
- Don't merge orgmap into wreck unilaterally — Zack hasn't ordered that. These are
  sibling projects; convergence is his call.
- No contact with the ManageStrata founder on any channel until Zack orders it
  (applies to anything citing this intel).
