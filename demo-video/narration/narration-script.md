# wreck demo narration script (2026-10-14)

Timed to the draft stills in demo-video/concat.txt. Voice: MAI_03 (Smooth), ~2.46 words/sec measured.

## 0:00 — s01_title (n01)

wreck. Don't merge agents. Merge proven state transitions. A deterministic governor for AI agents pushing code to the same repo.

## 0:10 — s02_problem1 (n02)

Git records competing states, but it never knows why an agent made a change. When agents merge on vibes, broken code ships.

## 0:24 — s03_problem2 (n03)

Picture fifty AI agents pushing to the same repo at once. The real problem isn't textual. Two agents can touch different files that implement the same invariant, and Git will happily merge them into a broken system.

## 0:42 — s03b_claim (n04)

wreck treats every change as a claim: intent, evidence, and semantic scope. A deterministic governor — written in Rust, with no language model in the decision path — classifies conflicts and issues verdicts. Every verdict is a sealed, hash-chained receipt.

## 1:00 — s03c_agents (n05)

The scenario: five agents, one authentication subsystem. Agent A hardens token validation. B shortens token expiry. C rewrites retry logic. D touches error semantics. E adds tests that depend on A. Watch the governor decide, live, on real Git.

## 1:22 — s04_term_cmd (n06)

We run the demo. cargo run, dash p, wreck-demo.

## 1:28 — s05_term_top (n07)

All five agents propose changes concurrently against the same baseline. Two canon rules are active — contracts the agents agreed to, enforced every time. The governor pulls each claim, checks its evidence, and maps its semantic scope.

## 1:46 — s06_term_table (n08)

Verdicts. A, B, and E: accepted and merged, each stamped with a seal hash. C: rejected — conflict with A. Both touch invariant auth-oh-three, overlapping edits in the same auth file. Git sees no textual conflict; wreck sees the semantic one. D: rejected. Rule canon-thirty-one forbids mutating auth error semantics, and every rejection cites its rule.

## 2:12 — s07_term_bottom (n09)

Three accepted, two rejected. Zero human merges. The full baseline log shows every merge and every change commit, all decided by the governor.

## 2:30 — s08_zero (n10)

Zero human merges. Five decisions sealed. Every verdict hash-chained, so the whole history is tamper-evident.

## 2:42 — s08b_conflict (n11)

Why was C rejected? Change C rewrites retry logic on lines thirty to forty-five. Change A hardens token validation on lines ten to forty. Both affect invariant auth-oh-three. Git sees no textual conflict — wreck sees the semantic one.

## 2:58 — s08c_policy (n12)

Why was D rejected? Change D touched auth error semantics. Canon-thirty-one: no agent may mutate auth error semantics. Policy violations are rejected with the rule cited — machine-readable, auditable.

## 3:12 — s09_dash_cards (n13)

The dashboard tells the same story at a glance. Verdict cards for every agent, seal hashes on every decision, and the conflict graph showing exactly which claims collided.

## 3:32 — s10_dash_table (n14)

The full verdict table: agent, change, verdict, and why. Every row is a sealed receipt — you can audit the entire run months later and prove exactly what the governor decided, and why.

## 3:54 — s11_scale_cmd (n15)

Five agents was the warm-up. Now fifty.

## 4:00 — s12_scale_out (n16)

Fifty agents, fifty changes, fifty decisions — all sealed, zero human merges. The governor doesn't slow down as the crowd grows; it classifies every claim against the same canon rules and the same conflict graph.

## 4:22 — s12b_rate (n17)

Twenty-two point two decisions per second. Forty-seven accepted, three rejected, zero human merges.

## 4:34 — s13_arch (n18)

The architecture. Agent forks, pushes, and the governor takes it from there: evidence, canon, conflict graph, verdict. Accept means merge plus a sealed receipt. Reject means the rule and the proof. The core is Rust — wreck protocol, graph, governor, canon, and WASM — with no language model in the decision path.

## 4:58 — s14_cf (n19)

The Cloudflare story. Artifacts provides the substrate — repos, Git, events. wreck provides the governance Artifacts deliberately leaves open. The governor core is substrate-independent: local Git today, Artifacts tomorrow, same MergePort trait. The Worker shell is already built: push events in, verdicts out, WASM decides.

## 5:22 — s15_close (n20)

Don't merge agents. Merge proven state transitions. wreck is MIT licensed — github dot com slash m f s p x z slash lucidota-wreck.

