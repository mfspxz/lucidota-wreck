# Semantic-merge SOTA survey — wreck (2026-10-08)

Context: wreck's conflict classifier today = line-range overlap (git diff -U0) +
agent-declared symbols/invariants. This surveys deterministic upgrades
implementable in Rust within days. No LLM oracle anywhere — every technique
below is deterministic.

## 1. tree-sitter structural diffing

**What:** Parse both revisions with tree-sitter, diff at the AST node level
instead of text lines. Formatting-only changes vanish from the diff; moved
code is recognized as moved; changed nodes map to enclosing symbols
(function/struct/impl) mechanically.
**Adds over line ranges:** kills the largest false-positive class
(formatting/refactor noise); symbol extraction becomes *measured* instead of
agent-declared; language-agnostic (one walker, N grammars).
**Cost:** 1-2 days. Parse with `tree-sitter` + `tree-sitter-rust` crates,
walk both trees, map changed node byte-ranges to enclosing `function_item`
nodes.
**Best source:** `diffsitter` (afnanenayet/diffsitter, MIT, Rust, 14 languages
incl. Rust, actively maintained) — study its approach or shell out to it;
jscpd's `functions/grammars.rs` shows the one-walker-N-grammars pattern.
**Deterministic:** yes.

## 2. GumTree-style AST edit scripts

**What:** Falleri et al., ASE 2014 ("Fine-grained and Accurate Source Code
Differencing"). Two-phase matching: top-down greedy mapping of isomorphic
subtrees, then bottom-up container/recovery mapping. Emits node-level edit
scripts: insert / delete / update / **move**. Handles renames via similarity.
**Adds over line ranges:** move detection (a function relocated + edited no
longer looks like delete+add); rename-aware symbol tracking across revisions.
**Cost:** 2-4 days to port the core top-down/bottom-up matchers to Rust over
tree-sitter CSTs. The move-detection phase is NP-hard in general; the
practical greedy heuristic is what everyone ships.
**Best source:** the ASE 2014 paper (doi:10.1149/2642937.2642982);
gumtree-spoon-ast-diff (SpoonLabs) as the reference implementation (Java).
No maintained Rust port exists — this would be a from-paper port.
**Deterministic:** yes (greedy heuristics, fixed seeds).
**Caveat:** UW ASE'24 evaluation found structured merge tools produce *more
incorrect merges* than git on representative sets. For wreck (an
adjudicator, not an auto-merger) the lesson is: use structural matching for
*classification*, never for silent resolution.

## 3. JDime / Mastery structured 3-way merge

**What:** JDime (Lessnich et al.): structured merge with *auto-tuning* —
run cheap textual merge first, escalate to AST merge only on conflict;
up to 92x faster than pure structured merge, ~10x on average. Mastery
(Zhu et al., JSA 2023): top-down + bottom-up matching, 82.9% merge accuracy,
best of the evaluated tools, notably better on shifted code.
**Adds over line ranges:** fewer false-positive conflicts; correct handling
of code that moved between revisions.
**Cost:** 3-5 days for a simplified auto-tuned 3-way AST merge in Rust.
Prior art is Java-centric; the matching core must be re-derived against the
tree-sitter Rust grammar.
**Deterministic:** yes.
**Verdict for wreck:** overkill for the classifier. The auto-tuning *idea*
(text-first, escalate on conflict) is worth stealing for performance; the
full merge engine is not needed — wreck governs, git merges.

## 4. Interprocedural dataflow / PDG interference detection

**What:** "Detecting Semantic Conflicts using Static Analysis"
(arXiv:2310.04269). Annotate the *merged* code with per-change metadata
(which lines came from which agent), then run four lightweight
interprocedural analyses — data flow, program dependence graph, confluence,
override assignment — looking for data/control flows *between* instructions
changed by different agents. A flow from A's changed instruction to B's
changed instruction = interference = semantic conflict.
**Adds over line ranges:** exactly wreck's missing class — disjoint edits in
the same function (or across functions) coupled by dataflow. Line ranges say
compatible; the PDG says conflicting. This is the technique that turns
TEXTUAL != SEMANTIC from a slogan into a measured property.
**Cost:** 3-4 days for the practical subset: tree-sitter -> CFG -> reaching
definitions (intraprocedural) + call-graph edges for the interprocedural
overlay. Full interprocedural precision is weeks; the lightweight version is
the paper's own recommendation for a detection basis.
**Best source:** the arXiv paper; tldr-code's architecture (tree-sitter ->
AST -> CFG -> DFG with reaching-defs, all in Rust) is a working template.
**Deterministic:** yes.

## 5. Call-graph impact analysis

**What:** Build caller->callee edges per revision (tree-sitter query for
`call_expression` nodes inside each `function_item`). A change that modifies
function F conflicts-semantically with a change that modifies any caller or
callee of F, even across files. Blast-radius = transitive closure.
**Adds over line ranges:** cross-function and cross-file semantic conflicts;
answers "can another agent safely build on it?" (the demo's key question).
**Cost:** 1-2 days intra-file (trivial tree-sitter query), 3-4 days
cross-file with module/`use` resolution. Over-approximate (prefer recall) —
false positives are acceptable in an adjudicator, silent misses are not.
**Best source:** glyphtrail, tldr-code, semble_rs — all Rust, all
tree-sitter-based, all with working call-graph extractors to study.
**Deterministic:** yes.

## 6. SafeMerge (verified three-way merge)

**What:** Sousa et al., OOPSLA 2018. Relational verification that a merge
candidate is *semantically conflict-free*: if variant A changed an output
relative to base, the merge must agree with A. Implemented with dependence
analysis + SMT. Result: 39/52 real-world scenarios verified, ~15% false
positive rate, ~0.5s average.
**Adds over line ranges:** actual proof of semantic conflict-freedom, not
heuristic detection.
**Cost:** weeks (dependence analysis + SMT solver integration + Rust
frontend). Not implementable in days.
**Deterministic:** yes, but heavyweight.
**Verdict:** future work. Cite it in the demo as the direction, don't build it.

## 7. Invariant / contract-based compatibility

**What (runtime):** the `contracts` crate (x52dev/contracts, MIT/Apache-2.0,
v0.6.11, actively maintained) — `#[requires]`/`#[ensures]`/`#[invariant]`
proc-macro attributes checked as assertions at runtime. Use it in the *demo
fixture itself*: agents' claims about invariants become executable checks,
and the governor's evidence gate can demand contract-annotated test runs.
**What (static):** extract contract attributes and `assert!`/`debug_assert!`
sites via tree-sitter into the change graph as machine-readable Contract
scope items (wreck already has the `ScopeItem::Contract` variant — today it
is agent-declared; this makes it measured).
**Adds over line ranges:** invariants stop being strings agents assert and
start being artifacts the pipeline can check.
**Cost:** 1 day (crate integration + tree-sitter attribute extraction).
**Deterministic:** yes.
**Verdict:** cheap, do it — but it strengthens *evidence*, not conflict
*detection*. It does not replace 1, 4, or 5.

## 8. stale benchmark (evaluation, not a technique)

Xia et al. 2026 ("stale: a benchmark for semantic coordination"): parallel
coding agents produce patches that work alone but fail when merged;
constructs tasks where interference is near-guaranteed (97% on constructed
Django tasks) and shows a message describing the concurrent change recovers
82% of runs. Directly relevant as *evaluation methodology* for wreck's demo,
not as a detection technique. Key empirical numbers for the pitch: textual
conflicts in 6-16% of merge scenarios; a 2026 study of 33,596 agent-authored
PRs found 41.7% textual conflict in cross-agent concurrent pairs.

---

## Ranked recommendation (value / cost)

1. **tree-sitter structural diffing** (1-2d) — highest value per day. Kills
   formatting-noise false positives, makes symbol extraction measured,
   language-agnostic, and is the foundation 4 and 5 build on. Do first.
2. **Dataflow interference via reaching-definitions** (3-4d) — the one
   technique that detects the disjoint-but-coupled semantic conflict class.
   This is wreck's thesis made measurable. Do second, reusing the
   tree-sitter parse from (1).
3. **Call-graph impact edges** (2d on top of 1) — cross-function/file
   conflicts and blast-radius for the dashboard. Natural extension of (2)'s
   infrastructure; fold into the same workstream.

Honorable mention: `contracts`-crate integration (1d) for executable
invariants in the demo fixture — cheap credibility for the evidence story.

Explicitly deferred: GumTree move detection (diminishing returns once (1)
exists), JDime/Mastery full merge engines (wreck adjudicates, doesn't
auto-merge), SafeMerge (weeks, not days).
