# wreck — Demo Script (5-minute video)

## The one-liner

> Git records competing states. It doesn't know why an agent made a change.
> Don't merge agents. Merge proven state transitions.

## The problem (30s)

When 50 AI agents push to the same repo concurrently, GitHub gives you
merge conflicts. But the real problem isn't textual — it's **semantic**:
two agents can touch different files that implement the same invariant,
and Git will happily merge them into a broken system.

wreck is the governance layer: every change is a **claim** with intent,
evidence, and semantic scope. A deterministic governor (Rust, no LLM
in the decision path) classifies conflicts and issues verdicts.
Every verdict is a sealed, hash-chained receipt.

## The demo (3 min)

### 1. The 5-agent nasty scenario

```sh
cargo run -p wreck-demo
```

Five agents work concurrently on "improve authentication":

| Agent | Change | Verdict | Why |
|-------|--------|---------|-----|
| A | Token validation (lines 10-40) | ✅ ACCEPT | Clean, no conflicts |
| B | Token expiry (lines 45-75) | ✅ ACCEPT | Same file, disjoint regions |
| C | Retry logic (lines 30-45) | ❌ REJECT | Textual + semantic vs A |
| D | Error semantics | ❌ REJECT | Policy: CANON-31 forbids |
| E | Tests (depends on A) | ✅ ACCEPT | After A merges |

**Key line:** "0 human merges. 5 decisions sealed."

### 2. The dashboard

Open `/tmp/wreck-demo/dashboard.html`:
- Change graph: agents × artifacts, green/red
- Every verdict with machine-readable reason
- Seal hashes, hash-chained

### 3. The scale proof

```sh
cargo run -p wreck-demo --bin wreck-scale 50
```

50 agents, 8+ decisions/sec, 0 human merges.

## The architecture (1 min)

```
Agent → fork → push → [Governor: evidence → CANON → conflict graph → verdict]
                                                      → ACCEPT → merge → sealed receipt
                                                      → REJECT → rule + proof
```

- **wreck-protocol**: change claims, forward-only status machine
- **wreck-graph**: conflict classifier (textual/semantic/dependency/policy)
- **wreck-governor**: the merge authority
- **wreck-canon**: why-rules with provenance
- **wreck-wasm**: governor as WASM for Cloudflare Workers

## The Cloudflare story (30s)

Artifacts provides the substrate (repos, Git, events).
wreck provides the governance Artifacts deliberately leaves open.
The governor core is substrate-independent: local git today,
Artifacts tomorrow, same `MergePort` trait.

## Close

> "Don't merge agents. Merge proven state transitions."
