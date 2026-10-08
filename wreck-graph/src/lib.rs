//! wreck-graph: the change graph and conflict classifier.
//!
//! Nodes: changes, files, symbols, contracts, invariants.
//! Edges: modifies, affects, depends-on.
//!
//! The product thesis in one function: TEXTUAL CONFLICT != SEMANTIC CONFLICT.
//! Two agents editing the same file in disjoint regions are compatible;
//! two agents touching the same invariant from different files are not.
//! Classification is a deterministic approximation with explicit evidence —
//! never an LLM oracle.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use wreck_protocol::{ConflictKind, ConflictRef, ScopeItem};

/// One file's changed line ranges, in the *new* (head) revision numbering
/// for added lines and the *base* numbering for removed lines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub added: Vec<(u32, u32)>,   // inclusive ranges, head numbering
    pub removed: Vec<(u32, u32)>, // inclusive ranges, base numbering
}

impl FileChange {
    fn overlaps(&self, other: &FileChange) -> bool {
        if self.path != other.path {
            return false;
        }
        // Conservative: any range intersection on either side counts.
        // Removed-vs-removed overlap = both deleted the same base lines.
        // Added-vs-added overlap = both wrote the same head region.
        // Cross overlap (added vs removed) = one rewrote what the other deleted.
        ranges_overlap(&self.added, &other.added)
            || ranges_overlap(&self.removed, &other.removed)
            || ranges_overlap(&self.added, &other.removed)
            || ranges_overlap(&self.removed, &other.added)
    }
}

fn ranges_overlap(a: &[(u32, u32)], b: &[(u32, u32)]) -> bool {
    a.iter()
        .any(|(s1, e1)| b.iter().any(|(s2, e2)| s1 <= e2 && s2 <= e1))
}

/// The adapter-facing view of one change: what it touches, what it claims,
/// what it needs. Built by the substrate adapter from (base, head).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChangeView {
    pub change_id: String,
    pub files: Vec<FileChange>,
    pub symbols: Vec<String>,
    pub invariants: Vec<String>,
    pub contracts: Vec<String>,
    pub dependencies: Vec<String>,
}

impl ChangeView {
    /// Derive the mechanical parts from a protocol ChangeClaim's scope.
    pub fn from_scope(change_id: &str, scope: &[ScopeItem]) -> Self {
        let mut v = ChangeView {
            change_id: change_id.to_string(),
            ..Default::default()
        };
        for s in scope {
            match s {
                ScopeItem::File { path } => {
                    if !v.files.iter().any(|f| f.path == *path) {
                        v.files.push(FileChange {
                            path: path.clone(),
                            added: vec![],
                            removed: vec![],
                        });
                    }
                }
                ScopeItem::Symbol { name } => v.symbols.push(name.clone()),
                ScopeItem::Contract { id } => v.contracts.push(id.clone()),
            }
        }
        v
    }
}

/// A policy rule: a scope pattern no change may touch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub forbidden_contract: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub rules: Vec<PolicyRule>,
}

/// Classify the relationship between two changes. Returns conflicts found
/// (empty = compatible pair). Deterministic; order-independent.
pub fn classify(
    a: &ChangeView,
    b: &ChangeView,
    merged: &HashSet<String>,
    policy: &Policy,
) -> Vec<ConflictRef> {
    let mut out = vec![];

    // 1. Policy violations are self-conflicts: a change that touches a
    //    forbidden contract is rejected regardless of the other change.
    //    Only the SUBJECT's contracts are checked — never attribute b's
    //    violation to a (that was a real bug: E got rejected for D's sin).
    for rule in &policy.rules {
        for c in &a.contracts {
            if *c == rule.forbidden_contract {
                out.push(ConflictRef {
                    with_change: "POLICY".to_string(),
                    kind: ConflictKind::Policy,
                    detail: format!(
                        "rule {} forbids touching contract {}: {}",
                        rule.id, rule.forbidden_contract, rule.reason
                    ),
                });
            }
        }
    }

    // 2. Dependency: a declares it needs b, but b is not merged.
    //    (Checked symmetrically.)
    for (x, y) in [(a, b), (b, a)] {
        if x.dependencies.contains(&y.change_id) && !merged.contains(&y.change_id) {
            out.push(ConflictRef {
                with_change: y.change_id.clone(),
                kind: ConflictKind::Dependency,
                detail: format!("{} depends on unmerged {}", x.change_id, y.change_id),
            });
        }
    }

    // 3. Textual: overlapping edits to the same file.
    for fa in &a.files {
        for fb in &b.files {
            if fa.overlaps(fb) {
                out.push(ConflictRef {
                    with_change: b.change_id.clone(),
                    kind: ConflictKind::Textual,
                    detail: format!("overlapping edits in {}", fa.path),
                });
            }
        }
    }

    // 4. Semantic: same invariant claimed from different changes, or same
    //    symbol touched without textual overlap (e.g. different files
    //    implementing the two sides of one invariant).
    for inv in &a.invariants {
        if b.invariants.contains(inv) {
            out.push(ConflictRef {
                with_change: b.change_id.clone(),
                kind: ConflictKind::Semantic,
                detail: format!("both affect invariant {}", inv),
            });
        }
    }
    for sym in &a.symbols {
        if b.symbols.contains(sym) {
            // Only a semantic conflict if there is no textual conflict on it
            // already (avoid double counting the same underlying collision).
            let already_textual = out
                .iter()
                .any(|c| c.kind == ConflictKind::Textual && c.with_change == b.change_id);
            if !already_textual {
                out.push(ConflictRef {
                    with_change: b.change_id.clone(),
                    kind: ConflictKind::Semantic,
                    detail: format!("both modify symbol {}", sym),
                });
            }
        }
    }

    out
}

/// Greedy candidate builder: walk changes in a deterministic order,
/// accept each one that has no conflict with the already-accepted set and
/// whose dependencies are satisfied. Returns (accepted, rejected_with_reasons).
pub fn build_candidate(
    mut views: Vec<ChangeView>,
    merged: &HashSet<String>,
    policy: &Policy,
) -> (Vec<String>, Vec<(String, Vec<ConflictRef>)>) {
    views.sort_by(|a, b| a.change_id.cmp(&b.change_id));
    let mut accepted: Vec<ChangeView> = vec![];
    let mut rejected: Vec<(String, Vec<ConflictRef>)> = vec![];
    let mut merged_now: HashSet<String> = merged.clone();

    for v in views {
        let mut conflicts = vec![];
        // policy self-check (classify reports it per pair; do it once here)
        for rule in &policy.rules {
            if v.contracts.iter().any(|c| *c == rule.forbidden_contract) {
                conflicts.push(ConflictRef {
                    with_change: "POLICY".to_string(),
                    kind: ConflictKind::Policy,
                    detail: format!(
                        "rule {} forbids touching contract {}: {}",
                        rule.id, rule.forbidden_contract, rule.reason
                    ),
                });
            }
        }
        // dependency check against already-merged + accepted-this-round
        for dep in &v.dependencies {
            if !merged_now.contains(dep) {
                conflicts.push(ConflictRef {
                    with_change: dep.clone(),
                    kind: ConflictKind::Dependency,
                    detail: format!("{} depends on unmerged {}", v.change_id, dep),
                });
            }
        }
        // pairwise against accepted
        for a in &accepted {
            for c in classify(&v, a, &merged_now, &Policy::default()) {
                // skip policy dupes (already checked above)
                if c.kind != ConflictKind::Policy {
                    conflicts.push(c);
                }
            }
        }
        // dedup identical (kind, with_change, detail)
        conflicts.sort_by(|a, b| {
            (&a.kind_str(), &a.with_change, &a.detail).cmp(&(
                &b.kind_str(),
                &b.with_change,
                &b.detail,
            ))
        });
        conflicts.dedup_by(|a, b| {
            a.kind_str() == b.kind_str() && a.with_change == b.with_change && a.detail == b.detail
        });

        if conflicts.is_empty() {
            merged_now.insert(v.change_id.clone());
            accepted.push(v);
        } else {
            rejected.push((v.change_id.clone(), conflicts));
        }
    }
    (
        accepted.into_iter().map(|v| v.change_id).collect(),
        rejected,
    )
}

trait KindStr {
    fn kind_str(&self) -> &'static str;
}

impl KindStr for ConflictRef {
    fn kind_str(&self) -> &'static str {
        match self.kind {
            ConflictKind::Textual => "textual",
            ConflictKind::Semantic => "semantic",
            ConflictKind::Dependency => "dependency",
            ConflictKind::Policy => "policy",
        }
    }
}

/// Index helpers for the dashboard: who touches what.
#[derive(Debug, Default)]
pub struct ChangeIndex {
    pub by_file: HashMap<String, Vec<String>>,
    pub by_symbol: HashMap<String, Vec<String>>,
    pub by_invariant: HashMap<String, Vec<String>>,
}

impl ChangeIndex {
    pub fn build(views: &[ChangeView]) -> Self {
        let mut idx = ChangeIndex::default();
        for v in views {
            for f in &v.files {
                idx.by_file
                    .entry(f.path.clone())
                    .or_default()
                    .push(v.change_id.clone());
            }
            for s in &v.symbols {
                idx.by_symbol
                    .entry(s.clone())
                    .or_default()
                    .push(v.change_id.clone());
            }
            for i in &v.invariants {
                idx.by_invariant
                    .entry(i.clone())
                    .or_default()
                    .push(v.change_id.clone());
            }
        }
        for v in idx
            .by_file
            .values_mut()
            .chain(idx.by_symbol.values_mut())
            .chain(idx.by_invariant.values_mut())
        {
            v.sort();
            v.dedup();
        }
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fc(path: &str, added: Vec<(u32, u32)>, removed: Vec<(u32, u32)>) -> FileChange {
        FileChange {
            path: path.into(),
            added,
            removed,
        }
    }

    /// The nasty demo: five agents on the auth subsystem.
    fn demo_views() -> Vec<ChangeView> {
        vec![
            ChangeView {
                // A: token validation, lines 10-40
                change_id: "change-a".into(),
                files: vec![fc("src/auth.rs", vec![(10, 40)], vec![])],
                symbols: vec!["validate_token".into()],
                invariants: vec!["AUTH-03".into()],
                ..Default::default()
            },
            ChangeView {
                // B: token expiration, lines 50-80 — same file, disjoint
                change_id: "change-b".into(),
                files: vec![fc("src/auth.rs", vec![(50, 80)], vec![])],
                symbols: vec!["token_expiry".into()],
                invariants: vec!["AUTH-07".into()],
                ..Default::default()
            },
            ChangeView {
                // C: retry behavior, lines 30-45 — overlaps A textually
                change_id: "change-c".into(),
                files: vec![fc("src/auth.rs", vec![(30, 45)], vec![])],
                symbols: vec!["retry_policy".into()],
                invariants: vec!["AUTH-03".into()], // same invariant as A: semantic too
                ..Default::default()
            },
            ChangeView {
                // D: error handling, touches forbidden contract
                change_id: "change-d".into(),
                files: vec![fc("src/auth_err.rs", vec![(1, 20)], vec![])],
                contracts: vec!["auth.error-semantics".into()],
                ..Default::default()
            },
            ChangeView {
                // E: tests, depends on A
                change_id: "change-e".into(),
                files: vec![fc("tests/auth_test.rs", vec![(1, 60)], vec![])],
                dependencies: vec!["change-a".into()],
                ..Default::default()
            },
        ]
    }

    fn demo_policy() -> Policy {
        Policy {
            rules: vec![PolicyRule {
                id: "CANON-31".into(),
                forbidden_contract: "auth.error-semantics".into(),
                reason: "contract C-17 prohibits mutation of auth error semantics".into(),
            }],
        }
    }

    #[test]
    fn disjoint_same_file_is_compatible() {
        let v = demo_views();
        let c = classify(&v[0], &v[1], &HashSet::new(), &demo_policy());
        assert!(c.is_empty(), "A and B should be compatible, got {:?}", c);
    }

    #[test]
    fn overlapping_edits_are_textual() {
        let v = demo_views();
        let c = classify(&v[0], &v[2], &HashSet::new(), &demo_policy());
        assert!(
            c.iter().any(|x| x.kind == ConflictKind::Textual),
            "A vs C: {:?}",
            c
        );
    }

    #[test]
    fn shared_invariant_is_semantic() {
        // A and C share AUTH-03: semantic conflict on top of the textual one.
        let v = demo_views();
        let c = classify(&v[0], &v[2], &HashSet::new(), &demo_policy());
        assert!(
            c.iter().any(|x| x.kind == ConflictKind::Semantic),
            "A vs C: {:?}",
            c
        );
    }

    #[test]
    fn forbidden_contract_is_policy_violation() {
        let v = demo_views();
        let c = classify(&v[3], &v[0], &HashSet::new(), &demo_policy());
        assert!(
            c.iter().any(|x| x.kind == ConflictKind::Policy),
            "D: {:?}",
            c
        );
    }

    #[test]
    fn dependency_blocks_until_merged() {
        let v = demo_views();
        let empty = HashSet::new();
        let c = classify(&v[4], &v[0], &empty, &demo_policy());
        assert!(
            c.iter().any(|x| x.kind == ConflictKind::Dependency),
            "E vs A: {:?}",
            c
        );
        let mut merged = HashSet::new();
        merged.insert("change-a".into());
        let c2 = classify(&v[4], &v[0], &merged, &demo_policy());
        assert!(!c2.iter().any(|x| x.kind == ConflictKind::Dependency));
    }

    #[test]
    fn candidate_builder_matches_demo_script() {
        // Greedy order: a, b, c, d, e.
        // a: accept. b: accept (disjoint). c: textual+semantic vs a -> reject.
        // d: policy -> reject. e: depends on a (accepted this round) -> accept.
        let (accepted, rejected) = build_candidate(demo_views(), &HashSet::new(), &demo_policy());
        assert_eq!(accepted, vec!["change-a", "change-b", "change-e"]);
        let rids: Vec<_> = rejected.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(rids, vec!["change-c", "change-d"]);
        let c_reasons: Vec<_> = rejected[0].1.iter().map(|c| c.kind_str()).collect();
        assert!(c_reasons.contains(&"textual"));
        assert!(c_reasons.contains(&"semantic"));
        assert!(rejected[1].1.iter().any(|c| c.kind_str() == "policy"));
    }

    #[test]
    fn index_maps_who_touches_what() {
        let idx = ChangeIndex::build(&demo_views());
        assert_eq!(
            idx.by_file["src/auth.rs"],
            vec!["change-a", "change-b", "change-c"]
        );
        assert_eq!(idx.by_invariant["AUTH-03"], vec!["change-a", "change-c"]);
    }
}

/// Measured symbol extraction: parse Rust source with tree-sitter and return
/// the names of `function_item`s whose line span intersects any changed
/// range. This makes symbols MEASURED instead of agent-declared — the
/// foundation for structural (not textual) conflict classification.
pub fn enclosing_functions(source: &str, ranges: &[(u32, u32)]) -> Vec<String> {
    use streaming_iterator::StreamingIterator;
    use tree_sitter::{Parser, Query, QueryCursor};
    let mut parser = Parser::new();
    let lang = tree_sitter_rust::LANGUAGE;
    parser.set_language(&lang.into()).expect("rust grammar");
    let tree = match parser.parse(source, None) {
        Some(t) => t,
        None => return vec![],
    };
    let root = tree.root_node();
    // (function_item) @f with name field
    let query =
        Query::new(&lang.into(), "(function_item name: (identifier) @name) @f").expect("query");
    let mut cursor = QueryCursor::new();
    let mut out = vec![];
    let mut it = cursor.matches(&query, root, source.as_bytes());
    while let Some(m) = {
        it.advance();
        it.get()
    } {
        let mut name = None;
        let mut fnode = None;
        for cap in m.captures {
            let idx = cap.index as usize;
            let cap_name = query.capture_names()[idx];
            if cap_name == "name" {
                name = Some(
                    cap.node
                        .utf8_text(source.as_bytes())
                        .unwrap_or("")
                        .to_string(),
                );
            } else if cap_name == "f" {
                fnode = Some(cap.node);
            }
        }
        if let (Some(n), Some(f)) = (name, fnode) {
            let start = f.start_position().row as u32 + 1; // 1-indexed
            let end = f.end_position().row as u32 + 1;
            if ranges.iter().any(|(s, e)| *s <= end && start <= *e) {
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod structural_tests {
    use super::enclosing_functions;

    const SRC: &str = r#"fn alpha() {
    let x = 1;
}

fn beta() {
    let y = 2;
}

fn gamma() {
    let z = 3;
}
"#;

    #[test]
    fn finds_enclosing_function() {
        // lines 5-7 are beta (1-indexed)
        let syms = enclosing_functions(SRC, &[(5, 7)]);
        assert_eq!(syms, vec!["beta"]);
    }

    #[test]
    fn multiple_ranges() {
        let syms = enclosing_functions(SRC, &[(1, 3), (9, 11)]);
        assert_eq!(syms, vec!["alpha", "gamma"]);
    }

    #[test]
    fn no_overlap_no_symbols() {
        let syms = enclosing_functions(SRC, &[(4, 4)]);
        assert!(syms.is_empty());
    }

    #[test]
    fn invalid_source_is_empty() {
        let syms = enclosing_functions("fn broken((", &[(1, 1)]);
        assert!(syms.is_empty());
    }
}
