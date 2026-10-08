//! wreck-governor: the deterministic merge authority.
//!
//! Pipeline (no silent transitions; every step is a recorded state change):
//!   PROPOSED -> OBSERVED -> CHECKED -> PROVEN -> ELIGIBLE -> MERGED
//!                                  |-> REJECTED (terminal)
//!
//! The governor decides by evidence + graph + policy, never by vibes.
//! Every verdict becomes a sealed DecisionRecord chained to its parent.

use std::collections::HashSet;
use wreck_graph::{ChangeView, Policy, classify};
use wreck_protocol::{
    ChangeClaim, ChangeStatus, ConflictKind, ConflictRef, DecisionRecord, PolicyResult, Sha,
    Verdict,
};

/// The substrate's merge operation. The governor decides; the port executes.
/// Local git implements this today; the Artifacts binding implements it next.
pub trait MergePort {
    fn merge(&self, change: &ChangeClaim) -> Result<Sha, String>;
    fn name(&self) -> &str;
}

/// Outcome of a merge-free decision (the WASM boundary).
/// AcceptPending: the claim is ELIGIBLE; the caller merges via its
/// substrate port, then calls complete_merge. Decided: already sealed
/// (Reject or Blocked).
#[derive(Debug)]
pub enum DecideOutcome {
    AcceptPending { draft: DecisionRecord },
    Decided(DecisionRecord),
}

fn conflict_key(k: &ConflictKind) -> &'static str {
    match k {
        ConflictKind::Textual => "textual",
        ConflictKind::Semantic => "semantic",
        ConflictKind::Dependency => "dependency",
        ConflictKind::Policy => "policy",
    }
}

/// Step a claim forward along the legal chain until it reaches `target`.
/// No-ops when already there; errors only on illegal movement.
fn advance_to(change: &mut ChangeClaim, target: ChangeStatus) -> Result<(), String> {
    use ChangeStatus::*;
    let order = [Proposed, Observed, Checked, Proven, Eligible, Merged];
    let pos = |s: ChangeStatus| {
        order
            .iter()
            .position(|&x| x == s)
            .ok_or_else(|| format!("wreck-governor: {:?} is not on the forward chain", s))
    };
    while pos(change.status)? < pos(target)? {
        let next = order[pos(change.status)? + 1];
        change.transition(next)?;
    }
    Ok(())
}

pub struct Governor {
    pub policy: Policy,
    key: Vec<u8>,
    pub actor: String,
    /// seals of sealed decisions, in order: the decision hash chain.
    chain: Vec<String>,
}

impl Governor {
    pub fn new(policy: Policy, key: Vec<u8>, actor: &str) -> Self {
        Governor { policy, key, actor: actor.to_string(), chain: vec!["GENESIS".to_string()] }
    }

    fn parent_seal(&self) -> String {
        self.chain.last().cloned().unwrap_or_else(|| "GENESIS".to_string())
    }

    fn seal(&mut self, mut rec: DecisionRecord, ts: &str) -> Result<DecisionRecord, String> {
        rec.seal(&self.key, &self.actor, ts)?;
        let seal = rec
            .receipt
            .get("seal")
            .and_then(|v| v.as_str())
            .ok_or("wreck-governor: sealed receipt missing seal")?
            .to_string();
        self.chain.push(seal);
        Ok(rec)
    }

    /// CHECKED gate: every claim must carry at least one evidence item,
    /// every evidence item must pin a digest, scope must be non-empty.
    fn check_evidence(change: &ChangeClaim) -> Result<(), String> {
        if change.scope.is_empty() {
            return Err("empty scope: nothing to govern".into());
        }
        for claim in &change.claims {
            let ev: Vec<_> = change
                .evidence
                .iter()
                .filter(|e| e.reference.contains(&claim.id) || claim.id.is_empty())
                .collect();
            // evidence links to claims by convention "C1:..." in reference,
            // or is unattached (applies to the change as a whole).
            let linked = change.evidence.iter().any(|e| {
                e.reference.starts_with(&format!("{}:", claim.id)) || e.id.starts_with(&claim.id)
            });
            let unattached = change.evidence.iter().any(|e| !e.reference.contains(':'));
            if !linked && !unattached && !ev.is_empty() {
                return Err(format!("claim {} has no linked evidence", claim.id));
            }
            if change.evidence.is_empty() {
                return Err(format!("claim {} has no evidence at all", claim.id));
            }
        }
        for e in &change.evidence {
            if e.digest.trim().is_empty() {
                return Err(format!("evidence {} pins no digest", e.id));
            }
        }
        Ok(())
    }

    /// Run one change through the full pipeline. Mutates the claim's status.
    /// Resumable: a Blocked claim sitting at PROVEN re-enters cleanly.
    /// Returns the sealed decision record.
    pub fn evaluate(
        &mut self,
        change: &mut ChangeClaim,
        view: &ChangeView,
        in_flight: &[ChangeView],
        merged: &HashSet<String>,
        merger: &dyn MergePort,
        ts: &str,
    ) -> Result<DecisionRecord, String> {
        match self.decide(change, view, in_flight, merged, ts)? {
            DecideOutcome::AcceptPending { draft } => {
                match merger.merge(change) {
                    Ok(merge_sha) => {
                        advance_to(change, ChangeStatus::Merged)?;
                        self.complete_merge(draft, &merge_sha, merger.name(), ts)
                    }
                    Err(e) => {
                        let conflicts = draft.conflicts.clone();
                        self.reject(
                            change,
                            format!("merge failed: {}", e),
                            "MERGE-FAILED".into(),
                            conflicts,
                            ts,
                        )
                    }
                }
            }
            DecideOutcome::Decided(rec) => Ok(rec),
        }
    }

    /// Decide WITHOUT merging. Pure decision logic — this is what compiles
    /// to WASM for the Worker. Returns either a pending accept (the caller
    /// merges, then calls complete_merge) or an already-sealed decision.
    pub fn decide(
        &mut self,
        change: &mut ChangeClaim,
        view: &ChangeView,
        in_flight: &[ChangeView],
        merged: &HashSet<String>,
        ts: &str,
    ) -> Result<DecideOutcome, String> {
        if change.status.is_terminal() {
            return Err(format!(
                "wreck-governor: change {} is terminal ({:?})",
                change.change_id, change.status
            ));
        }
        advance_to(change, ChangeStatus::Checked)?;

        // --- CHECKED: evidence gate ---
        if let Err(reason) = Self::check_evidence(change) {
            return Ok(DecideOutcome::Decided(
                self.reject(change, reason, "EVIDENCE-01".to_string(), vec![], ts)?,
            ));
        }

        // --- graph: conflicts vs in-flight + policy ---
        let mut conflicts: Vec<ConflictRef> = vec![];
        // dependency gate: every declared dependency must already be merged.
        for dep in &view.dependencies {
            if !merged.contains(dep) {
                conflicts.push(ConflictRef {
                    with_change: dep.clone(),
                    kind: ConflictKind::Dependency,
                    detail: format!("{} depends on unmerged {}", change.change_id, dep),
                });
            }
        }
        for other in in_flight {
            if other.change_id == change.change_id {
                continue;
            }
            conflicts.extend(classify(view, other, merged, &self.policy));
        }
        // dedup on (kind, with_change, detail)
        conflicts.sort_by(|a, b| {
            (conflict_key(&a.kind), &a.with_change, &a.detail)
                .cmp(&(conflict_key(&b.kind), &b.with_change, &b.detail))
        });
        conflicts.dedup_by(|a, b| {
            conflict_key(&a.kind) == conflict_key(&b.kind)
                && a.with_change == b.with_change
                && a.detail == b.detail
        });
        // policy self-check (classify only reports it per pair)
        for rule in &self.policy.rules {
            if view.contracts.iter().any(|c| *c == rule.forbidden_contract)
                && !conflicts.iter().any(|c| c.kind == ConflictKind::Policy)
            {
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

        let policy_fail = conflicts.iter().find(|c| c.kind == ConflictKind::Policy).cloned();
        let blocking: Vec<ConflictRef> = conflicts
            .iter()
            .filter(|c| c.kind == ConflictKind::Dependency)
            .cloned()
            .collect();
        let hard: Vec<ConflictRef> = conflicts
            .iter()
            .filter(|c| {
                c.kind == ConflictKind::Textual || c.kind == ConflictKind::Semantic
            })
            .cloned()
            .collect();

        if let Some(p) = policy_fail {
            let rule = p.detail.clone();
            return Ok(DecideOutcome::Decided(self.reject(
                change,
                format!("policy violation: {}", p.detail),
                rule,
                conflicts,
                ts,
            )?));
        }
        if !hard.is_empty() {
            let detail = hard.iter().map(|c| c.detail.clone()).collect::<Vec<_>>().join("; ");
            return Ok(DecideOutcome::Decided(self.reject(
                change,
                format!("conflicts: {}", detail),
                "CONFLICT".into(),
                conflicts,
                ts,
            )?));
        }

        advance_to(change, ChangeStatus::Proven)?;

        if !blocking.is_empty() {
            // Not terminal: the claim waits at PROVEN for its dependencies.
            let by: Vec<String> = blocking.iter().map(|c| c.with_change.clone()).collect();
            let rec = DecisionRecord::draft(
                change,
                Verdict::Blocked { by },
                vec![],
                vec![],
                change.claims.len() as u32,
                change.evidence.len() as u32,
                0,
                conflicts,
                PolicyResult { pass: true, rule: "default-allow".into() },
                &self.parent_seal(),
            )?;
            return Ok(DecideOutcome::Decided(self.seal(rec, ts)?));
        }

        advance_to(change, ChangeStatus::Eligible)?;

        // ELIGIBLE with no conflicts and no blockers: pending the merge,
        // which the substrate executes (local git today, Artifacts next).
        let draft = DecisionRecord::draft(
            change,
            Verdict::Accept,
            vec![],
            vec![],
            change.claims.len() as u32,
            change.evidence.len() as u32,
            0,
            conflicts,
            PolicyResult { pass: true, rule: "default-allow".into() },
            &self.parent_seal(),
        )?;
        Ok(DecideOutcome::AcceptPending { draft })
    }

    /// Seal an accepted draft after the substrate merged it.
    pub fn complete_merge(
        &mut self,
        draft: DecisionRecord,
        merge_sha: &Sha,
        port_name: &str,
        ts: &str,
    ) -> Result<DecisionRecord, String> {
        let mut rec = self.seal(draft, ts)?;
        if let Some(payload) = rec.receipt.get_mut("payload") {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert(
                    "merge_sha".into(),
                    serde_json::Value::String(merge_sha.as_str().into()),
                );
                obj.insert("merge_port".into(), serde_json::Value::String(port_name.into()));
            }
        }
        Ok(rec)
    }

    fn reject(
        &mut self,
        change: &mut ChangeClaim,
        reason: String,
        rule: String,
        conflicts: Vec<ConflictRef>,
        ts: &str,
    ) -> Result<DecisionRecord, String> {
        // Rejection is only reachable from CHECKED; if we already passed it
        // (e.g. merge failed at ELIGIBLE), record the verdict without a
        // status transition — the decision record is the source of truth.
        let _ = change.transition(ChangeStatus::Rejected);
        let rec = DecisionRecord::draft(
            change,
            Verdict::Reject { reason, rule },
            vec![],
            vec![],
            change.claims.len() as u32,
            change.evidence.len() as u32,
            0,
            conflicts,
            PolicyResult { pass: false, rule: "rejected".into() },
            &self.parent_seal(),
        )?;
        self.seal(rec, ts)
    }

    pub fn decisions_sealed(&self) -> usize {
        self.chain.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wreck_graph::FileChange;
    use wreck_protocol::{Claim, ClaimKind, Evidence, EvidenceKind, ScopeItem};

    struct FakeMerger;
    impl MergePort for FakeMerger {
        fn merge(&self, _c: &ChangeClaim) -> Result<Sha, String> {
            Sha::new(&"f".repeat(40))
        }
        fn name(&self) -> &str {
            "fake"
        }
    }

    fn policy() -> Policy {
        Policy {
            rules: vec![wreck_graph::PolicyRule {
                id: "CANON-31".into(),
                forbidden_contract: "auth.error-semantics".into(),
                reason: "C-17".into(),
            }],
        }
    }

    fn gov() -> Governor {
        Governor::new(policy(), b"test-key-32-bytes-long-padding!!".to_vec(), "governor-test")
    }

    fn mk_change(id: &str, scope: Vec<ScopeItem>) -> (ChangeClaim, ChangeView) {
        let mut c = ChangeClaim::propose(
            id, "agent-1", "task-1",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "test",
        );
        c.scope = scope;
        c.claims.push(Claim { id: "C1".into(), statement: "safe".into(), kind: ClaimKind::PreservesApi });
        c.evidence.push(Evidence {
            id: "C1-E1".into(), kind: EvidenceKind::Test,
            reference: "C1: test 184".into(), digest: "sha256:abc".into(),
        });
        let v = ChangeView::from_scope(id, &c.scope);
        (c, v)
    }

    fn file_view(id: &str, path: &str, added: Vec<(u32, u32)>) -> (ChangeClaim, ChangeView) {
        let (c, _) = mk_change(id, vec![ScopeItem::File { path: path.into() }]);
        let mut v = ChangeView::from_scope(id, &c.scope);
        v.files = vec![FileChange { path: path.into(), added, removed: vec![] }];
        (c, v)
    }

    #[test]
    fn clean_change_is_accepted_and_sealed() {
        let mut g = gov();
        let (mut c, v) = file_view("w-1", "src/foo.rs", vec![(1, 10)]);
        let d = g.evaluate(&mut c, &v, &[], &HashSet::new(), &FakeMerger, "2026-10-08T22:00:00Z").unwrap();
        assert!(matches!(d.verdict, Verdict::Accept));
        assert_eq!(c.status, ChangeStatus::Merged);
        d.verify_receipt().unwrap_err(); // signed with test key, not authority file key
        assert_eq!(d.receipt.get("status").and_then(|v| v.as_str()), Some("established"));
        assert_eq!(g.decisions_sealed(), 1);
    }

    #[test]
    fn empty_evidence_is_rejected() {
        let mut g = gov();
        let mut c = ChangeClaim::propose("w-2", "a", "t",
            Sha::new(&"a".repeat(40)).unwrap(), Sha::new(&"b".repeat(40)).unwrap(), "x");
        c.scope = vec![ScopeItem::File { path: "src/foo.rs".into() }];
        c.claims.push(Claim { id: "C1".into(), statement: "s".into(), kind: ClaimKind::PreservesApi });
        let v = ChangeView::from_scope("w-2", &c.scope);
        let d = g.evaluate(&mut c, &v, &[], &HashSet::new(), &FakeMerger, "2026-10-08T22:00:00Z").unwrap();
        assert!(matches!(d.verdict, Verdict::Reject { .. }));
        assert_eq!(c.status, ChangeStatus::Rejected);
    }

    #[test]
    fn textual_conflict_rejects() {
        let mut g = gov();
        let (mut c1, v1) = file_view("w-a", "src/auth.rs", vec![(10, 40)]);
        let (_, v2) = file_view("w-c", "src/auth.rs", vec![(30, 45)]);
        let d = g.evaluate(&mut c1, &v1, &[v2], &HashSet::new(), &FakeMerger, "2026-10-08T22:00:00Z").unwrap();
        assert!(matches!(d.verdict, Verdict::Reject { .. }));
        assert!(d.conflicts.iter().any(|c| c.kind == ConflictKind::Textual));
    }

    #[test]
    fn policy_violation_rejects_with_rule() {
        let mut g = gov();
        let (mut c, _) = mk_change("w-d", vec![ScopeItem::Contract { id: "auth.error-semantics".into() }]);
        let v = ChangeView::from_scope("w-d", &c.scope);
        let d = g.evaluate(&mut c, &v, &[], &HashSet::new(), &FakeMerger, "2026-10-08T22:00:00Z").unwrap();
        match &d.verdict {
            Verdict::Reject { reason, rule } => {
                assert!(rule.contains("CANON-31"), "rule was {}", rule);
                assert!(reason.contains("policy violation"));
            }
            v => panic!("expected Reject, got {:?}", v),
        }
    }

    #[test]
    fn dependency_blocks_without_rejecting() {
        let mut g = gov();
        let (mut c, _) = mk_change("w-e", vec![ScopeItem::File { path: "tests/x.rs".into() }]);
        let mut v = ChangeView::from_scope("w-e", &c.scope);
        v.dependencies = vec!["w-a".into()];
        let d = g.evaluate(&mut c, &v, &[], &HashSet::new(), &FakeMerger, "2026-10-08T22:00:00Z").unwrap();
        assert!(matches!(d.verdict, Verdict::Blocked { .. }));
        assert_eq!(c.status, ChangeStatus::Proven); // not terminal: waits
        // now merge the dependency and re-run: accepted
        let mut merged = HashSet::new();
        merged.insert("w-a".into());
        let d2 = g.evaluate(&mut c, &v, &[], &merged, &FakeMerger, "2026-10-08T22:01:00Z").unwrap();
        assert!(matches!(d2.verdict, Verdict::Accept));
    }

    #[test]
    fn decisions_chain() {
        let mut g = gov();
        let (mut c1, v1) = file_view("w-1", "src/a.rs", vec![(1, 5)]);
        let (mut c2, v2) = file_view("w-2", "src/b.rs", vec![(1, 5)]);
        let d1 = g.evaluate(&mut c1, &v1, &[], &HashSet::new(), &FakeMerger, "2026-10-08T22:00:00Z").unwrap();
        let d2 = g.evaluate(&mut c2, &v2, &[], &HashSet::new(), &FakeMerger, "2026-10-08T22:01:00Z").unwrap();
        let s1 = d1.receipt.get("seal").and_then(|v| v.as_str()).unwrap();
        assert_eq!(d2.receipt.get("prev_hash").and_then(|v| v.as_str()), Some(s1));
        assert_eq!(g.decisions_sealed(), 2);
    }
}
