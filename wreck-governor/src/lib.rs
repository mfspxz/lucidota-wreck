//! wreck-governor: the deterministic merge authority.
//!
//! Pipeline (no silent transitions; every step is a recorded state change):
//!   PROPOSED -> OBSERVED -> CHECKED -> PROVEN -> ELIGIBLE -> MERGED
//!                                  |-> REJECTED (terminal)
//!
//! The governor decides by evidence + graph + policy, never by vibes.
//! Every verdict becomes a sealed DecisionRecord chained to its parent.

use std::collections::HashSet;
use wreck_graph::{classify, ChangeView, Policy};
use wreck_protocol::{
    ChangeClaim, ChangeStatus, ConflictKind, ConflictRef, DecisionRecord, PolicyResult,
    ProvenanceEntry, ProvenanceKind, Sha, Verdict,
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
        Governor {
            policy,
            key,
            actor: actor.to_string(),
            chain: vec!["GENESIS".to_string()],
        }
    }

    /// For the WASM complete path: seed the chain at the persisted head
    /// (D1) so seal() enforces continuity against the real head, not GENESIS.
    /// The caller MUST supply the persisted head; see run_complete.
    pub fn with_head(policy: Policy, key: Vec<u8>, actor: &str, head: &str) -> Self {
        Governor {
            policy,
            key,
            actor: actor.to_string(),
            chain: vec![head.to_string()],
        }
    }

    fn parent_seal(&self) -> String {
        self.chain
            .last()
            .cloned()
            .unwrap_or_else(|| "GENESIS".to_string())
    }

    fn seal(&mut self, mut rec: DecisionRecord, ts: &str) -> Result<DecisionRecord, String> {
        // M3 (cycle-06 audit): chain continuity — the record must extend
        // the CURRENT head. A draft built on a stale head (concurrent
        // decide, replayed event) is refused: no forks, no replays.
        if rec.parent_decision != self.parent_seal() {
            return Err(format!(
                "wreck-governor: refusing to seal: parent_decision {:?} != chain head {:?} (fork or replay)",
                rec.parent_decision,
                self.parent_seal()
            ));
        }
        rec.seal(&self.key, &self.actor, ts)?;
        // Fail-closed: every sealed decision verifies under our own key
        // before it leaves the governor — accepted merges included.
        rec.verify_receipt_with(&self.key)?;
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

    /// CHECKED gate: scope attestation. Every file the diff actually
    /// touched must be in the agent's declared scope. An agent that hides
    /// changed files from its claim is rejected — the governor measures,
    /// the agent declares, and the two must agree.
    fn check_scope_attestation(change: &ChangeClaim, view: &ChangeView) -> Result<(), String> {
        use wreck_protocol::ScopeItem;
        let declared: std::collections::HashSet<&str> = change
            .scope
            .iter()
            .filter_map(|s| match s {
                ScopeItem::File { path } => Some(path.as_str()),
                _ => None,
            })
            .collect();
        // No declared files = no attestation to check (measured diff rules).
        if declared.is_empty() {
            return Ok(());
        }
        for f in &view.files {
            if !declared.contains(f.path.as_str()) {
                return Err(format!(
                    "scope attestation failed: measured change to {} not in declared scope",
                    f.path
                ));
            }
        }
        Ok(())
    }

    /// Build one provenance entry for an input the governor consumed.
    /// Callers pass the content hash of the exact bytes read.
    fn prov_entry(kind: ProvenanceKind, id: &str, hash: String) -> ProvenanceEntry {
        ProvenanceEntry {
            kind,
            id: id.to_string(),
            hash,
        }
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
            DecideOutcome::AcceptPending { draft } => match merger.merge(change) {
                Ok(merge_sha) => {
                    advance_to(change, ChangeStatus::Merged)?;
                    self.complete_merge(draft, &merge_sha, merger.name(), ts)
                }
                Err(e) => {
                    let conflicts = draft.conflicts.clone();
                    // The draft already carries decide-time provenance;
                    // the merge-failed rejection inherits it rather than
                    // rebuilding (same inputs were consumed).
                    let prov = draft.provenance.clone();
                    self.reject(
                        change,
                        format!("merge failed: {}", e),
                        "MERGE-FAILED".into(),
                        conflicts,
                        ts,
                        prov,
                    )
                }
            },
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

        // --- provenance: derived-from tracking (cycle-12, mirrors the
        // Cloudflare OS observation log — taint follows the data). Entries
        // are recorded AT READ TIME, only for inputs the governor actually
        // consumed: never from agent declarations (the claim carries no
        // provenance field, and nothing agent-written is parsed for
        // entries). An early reject's provenance therefore contains the
        // claim and evidence but no diffs or policy rules it never reached.
        // The claim entry binds the as-given bytes (status before advance).
        let mut prov: Vec<ProvenanceEntry> = vec![Self::prov_entry(
            ProvenanceKind::Claim,
            &change.change_id,
            wreck_protocol::content_hash(change)?,
        )];
        for e in &change.evidence {
            // evidence entry hash = the pinned digest the governor required
            // and consumed (non-empty enforced by check_evidence).
            prov.push(ProvenanceEntry {
                kind: ProvenanceKind::Claim,
                id: e.id.clone(),
                hash: e.digest.clone(),
            });
        }

        advance_to(change, ChangeStatus::Checked)?;

        // --- CHECKED: evidence gate ---
        if let Err(reason) = Self::check_evidence(change) {
            return Ok(DecideOutcome::Decided(self.reject(
                change,
                reason,
                "EVIDENCE-01".to_string(),
                vec![],
                ts,
                prov,
            )?));
        }

        // The scope-attestation check reads the measured view's files, so
        // the view entry is recorded BEFORE it runs.
        prov.push(Self::prov_entry(
            ProvenanceKind::Diff,
            &view.change_id,
            wreck_protocol::content_hash(view)?,
        ));

        // --- CHECKED: scope attestation (measured vs declared) ---
        if let Err(reason) = Self::check_scope_attestation(change, view) {
            return Ok(DecideOutcome::Decided(self.reject(
                change,
                reason,
                "SCOPE-01".to_string(),
                vec![],
                ts,
                prov,
            )?));
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
            // Record the view at classification time — a skipped (self)
            // view is never recorded.
            prov.push(Self::prov_entry(
                ProvenanceKind::Diff,
                &other.change_id,
                wreck_protocol::content_hash(other)?,
            ));
            conflicts.extend(classify(view, other, merged, &self.policy));
        }
        // dedup on (kind, with_change, detail)
        conflicts.sort_by(|a, b| {
            (conflict_key(&a.kind), &a.with_change, &a.detail).cmp(&(
                conflict_key(&b.kind),
                &b.with_change,
                &b.detail,
            ))
        });
        conflicts.dedup_by(|a, b| {
            conflict_key(&a.kind) == conflict_key(&b.kind)
                && a.with_change == b.with_change
                && a.detail == b.detail
        });
        // policy self-check (classify only reports it per pair)
        for rule in &self.policy.rules {
            // The rule is evaluated here, so its provenance is recorded
            // here — every rule the loop touches was read.
            prov.push(Self::prov_entry(
                ProvenanceKind::Policy,
                &rule.id,
                wreck_protocol::content_hash(rule)?,
            ));
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

        let policy_fail = conflicts
            .iter()
            .find(|c| c.kind == ConflictKind::Policy)
            .cloned();
        let blocking: Vec<ConflictRef> = conflicts
            .iter()
            .filter(|c| c.kind == ConflictKind::Dependency)
            .cloned()
            .collect();
        let hard: Vec<ConflictRef> = conflicts
            .iter()
            .filter(|c| c.kind == ConflictKind::Textual || c.kind == ConflictKind::Semantic)
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
                prov,
            )?));
        }
        if !hard.is_empty() {
            let detail = hard
                .iter()
                .map(|c| c.detail.clone())
                .collect::<Vec<_>>()
                .join("; ");
            return Ok(DecideOutcome::Decided(self.reject(
                change,
                format!("conflicts: {}", detail),
                "CONFLICT".into(),
                conflicts,
                ts,
                prov,
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
                PolicyResult {
                    pass: true,
                    rule: "default-allow".into(),
                },
                &self.parent_seal(),
            )?;
            let rec = rec.with_provenance(prov)?;
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
            PolicyResult {
                pass: true,
                rule: "default-allow".into(),
            },
            &self.parent_seal(),
        )?;
        let draft = draft.with_provenance(prov)?;
        Ok(DecideOutcome::AcceptPending { draft })
    }

    /// Seal an accepted draft after the substrate merged it.
    ///
    /// The merge outcome is part of the DECISION: it is attached via
    /// `with_merge` (which re-hashes) BEFORE sealing. The old code sealed
    /// first and then mutated `receipt.payload`, invalidating
    /// payload_hash and the seal — that shape is now impossible: the
    /// stale-hash guard in DecisionRecord::seal refuses it.
    pub fn complete_merge(
        &mut self,
        draft: DecisionRecord,
        merge_sha: &Sha,
        port_name: &str,
        ts: &str,
    ) -> Result<DecisionRecord, String> {
        let rec = draft.with_merge(merge_sha.clone(), port_name)?;
        self.seal(rec, ts)
    }

    fn reject(
        &mut self,
        change: &mut ChangeClaim,
        reason: String,
        rule: String,
        conflicts: Vec<ConflictRef>,
        ts: &str,
        prov: Vec<ProvenanceEntry>,
    ) -> Result<DecisionRecord, String> {
        // Rejection is only reachable from CHECKED; if we already passed it
        // (e.g. merge failed at ELIGIBLE), record the verdict without a
        // status transition — the decision record is the source of truth.
        //
        // L-F (cycle-11): surface the transition error, never swallow it.
        // A failed transition means the claim is already terminal — the
        // verdict still seals, but the anomaly is sealed INTO the record
        // instead of disappearing (status/verdict skew otherwise).
        let mut reason = reason;
        if let Err(e) = change.transition(ChangeStatus::Rejected) {
            reason = format!("{} [transition skipped: {}]", reason, e);
        }
        let rec = DecisionRecord::draft(
            change,
            Verdict::Reject { reason, rule },
            vec![],
            vec![],
            change.claims.len() as u32,
            change.evidence.len() as u32,
            0,
            conflicts,
            PolicyResult {
                pass: false,
                rule: "rejected".into(),
            },
            &self.parent_seal(),
        )?;
        // Provenance is sealed with the rejection, exactly as with
        // accepts: the record states what the verdict was derived from.
        let rec = rec.with_provenance(prov)?;
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

    fn gov() -> (Governor, Vec<u8>) {
        let key = b"test-key-32-bytes-long-padding!!".to_vec();
        (Governor::new(policy(), key.clone(), "governor-test"), key)
    }

    fn mk_change(id: &str, scope: Vec<ScopeItem>) -> (ChangeClaim, ChangeView) {
        let mut c = ChangeClaim::propose(
            id,
            "agent-1",
            "task-1",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "test",
        )
        .expect("valid change_id");
        c.scope = scope;
        c.claims.push(Claim {
            id: "C1".into(),
            statement: "safe".into(),
            kind: ClaimKind::PreservesApi,
        });
        c.evidence.push(Evidence {
            id: "C1-E1".into(),
            kind: EvidenceKind::Test,
            reference: "C1: test 184".into(),
            digest: "sha256:abc".into(),
        });
        let v = ChangeView::from_scope(id, &c.scope);
        (c, v)
    }

    fn file_view(id: &str, path: &str, added: Vec<(u32, u32)>) -> (ChangeClaim, ChangeView) {
        let (c, _) = mk_change(id, vec![ScopeItem::File { path: path.into() }]);
        let mut v = ChangeView::from_scope(id, &c.scope);
        v.files = vec![FileChange {
            path: path.into(),
            added,
            removed: vec![],
        }];
        (c, v)
    }

    #[test]
    fn clean_change_is_accepted_and_sealed() {
        let (mut g, key) = gov();
        let (mut c, v) = file_view("w-1", "src/foo.rs", vec![(1, 10)]);
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Accept));
        assert_eq!(c.status, ChangeStatus::Merged);
        // every returned decision verifies under the injected key —
        // accepted merges included (no more unwrap_err on file keys)
        d.verify_receipt_with(&key)
            .expect("accepted decision must verify");
        assert_eq!(
            d.receipt.get("status").and_then(|v| v.as_str()),
            Some("established")
        );
        // the merge outcome is sealed INSIDE the payload, not bolted on after
        let payload = d
            .receipt
            .get("payload")
            .and_then(|v| v.as_object())
            .unwrap();
        assert_eq!(
            payload
                .get("merge")
                .and_then(|m| m.get("port"))
                .and_then(|v| v.as_str()),
            Some("fake")
        );
        assert!(payload
            .get("merge")
            .and_then(|m| m.get("merge_sha"))
            .and_then(|v| v.as_str())
            .is_some());
        assert_eq!(g.decisions_sealed(), 1);
    }

    // Cycle-08 regression: the original complete_merge bug — seal first,
    // then mutate receipt.payload. Any post-seal mutation MUST fail
    // verification (payload_hash + seal both cover the payload).
    #[test]
    fn post_seal_mutation_fails_verification() {
        let (mut g, key) = gov();
        let (mut c, v) = file_view("w-mut", "src/foo.rs", vec![(1, 10)]);
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        d.verify_receipt_with(&key).unwrap();
        // attacker adds merge_sha to the sealed payload, exactly as the
        // old complete_merge did
        let mut evil = d.clone();
        evil.receipt
            .get_mut("payload")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "merge_sha".into(),
                serde_json::Value::String("f".repeat(40)),
            );
        let err = evil.verify_receipt_with(&key).unwrap_err();
        assert!(
            err.contains("tampered") || err.contains("mismatch"),
            "unexpected error: {}",
            err
        );
        // the pristine record still verifies
        d.verify_receipt_with(&key).unwrap();
    }

    // Cycle-08 regression: a record mutated after hashing must be refused
    // AT SEAL TIME, before any envelope exists to invalidate.
    #[test]
    fn stale_hash_refused_at_seal() {
        let c = ChangeClaim::propose(
            "w-stale",
            "a",
            "t",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "x",
        )
        .expect("valid change_id");
        let mut rec = DecisionRecord::draft(
            &c,
            Verdict::Accept,
            vec![],
            vec![],
            0,
            0,
            0,
            vec![],
            PolicyResult {
                pass: true,
                rule: "r".into(),
            },
            "GENESIS",
        )
        .unwrap();
        // mutate after the draft hashed (simulates the old seal-then-mutate)
        rec.tests = 999;
        let err = rec
            .seal(
                b"test-key-32-bytes-long-padding!!",
                "g",
                "2026-10-08T22:00:00Z",
            )
            .unwrap_err();
        assert!(err.contains("stale"), "unexpected error: {}", err);
        assert!(
            rec.receipt.is_empty(),
            "nothing must be sealed on stale hash"
        );
    }

    // M3 regression: two drafts built on the same head — sealing the second
    // after the first is a fork and must be refused.
    #[test]
    fn chain_fork_is_refused() {
        let (mut g, _key) = gov();
        let (mut c1, v1) = file_view("w-f1", "src/a.rs", vec![(1, 5)]);
        let (mut c2, v2) = file_view("w-f2", "src/b.rs", vec![(1, 5)]);
        // both decide against the GENESIS head
        let d1 = match g
            .decide(&mut c1, &v1, &[], &HashSet::new(), "2026-10-08T22:00:00Z")
            .unwrap()
        {
            DecideOutcome::AcceptPending { draft } => draft,
            DecideOutcome::Decided(_) => panic!("expected accept-pending"),
        };
        let d2 = match g
            .decide(&mut c2, &v2, &[], &HashSet::new(), "2026-10-08T22:01:00Z")
            .unwrap()
        {
            DecideOutcome::AcceptPending { draft } => draft,
            DecideOutcome::Decided(_) => panic!("expected accept-pending"),
        };
        let sha = Sha::new(&"f".repeat(40)).unwrap();
        g.complete_merge(d1, &sha, "fake", "2026-10-08T22:02:00Z")
            .unwrap();
        // d2 was built on GENESIS; the head has moved on
        let err = g
            .complete_merge(d2, &sha, "fake", "2026-10-08T22:03:00Z")
            .unwrap_err();
        assert!(
            err.contains("fork") || err.contains("replay"),
            "unexpected error: {}",
            err
        );
        assert_eq!(g.decisions_sealed(), 1);
    }

    // Complete chain verification with the injected key, accepted merges
    // included: every envelope verifies and every prev_hash links.
    #[test]
    fn full_chain_verifies_with_injected_key() {
        let (mut g, key) = gov();
        let (mut c1, v1) = file_view("w-c1", "src/a.rs", vec![(1, 5)]);
        let (mut c2, v2) = file_view("w-c2", "src/b.rs", vec![(1, 5)]);
        let d1 = g
            .evaluate(
                &mut c1,
                &v1,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        let d2 = g
            .evaluate(
                &mut c2,
                &v2,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:01:00Z",
            )
            .unwrap();
        d1.verify_receipt_with(&key).unwrap();
        d2.verify_receipt_with(&key).unwrap();
        pl::envelope::verify_chain_with(&key, &[d1.receipt.clone(), d2.receipt.clone()]).unwrap();
    }

    #[test]
    fn empty_evidence_is_rejected() {
        let (mut g, key) = gov();
        let mut c = ChangeClaim::propose(
            "w-2",
            "a",
            "t",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "x",
        )
        .expect("valid change_id");
        c.scope = vec![ScopeItem::File {
            path: "src/foo.rs".into(),
        }];
        c.claims.push(Claim {
            id: "C1".into(),
            statement: "s".into(),
            kind: ClaimKind::PreservesApi,
        });
        let v = ChangeView::from_scope("w-2", &c.scope);
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Reject { .. }));
        assert_eq!(c.status, ChangeStatus::Rejected);
        d.verify_receipt_with(&key).unwrap();
    }

    #[test]
    fn textual_conflict_rejects() {
        let (mut g, key) = gov();
        let (mut c1, v1) = file_view("w-a", "src/auth.rs", vec![(10, 40)]);
        let (_, v2) = file_view("w-c", "src/auth.rs", vec![(30, 45)]);
        let d = g
            .evaluate(
                &mut c1,
                &v1,
                &[v2],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Reject { .. }));
        assert!(d.conflicts.iter().any(|c| c.kind == ConflictKind::Textual));
        d.verify_receipt_with(&key).unwrap();
    }

    #[test]
    fn policy_violation_rejects_with_rule() {
        let (mut g, key) = gov();
        let (mut c, _) = mk_change(
            "w-d",
            vec![ScopeItem::Contract {
                id: "auth.error-semantics".into(),
            }],
        );
        let v = ChangeView::from_scope("w-d", &c.scope);
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        match &d.verdict {
            Verdict::Reject { reason, rule } => {
                assert!(rule.contains("CANON-31"), "rule was {}", rule);
                assert!(reason.contains("policy violation"));
            }
            v => panic!("expected Reject, got {:?}", v),
        }
        d.verify_receipt_with(&key).unwrap();
    }

    #[test]
    fn dependency_blocks_without_rejecting() {
        let (mut g, key) = gov();
        let (mut c, _) = mk_change(
            "w-e",
            vec![ScopeItem::File {
                path: "tests/x.rs".into(),
            }],
        );
        let mut v = ChangeView::from_scope("w-e", &c.scope);
        v.dependencies = vec!["w-a".into()];
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Blocked { .. }));
        assert_eq!(c.status, ChangeStatus::Proven); // not terminal: waits
                                                    // now merge the dependency and re-run: accepted
        let mut merged = HashSet::new();
        merged.insert("w-a".into());
        let d2 = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &merged,
                &FakeMerger,
                "2026-10-08T22:01:00Z",
            )
            .unwrap();
        assert!(matches!(d2.verdict, Verdict::Accept));
        d.verify_receipt_with(&key).unwrap();
        d2.verify_receipt_with(&key).unwrap();
    }

    #[test]
    fn decisions_chain() {
        let (mut g, key) = gov();
        let (mut c1, v1) = file_view("w-1", "src/a.rs", vec![(1, 5)]);
        let (mut c2, v2) = file_view("w-2", "src/b.rs", vec![(1, 5)]);
        let d1 = g
            .evaluate(
                &mut c1,
                &v1,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:00:00Z",
            )
            .unwrap();
        let d2 = g
            .evaluate(
                &mut c2,
                &v2,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T22:01:00Z",
            )
            .unwrap();
        d1.verify_receipt_with(&key).unwrap();
        d2.verify_receipt_with(&key).unwrap();
        let s1 = d1.receipt.get("seal").and_then(|v| v.as_str()).unwrap();
        assert_eq!(
            d2.receipt.get("prev_hash").and_then(|v| v.as_str()),
            Some(s1)
        );
        assert_eq!(g.decisions_sealed(), 2);
    }
    // --- L-F (cycle-11): reject() surfaces transition errors -------------

    #[test]
    fn reject_on_terminal_claim_seals_the_skew_into_the_record() {
        let (mut g, _key) = gov();
        let (mut c, _v) = mk_change("wreck-lf", vec![]);
        // drive the claim to terminal Rejected: the transition inside
        // reject() now FAILS (already terminal) instead of succeeding.
        c.transition(ChangeStatus::Observed).unwrap();
        c.transition(ChangeStatus::Rejected).unwrap();
        let d = g
            .reject(
                &mut c,
                "merge failed: boom".into(),
                "MERGE-FAILED".into(),
                vec![],
                "ts",
                vec![],
            )
            .unwrap();
        // the verdict still seals (the decision record is the source of
        // truth) ...
        match &d.verdict {
            Verdict::Reject { reason, rule } => {
                assert_eq!(rule, "MERGE-FAILED");
                // ... but the anomaly is visible in the sealed reason,
                // never silently swallowed.
                assert!(
                    reason.contains("transition skipped"),
                    "skew must be surfaced, reason: {}",
                    reason
                );
                assert!(reason.contains("merge failed: boom"), "reason: {}", reason);
            }
            v => panic!("expected Reject, got {:?}", v),
        }
        // and the claim status is untouched (still terminal Rejected)
        assert_eq!(c.status, ChangeStatus::Rejected);
    }

    #[test]
    fn reject_on_nonterminal_claim_has_no_skew_marker() {
        let (mut g, _key) = gov();
        let (mut c, _v) = mk_change("wreck-lf2", vec![]);
        c.transition(ChangeStatus::Observed).unwrap();
        c.transition(ChangeStatus::Checked).unwrap();
        let d = g
            .reject(
                &mut c,
                "nope".into(),
                "EVIDENCE-01".into(),
                vec![],
                "ts",
                vec![],
            )
            .unwrap();
        match &d.verdict {
            Verdict::Reject { reason, .. } => {
                assert!(
                    !reason.contains("transition skipped"),
                    "no skew on the happy path, reason: {}",
                    reason
                );
            }
            v => panic!("expected Reject, got {:?}", v),
        }
        assert_eq!(c.status, ChangeStatus::Rejected);
    }

    // Cycle-12: provenance records ONLY what the governor actually read.
    // The sealed decision's provenance must contain the claim, its
    // evidence, the measured view, each classified in-flight view, and
    // each evaluated policy rule — and must NOT contain a skipped view,
    // an unseen change, anything smuggled through agent-written text, or
    // merged-set lookups (membership answers, not content reads).
    #[test]
    fn provenance_only_contains_consumed_inputs() {
        let (mut g, key) = gov();
        let (mut c, mut v) = file_view("w-prov", "src/p.rs", vec![(1, 10)]);
        v.dependencies = vec!["w-dep".into()];
        // The agent tries to smuggle a fake provenance entry through
        // evidence text. The governor never parses agent strings for
        // provenance — nothing may appear for w-ghost.
        c.evidence.push(Evidence {
            id: "C1-E2".into(),
            kind: EvidenceKind::Test,
            reference: "C1: provenance w-ghost blob deadbeef".into(),
            digest: "sha256:def".into(),
        });
        let (_, other) = file_view("w-other", "src/q.rs", vec![(1, 5)]);
        // Same change_id as the claim: skipped by the classify loop, so
        // its bytes must never be recorded.
        let (_, selfskip) = file_view("w-prov", "src/other.rs", vec![(9, 9)]);
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[other, selfskip],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T23:00:00Z",
            )
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Blocked { .. }));
        // sealed WITH provenance: the envelope covers it
        d.verify_receipt_with(&key).unwrap();

        let has = |kind: &ProvenanceKind, id: &str| {
            d.provenance.iter().any(|p| &p.kind == kind && p.id == id)
        };
        // every consumed input is recorded
        assert!(has(&ProvenanceKind::Claim, "w-prov"));
        assert!(has(&ProvenanceKind::Claim, "C1-E1"));
        assert!(has(&ProvenanceKind::Claim, "C1-E2"));
        assert!(has(&ProvenanceKind::Diff, "w-prov"));
        assert!(has(&ProvenanceKind::Diff, "w-other"));
        assert!(has(&ProvenanceKind::Policy, "CANON-31"));
        assert_eq!(d.provenance.len(), 6);
        // never read: the smuggled ghost, unseen changes, merged-set
        // lookups, raw blobs (the governor never reads blobs)
        assert!(!has(&ProvenanceKind::Claim, "w-ghost"));
        assert!(!has(&ProvenanceKind::Diff, "w-ghost"));
        assert!(!has(&ProvenanceKind::Diff, "w-dep"));
        assert!(!has(&ProvenanceKind::Claim, "w-dep"));
        assert!(!d.provenance.iter().any(|p| p.kind == ProvenanceKind::Blob));
        // evidence entries carry the pinned digest the governor required
        let e1 = d.provenance.iter().find(|p| p.id == "C1-E1").unwrap();
        assert_eq!(e1.hash, "sha256:abc");
        // the diff entry binds the OWN view's bytes — not the skipped one's
        let own = d
            .provenance
            .iter()
            .find(|p| p.kind == ProvenanceKind::Diff && p.id == "w-prov")
            .unwrap();
        assert_eq!(own.hash, wreck_protocol::content_hash(&v).unwrap());
        assert_eq!(own.hash.len(), 64);
        // the policy entry binds the evaluated rule's bytes
        let rule = d
            .provenance
            .iter()
            .find(|p| p.kind == ProvenanceKind::Policy)
            .unwrap();
        assert_eq!(
            rule.hash,
            wreck_protocol::content_hash(&wreck_graph::PolicyRule {
                id: "CANON-31".into(),
                forbidden_contract: "auth.error-semantics".into(),
                reason: "C-17".into(),
            })
            .unwrap()
        );
        // the claim entry binds the as-given claim bytes (64-hex digest)
        let claim = d
            .provenance
            .iter()
            .find(|p| p.kind == ProvenanceKind::Claim && p.id == "w-prov")
            .unwrap();
        assert_eq!(claim.hash.len(), 64);
        assert!(claim.hash.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    // Cycle-12: an early EVIDENCE-01 reject never reached the view, the
    // in-flight set, or the policy rules — its provenance must say so.
    #[test]
    fn early_reject_provenance_contains_only_what_was_read() {
        let (mut g, key) = gov();
        let mut c = ChangeClaim::propose(
            "w-noev",
            "a",
            "t",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "x",
        )
        .expect("valid change_id");
        c.claims.push(Claim {
            id: "C1".into(),
            statement: "s".into(),
            kind: ClaimKind::PreservesApi,
        });
        // no evidence at all → EVIDENCE-01 before any view/policy read
        let v = ChangeView::from_scope("w-noev", &c.scope);
        let d = g
            .evaluate(
                &mut c,
                &v,
                &[],
                &HashSet::new(),
                &FakeMerger,
                "2026-10-08T23:00:00Z",
            )
            .unwrap();
        assert!(matches!(d.verdict, Verdict::Reject { .. }));
        d.verify_receipt_with(&key).unwrap();
        // only the claim itself was read
        assert_eq!(d.provenance.len(), 1);
        assert!(matches!(d.provenance[0].kind, ProvenanceKind::Claim));
        assert_eq!(d.provenance[0].id, "w-noev");
    }
}

#[cfg(test)]
mod attestation_tests {
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

    #[test]
    fn hidden_file_is_rejected() {
        let mut gov = Governor::new(
            Policy::default(),
            b"test-key-32-bytes-long-padding!!".to_vec(),
            "g",
        );
        // agent declares only src/a.rs but the diff touches src/evil.rs
        let mut c = ChangeClaim::propose(
            "w-sneaky",
            "agent-x",
            "t1",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "innocent refactor",
        )
        .expect("valid change_id");
        c.scope = vec![ScopeItem::File {
            path: "src/a.rs".into(),
        }];
        c.claims.push(Claim {
            id: "C1".into(),
            statement: "s".into(),
            kind: ClaimKind::PreservesApi,
        });
        c.evidence.push(Evidence {
            id: "C1-E1".into(),
            kind: EvidenceKind::Test,
            reference: "C1: t".into(),
            digest: "sha256:x".into(),
        });
        let v = ChangeView {
            change_id: "w-sneaky".into(),
            files: vec![
                FileChange {
                    path: "src/a.rs".into(),
                    added: vec![(1, 2)],
                    removed: vec![],
                },
                FileChange {
                    path: "src/evil.rs".into(),
                    added: vec![(1, 50)],
                    removed: vec![],
                },
            ],
            ..Default::default()
        };
        let d = gov
            .evaluate(
                &mut c,
                &v,
                &[],
                &std::collections::HashSet::new(),
                &FakeMerger,
                "2026-10-08T23:00:00Z",
            )
            .unwrap();
        match &d.verdict {
            Verdict::Reject { reason, rule } => {
                assert_eq!(rule, "SCOPE-01");
                assert!(reason.contains("src/evil.rs"), "reason: {}", reason);
            }
            v => panic!("expected SCOPE-01 reject, got {:?}", v),
        }
    }
}
