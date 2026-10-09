//! wreck-protocol: the change-governance protocol objects.
//!
//! The fundamental object is not a branch or a PR. It is a CHANGE CLAIM:
//! an agent proposing a state transition, with intent, semantic claims,
//! and evidence attached. A deterministic governor decides; every decision
//! is sealed in the existing `lucidota-receipt/1` envelope (see the `pl`
//! crate) — this crate invents no new envelope.
//!
//! Status machine (forward only, no silent transitions):
//! PROPOSED -> OBSERVED -> CHECKED -> PROVEN -> ELIGIBLE -> MERGED
//!                                  |-> REJECTED (terminal, from CHECKED)

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A git SHA (full 40-hex). Validated on construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha(String);

impl Sha {
    pub fn new(s: &str) -> Result<Self, String> {
        if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(Sha(s.to_lowercase()))
        } else {
            Err(format!("wreck-protocol: invalid sha {:?}", s))
        }
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Something the change touches: a file path, a symbol, or a contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeItem {
    File { path: String },
    Symbol { name: String },
    Contract { id: String },
}

/// A semantic claim the agent makes about its change.
/// Textual diffs say WHAT; claims say WHY it is safe/correct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub id: String,
    pub statement: String,
    pub kind: ClaimKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    PreservesApi,
    EliminatesRace,
    PassesInvariant { invariant: String },
    NoPolicyViolation { policy: String },
    Custom { label: String },
}

/// Evidence backing a claim. The digest pins the artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub kind: EvidenceKind,
    pub reference: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Test,
    Oracle,
    StaticAnalysis,
    Receipt,
    Observation,
}

/// Forward-only lifecycle of a change claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangeStatus {
    Proposed,
    Observed,
    Checked,
    Proven,
    Eligible,
    Merged,
    Rejected,
}

impl ChangeStatus {
    fn rank(self) -> u8 {
        match self {
            ChangeStatus::Proposed => 0,
            ChangeStatus::Observed => 1,
            ChangeStatus::Checked => 2,
            ChangeStatus::Proven => 3,
            ChangeStatus::Eligible => 4,
            ChangeStatus::Merged => 5,
            ChangeStatus::Rejected => 6,
        }
    }

    /// Legal forward transitions. Rejected is terminal and reachable from
    /// any state past Proposed (a verdict can land any time before merge);
    /// a claim must at least be Observed before it can be rejected.
    pub fn can_transition(self, next: ChangeStatus) -> bool {
        use ChangeStatus::*;
        matches!(
            (self, next),
            (Proposed, Observed)
                | (Observed, Checked)
                | (Observed, Rejected)
                | (Checked, Proven)
                | (Checked, Rejected)
                | (Proven, Eligible)
                | (Proven, Rejected)
                | (Eligible, Merged)
                | (Eligible, Rejected)
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, ChangeStatus::Merged | ChangeStatus::Rejected)
    }

    pub fn rank_of(self) -> u8 {
        self.rank()
    }
}

/// "I propose this state transition." — the unit the governor reasons over.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeClaim {
    pub change_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub base: Sha,
    pub head: Sha,
    pub intent: String,
    pub scope: Vec<ScopeItem>,
    pub claims: Vec<Claim>,
    pub evidence: Vec<Evidence>,
    pub dependencies: Vec<String>,
    pub status: ChangeStatus,
}

impl ChangeClaim {
    /// Validate a change_id at the boundary. Mirrors the Artifacts repo-name
    /// rule: `^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$`. Rejects path separators
    /// (`../../x` → merge-dir traversal in ArtifactsMergePort), `..`,
    /// newlines (commit-message injection), and empty/1-char ids.
    /// The change_id is agent-influenced via the `Wreck-Claim:` trailer, so
    /// it must never become a filesystem or shell capability unchecked.
    pub fn validate_change_id(id: &str) -> Result<(), String> {
        let bytes = id.as_bytes();
        let ok = bytes.len() >= 2
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-' || *b == b'_');
        if ok {
            Ok(())
        } else {
            Err(format!("wreck-protocol: invalid change_id {:?}", id))
        }
    }

    pub fn propose(
        change_id: &str,
        agent_id: &str,
        task_id: &str,
        base: Sha,
        head: Sha,
        intent: &str,
    ) -> Result<Self, String> {
        Self::validate_change_id(change_id)?;
        Ok(ChangeClaim {
            change_id: change_id.to_string(),
            agent_id: agent_id.to_string(),
            task_id: task_id.to_string(),
            base,
            head,
            intent: intent.to_string(),
            scope: vec![],
            claims: vec![],
            evidence: vec![],
            dependencies: vec![],
            status: ChangeStatus::Proposed,
        })
    }

    /// Serialize as a git commit trailer: `Wreck-Claim: <compact json>`.
    /// The claim rides the push event's commit message — the Worker's
    /// claimFromCommit parses it with zero extra subrequests.
    pub fn to_trailer(&self) -> String {
        format!(
            "Wreck-Claim: {}",
            serde_json::to_string(self).unwrap_or_default()
        )
    }

    /// Parse the first `Wreck-Claim:` trailer from a commit message.
    /// The change_id is re-validated here: the trailer is agent-influenced
    /// input, so an invalid id rejects the whole claim (returns None).
    pub fn from_trailer(msg: &str) -> Option<Self> {
        msg.lines()
            .filter_map(|l| l.strip_prefix("Wreck-Claim:"))
            .next()
            .and_then(|j| serde_json::from_str(j.trim()).ok())
            .and_then(|c: Self| Self::validate_change_id(&c.change_id).ok().map(|_| c))
    }

    /// Forward-only transition. Errors on any backward or skipped step.
    pub fn transition(&mut self, next: ChangeStatus) -> Result<(), String> {
        if self.status.is_terminal() {
            return Err(format!(
                "wreck-protocol: change {} is terminal ({:?}), no transitions allowed",
                self.change_id, self.status
            ));
        }
        if self.status.can_transition(next) {
            self.status = next;
            Ok(())
        } else {
            Err(format!(
                "wreck-protocol: illegal transition {:?} -> {:?} for {}",
                self.status, next, self.change_id
            ))
        }
    }
}

/// The governor's verdict on one change claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Accept,
    Reject { reason: String, rule: String },
    NeedsRebase { onto: String },
    Blocked { by: Vec<String> },
}

/// The merge outcome. Sealed INTO the decision record before sealing —
/// never bolted onto the receipt afterwards (that would invalidate the
/// payload_hash/seal; see the stale-hash guard in DecisionRecord::seal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeRecord {
    pub merge_sha: Sha,
    pub port: String,
}

/// What a decision was derived from. Mirrors the Cloudflare OS
/// observation-log pattern (cycle-01): taint follows the data — the record
/// states what was read, and the hash binds the exact bytes consumed.
/// `Blob` entries are emitted by the Worker/adapter boundary at fetch time
/// (raw blob reads) and *consumed* by the governor — never synthesized:
/// the governor itself never reads blobs, so a Blob entry in a decision
/// always came from the reader that fetched the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    Blob,
    Diff,
    Claim,
    Policy,
}

/// One derived-from entry: a single resource the governor actually consumed
/// while producing a decision. Populated by the governor at read time —
/// never from agent declarations (the claim carries no provenance field,
/// and nothing the agent writes is parsed for entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEntry {
    pub kind: ProvenanceKind,
    pub id: String,
    /// sha256 of the canonical bytes consumed (hex), or the pinned digest
    /// the governor required (evidence items).
    pub hash: String,
}

/// Deterministic content hash of any serializable value: hex sha256 of the
/// canonical JSON. Binds a provenance entry to the exact bytes read.
pub fn content_hash<T: Serialize>(v: &T) -> Result<String, String> {
    let val =
        serde_json::to_value(v).map_err(|e| format!("wreck-protocol: serialize failed: {}", e))?;
    pl::canon::hash_record(&val)
}

/// Hex sha256 of raw bytes. The canonical hash for blob provenance:
/// the entry binds the exact bytes the reader consumed.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Build one Blob provenance entry for bytes a reader actually fetched.
/// `id` is the blob's key in the reader's domain (path or object hash);
/// `hash` is sha256 of the exact bytes read — never a claimed digest.
/// Cycle-19: emitted at fetch time by the Worker/adapter boundary,
/// consumed (never synthesized) by the governor.
pub fn blob_provenance_entry(id: &str, bytes: &[u8]) -> ProvenanceEntry {
    ProvenanceEntry {
        kind: ProvenanceKind::Blob,
        id: id.to_string(),
        hash: sha256_hex(bytes),
    }
}

/// A conflict discovered by the change graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictRef {
    pub with_change: String,
    pub kind: ConflictKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    Textual,
    Semantic,
    Dependency,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyResult {
    pub pass: bool,
    pub rule: String,
}

/// The machine-verifiable review record. Replaces "LGTM".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub change_id: String,
    pub verdict: Verdict,
    pub base: Sha,
    pub head: Sha,
    pub canon: Vec<String>,
    pub contracts: Vec<String>,
    pub claims_checked: u32,
    pub proofs: u32,
    pub tests: u32,
    pub conflicts: Vec<ConflictRef>,
    pub policy: PolicyResult,
    /// sha256 of the canonical JSON of this record minus receipt.
    pub decision_hash: String,
    /// seal of the previous decision record: the hash chain.
    pub parent_decision: String,
    /// Merge outcome (sha + port). Present only on accepted+merged
    /// decisions; part of the hashed canonical value, so it is sealed
    /// with the decision — never added to the receipt post-seal.
    #[serde(default)]
    pub merge: Option<MergeRecord>,
    /// Derived-from provenance: every input the governor actually consumed
    /// while producing this decision (claim, evidence, measured diffs,
    /// evaluated policy rules). Recorded at read time, never from agent
    /// declarations; part of the hashed canonical value. Empty on legacy
    /// records (serde default).
    #[serde(default)]
    pub provenance: Vec<ProvenanceEntry>,
    /// `lucidota-receipt/1` envelope sealing this decision.
    pub receipt: Map<String, Value>,
}

impl DecisionRecord {
    /// Build an unsealed decision (receipt empty). `seal` attaches the envelope.
    #[allow(clippy::too_many_arguments)] // builder-style ctor; fields are distinct
    pub fn draft(
        change: &ChangeClaim,
        verdict: Verdict,
        canon: Vec<String>,
        contracts: Vec<String>,
        claims_checked: u32,
        proofs: u32,
        tests: u32,
        conflicts: Vec<ConflictRef>,
        policy: PolicyResult,
        parent_decision: &str,
    ) -> Result<Self, String> {
        let mut rec = DecisionRecord {
            change_id: change.change_id.clone(),
            verdict,
            base: change.base.clone(),
            head: change.head.clone(),
            canon,
            contracts,
            claims_checked,
            proofs,
            tests,
            conflicts,
            policy,
            decision_hash: String::new(),
            parent_decision: parent_decision.to_string(),
            merge: None,
            provenance: Vec::new(),
            receipt: Map::new(),
        };
        rec.decision_hash = rec.compute_hash()?;
        Ok(rec)
    }

    /// Attach the merge outcome BEFORE sealing. Re-hashes, because the
    /// merge is part of the decision: sealing a hash computed without it
    /// would leave the receipt lying about what was sealed.
    pub fn with_merge(mut self, merge_sha: Sha, port: &str) -> Result<Self, String> {
        self.merge = Some(MergeRecord {
            merge_sha,
            port: port.to_string(),
        });
        self.decision_hash = self.compute_hash()?;
        Ok(self)
    }

    /// Attach derived-from provenance BEFORE sealing. Re-hashes, because
    /// provenance is part of the decision: it must be covered by
    /// decision_hash, exactly like the merge outcome. Dedupes on
    /// (kind, id, hash); the first entry wins. The hash is part of the
    /// key because two observations of the same resource with different
    /// bytes (e.g. a blob's old and new sides) are different
    /// observations — deduping on (kind, id) alone would silently drop
    /// one side of every diff (cycle-19).
    pub fn with_provenance(mut self, entries: Vec<ProvenanceEntry>) -> Result<Self, String> {
        for e in entries {
            if !self
                .provenance
                .iter()
                .any(|p| p.kind == e.kind && p.id == e.id && p.hash == e.hash)
            {
                self.provenance.push(e);
            }
        }
        self.decision_hash = self.compute_hash()?;
        Ok(self)
    }

    fn canonical_value(&self) -> Value {
        // decision_hash and receipt excluded: the hash covers the decision,
        // the envelope then seals (decision_hash + everything else).
        let mut m = Map::new();
        m.insert("change_id".into(), Value::String(self.change_id.clone()));
        m.insert(
            "verdict".into(),
            serde_json::to_value(&self.verdict).unwrap_or(Value::Null),
        );
        m.insert("base".into(), Value::String(self.base.as_str().into()));
        m.insert("head".into(), Value::String(self.head.as_str().into()));
        m.insert(
            "canon".into(),
            Value::Array(
                self.canon
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        m.insert(
            "contracts".into(),
            Value::Array(
                self.contracts
                    .iter()
                    .map(|s| Value::String(s.clone()))
                    .collect(),
            ),
        );
        m.insert("claims_checked".into(), Value::from(self.claims_checked));
        m.insert("proofs".into(), Value::from(self.proofs));
        m.insert("tests".into(), Value::from(self.tests));
        m.insert(
            "conflicts".into(),
            serde_json::to_value(&self.conflicts).unwrap_or(Value::Null),
        );
        m.insert(
            "policy".into(),
            serde_json::to_value(&self.policy).unwrap_or(Value::Null),
        );
        m.insert(
            "parent_decision".into(),
            Value::String(self.parent_decision.clone()),
        );
        m.insert(
            "merge".into(),
            serde_json::to_value(&self.merge).unwrap_or(Value::Null),
        );
        m.insert(
            "provenance".into(),
            serde_json::to_value(&self.provenance).unwrap_or(Value::Null),
        );
        Value::Object(m)
    }

    pub fn compute_hash(&self) -> Result<String, String> {
        pl::canon::hash_record(&self.canonical_value())
            .map_err(|e| format!("wreck-protocol: hash failed: {}", e))
    }

    /// Seal the decision into a `lucidota-receipt/1` envelope.
    /// `status` is the envelope vocabulary: "claimed" | "established" | "authorized".
    /// An ACCEPT verdict seals as "established"; anything else as "claimed".
    ///
    /// Fail-closed integrity (cycle-08): the stored `decision_hash` must
    /// cover the CURRENT fields. A record mutated after hashing (the
    /// original complete_merge bug: seal-then-mutate the receipt payload)
    /// is refused here, before any envelope exists to invalidate.
    pub fn seal(&mut self, key: &[u8], actor: &str, ts: &str) -> Result<(), String> {
        let fresh = self.compute_hash()?;
        if self.decision_hash.is_empty() {
            self.decision_hash = fresh;
        } else if self.decision_hash != fresh {
            return Err(
                "wreck-protocol: decision_hash is stale — record mutated after hashing; refusing to seal".into(),
            );
        }
        let status = match &self.verdict {
            Verdict::Accept => "established",
            _ => "claimed",
        };
        let payload = match self.canonical_value() {
            Value::Object(m) => {
                let mut m = m;
                m.insert(
                    "decision_hash".into(),
                    Value::String(self.decision_hash.clone()),
                );
                m
            }
            _ => return Err("wreck-protocol: canonical value not an object".into()),
        };
        self.receipt = pl::envelope::wrap_with(
            key,
            actor,
            &format!("wreck-decision-{}", self.change_id),
            status,
            payload,
            &self.parent_decision,
            ts,
        )?;
        Ok(())
    }

    /// Verify the attached envelope (signature, payload binding, seal).
    pub fn verify_receipt(&self) -> Result<(), String> {
        if self.receipt.is_empty() {
            return Err("wreck-protocol: decision is not sealed".into());
        }
        pl::envelope::verify(&self.receipt)
    }

    /// Key-injectable receipt verification (hermetic tests; the governor
    /// passes its own key after every seal, accepted merges included).
    pub fn verify_receipt_with(&self, key: &[u8]) -> Result<(), String> {
        if self.receipt.is_empty() {
            return Err("wreck-protocol: decision is not sealed".into());
        }
        pl::envelope::verify_with(key, &self.receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(s: char) -> Sha {
        Sha::new(&s.to_string().repeat(40)).unwrap()
    }

    #[test]
    fn sha_validation() {
        assert!(Sha::new(&"a".repeat(40)).is_ok());
        assert!(Sha::new("abc").is_err());
        assert!(Sha::new(&"z".repeat(40)).is_err());
        assert_eq!(Sha::new(&"A".repeat(40)).unwrap().as_str(), "a".repeat(40));
    }

    #[test]
    fn transitions_are_forward_only() {
        let mut c = ChangeClaim::propose("wreck-1", "a1", "t1", sha('a'), sha('b'), "test")
            .expect("valid change_id");
        assert!(c.transition(ChangeStatus::Observed).is_ok());
        assert!(c.transition(ChangeStatus::Proposed).is_err()); // backward
        assert!(c.transition(ChangeStatus::Proven).is_err()); // skip
        assert!(c.transition(ChangeStatus::Checked).is_ok());
        assert!(c.transition(ChangeStatus::Rejected).is_ok());
        assert!(c.transition(ChangeStatus::Proven).is_err()); // terminal
    }

    #[test]
    fn happy_path_to_merged() {
        let mut c = ChangeClaim::propose("wreck-2", "a1", "t1", sha('a'), sha('b'), "test")
            .expect("valid change_id");
        for s in [
            ChangeStatus::Observed,
            ChangeStatus::Checked,
            ChangeStatus::Proven,
            ChangeStatus::Eligible,
            ChangeStatus::Merged,
        ] {
            c.transition(s).unwrap();
        }
        assert_eq!(c.status, ChangeStatus::Merged);
    }

    #[test]
    fn decision_hash_is_deterministic() {
        let mk = || {
            let c = ChangeClaim::propose("wreck-3", "a1", "t1", sha('a'), sha('b'), "x")
                .expect("valid change_id");
            DecisionRecord::draft(
                &c,
                Verdict::Accept,
                vec!["CANON-17".into()],
                vec!["C-09".into()],
                3,
                7,
                14,
                vec![],
                PolicyResult {
                    pass: true,
                    rule: "default-allow".into(),
                },
                "GENESIS",
            )
            .unwrap()
        };
        let a = mk();
        let b = mk();
        assert_eq!(a.decision_hash, b.decision_hash);
        assert!(!a.decision_hash.is_empty());
    }

    #[test]
    fn seal_and_verify_roundtrip() {
        let key = b"test-authority-key-32-bytes-long!!!!";
        let c = ChangeClaim::propose("wreck-4", "a1", "t1", sha('a'), sha('b'), "x")
            .expect("valid change_id");
        let mut d = DecisionRecord::draft(
            &c,
            Verdict::Accept,
            vec![],
            vec![],
            1,
            1,
            1,
            vec![],
            PolicyResult {
                pass: true,
                rule: "r".into(),
            },
            "GENESIS",
        )
        .unwrap();
        // wrap_with signs with the given key; verify checks against the
        // authority key file, so verify the envelope structurally here via
        // the chain verifier shape instead: seal must populate receipt.
        d.seal(key, "governor-test", "2026-10-08T21:00:00Z")
            .unwrap();
        assert_eq!(
            d.receipt.get("env").and_then(|v| v.as_str()),
            Some("lucidota-receipt/1")
        );
        assert_eq!(
            d.receipt.get("status").and_then(|v| v.as_str()),
            Some("established")
        );
        assert_eq!(
            d.receipt.get("prev_hash").and_then(|v| v.as_str()),
            Some("GENESIS")
        );
        // chain verification over two decisions
        let seal1 = d
            .receipt
            .get("seal")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let c2 = ChangeClaim::propose("wreck-5", "a2", "t1", sha('b'), sha('c'), "y")
            .expect("valid change_id");
        let mut d2 = DecisionRecord::draft(
            &c2,
            Verdict::Reject {
                reason: "policy".into(),
                rule: "CANON-31".into(),
            },
            vec![],
            vec![],
            0,
            0,
            0,
            vec![],
            PolicyResult {
                pass: false,
                rule: "CANON-31".into(),
            },
            &seal1,
        )
        .unwrap();
        d2.seal(key, "governor-test", "2026-10-08T21:01:00Z")
            .unwrap();
        assert_eq!(
            d2.receipt.get("status").and_then(|v| v.as_str()),
            Some("claimed")
        );
        // verify_chain_with with the same key proves the chain is intact
        pl::envelope::verify_chain_with(key, &[d.receipt.clone(), d2.receipt.clone()]).unwrap();
    }

    #[test]
    fn reject_reachable_past_proposed_only() {
        let mut c = ChangeClaim::propose("wreck-6", "a1", "t1", sha('a'), sha('b'), "x")
            .expect("valid change_id");
        assert!(c.transition(ChangeStatus::Rejected).is_err()); // not from Proposed
        c.transition(ChangeStatus::Observed).unwrap();
        c.transition(ChangeStatus::Rejected).unwrap(); // legal from Observed
    }

    #[test]
    fn schema_json_roundtrip() {
        let mut c = ChangeClaim::propose(
            "wreck-7",
            "agent-a",
            "task-42",
            sha('a'),
            sha('b'),
            "improve auth timeout",
        )
        .expect("valid change_id");
        c.scope.push(ScopeItem::File {
            path: "src/auth.rs".into(),
        });
        c.claims.push(Claim {
            id: "C1".into(),
            statement: "preserves public API".into(),
            kind: ClaimKind::PreservesApi,
        });
        c.evidence.push(Evidence {
            id: "E1".into(),
            kind: EvidenceKind::Test,
            reference: "test 184".into(),
            digest: "sha256:abc".into(),
        });
        let json = serde_json::to_string(&c).unwrap();
        let back: ChangeClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(back.change_id, "wreck-7");
        assert_eq!(back.scope.len(), 1);
    }
}

#[cfg(test)]
mod trailer_tests {
    use super::*;

    #[test]
    fn trailer_roundtrip() {
        let mut c = ChangeClaim::propose(
            "wreck-t",
            "a1",
            "t1",
            Sha::new(&"a".repeat(40)).unwrap(),
            Sha::new(&"b".repeat(40)).unwrap(),
            "do the thing",
        )
        .expect("valid change_id");
        c.scope.push(ScopeItem::File {
            path: "src/x.rs".into(),
        });
        let msg = format!("do the thing\n\n{}", c.to_trailer());
        let back = ChangeClaim::from_trailer(&msg).unwrap();
        assert_eq!(back.change_id, "wreck-t");
        assert_eq!(back.intent, "do the thing");
        assert!(ChangeClaim::from_trailer("no trailer here").is_none());
    }

    // H5 regression: change_id is validated at claim intake.
    fn sha(c: char) -> Sha {
        Sha::new(&c.to_string().repeat(40)).unwrap()
    }

    #[test]
    fn change_id_charset_accepts_repo_style_ids() {
        for id in ["wreck-1", "w-2", "agent-0", "scale-003", "a_b.c-d", "AB12"] {
            assert!(ChangeClaim::validate_change_id(id).is_ok(), "id: {}", id);
            assert!(
                ChangeClaim::propose(id, "a", "t", sha('a'), sha('b'), "x").is_ok(),
                "id: {}",
                id
            );
        }
    }

    #[test]
    fn change_id_rejects_path_traversal() {
        for id in ["../../x", "..", "../evil", "a/b", "/abs", "x\\y"] {
            assert!(ChangeClaim::validate_change_id(id).is_err(), "id: {}", id);
            assert!(
                ChangeClaim::propose(id, "a", "t", sha('a'), sha('b'), "x").is_err(),
                "id: {}",
                id
            );
        }
    }

    #[test]
    fn change_id_rejects_injection_and_bad_lengths() {
        for id in [
            "",
            "x",
            "a\nb: injected",
            "a b",
            "a;b",
            "a$b",
            &"a".repeat(64),
        ] {
            assert!(ChangeClaim::validate_change_id(id).is_err(), "id: {:?}", id);
        }
        // 63 chars is the max (mirrors Artifacts repo-name rule)
        assert!(ChangeClaim::validate_change_id(&"a".repeat(63)).is_ok());
    }

    #[test]
    fn trailer_with_invalid_change_id_is_rejected() {
        // agent-influenced trailer carrying a traversal id must not parse
        let evil = r#"Wreck-Claim: {"change_id":"../../evil","agent_id":"a","task_id":"t","base":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","head":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","intent":"x","scope":[],"claims":[],"evidence":[],"dependencies":[],"status":"Proposed"}"#;
        assert!(ChangeClaim::from_trailer(evil).is_none());
    }
}
