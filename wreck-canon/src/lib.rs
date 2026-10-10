//! wreck-canon: canonical rules — the WHY behind policy.
//!
//! A CANON rule is a standing decision: "this is true, by this authority,
//! since this time." Rules are append-only — a new version supersedes the
//! old; nothing is ever mutated. The governor's policy rules reference
//! CANON ids; the store resolves them to statements with provenance.
//!
//! Git records WHAT happened. CANON records WHY it was allowed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wreck_graph::{Policy, PolicyRule};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonRule {
    pub id: String,
    pub statement: String,
    /// e.g. "contract C-17", "operator decree 2026-10-08"
    pub authority: String,
    pub created: String,
    /// id of the rule this one replaces, if any
    pub supersedes: Option<String>,
    /// the contract scope this rule forbids touching (for policy use)
    pub forbids_contract: Option<String>,
    /// file path patterns that imply touching the forbidden contract,
    /// measured from the diff (see PolicyRule::file_patterns).
    ///
    /// HONEST BOUND (R-2, 2026-10-10): this is a HEURISTIC, not a proof of
    /// contract impact. It catches: the obvious case — an agent touching
    /// files under the listed patterns while omitting the contract from
    /// scope (RT-A2-001). It does NOT catch: contract violations via files
    /// outside the listed patterns (behavioral coupling across modules),
    /// violations with no diff at all (config/env/runtime changes), or an
    /// agent that correctly declares the contract but violates its spirit.
    /// Patterns are curated by the operator, not discovered; coverage beyond
    /// the listed patterns is UNKNOWN, never assumed.
    #[serde(default)]
    pub contract_file_patterns: Vec<String>,
}

#[derive(Debug, Default)]
pub struct CanonStore {
    rules: HashMap<String, CanonRule>,
}

impl CanonStore {
    pub fn new() -> Self {
        CanonStore::default()
    }

    pub fn insert(&mut self, rule: CanonRule) {
        self.rules.insert(rule.id.clone(), rule);
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        let rules: Vec<CanonRule> =
            serde_json::from_str(json).map_err(|e| format!("wreck-canon: {}", e))?;
        let mut s = CanonStore::new();
        for r in rules {
            s.insert(r);
        }
        Ok(s)
    }

    pub fn get(&self, id: &str) -> Option<&CanonRule> {
        self.rules.get(id)
    }

    /// Rules that have not been superseded.
    pub fn active(&self) -> Vec<&CanonRule> {
        let superseded: std::collections::HashSet<&str> = self
            .rules
            .values()
            .filter_map(|r| r.supersedes.as_deref())
            .collect();
        let mut out: Vec<&CanonRule> = self
            .rules
            .values()
            .filter(|r| !superseded.contains(r.id.as_str()))
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Build a governor Policy from the active rules that forbid contracts.
    pub fn to_policy(&self) -> Policy {
        Policy {
            rules: self
                .active()
                .into_iter()
                .filter_map(|r| {
                    r.forbids_contract.as_ref().map(|c| PolicyRule {
                        id: r.id.clone(),
                        forbidden_contract: c.clone(),
                        reason: format!("{} (authority: {})", r.statement, r.authority),
                        file_patterns: r.contract_file_patterns.clone(),
                    })
                })
                .collect(),
        }
    }
}

/// The seed canon for the auth demo.
pub fn demo_canon() -> CanonStore {
    let mut s = CanonStore::new();
    s.insert(CanonRule {
        id: "CANON-31".into(),
        statement: "no agent may mutate auth error semantics".into(),
        authority: "contract C-17".into(),
        created: "2026-10-08".into(),
        supersedes: None,
        forbids_contract: Some("auth.error-semantics".into()),
        // REDTEAM (spree A2): measured from the diff — an agent cannot
        // bypass by omitting the contract declaration.
        // Specific to error-semantics files, not all auth files.
        contract_file_patterns: vec!["src/auth_err*".into()],
    });
    s.insert(CanonRule {
        id: "CANON-17".into(),
        statement: "token validation changes must preserve the public API".into(),
        authority: "contract C-09".into(),
        created: "2026-10-08".into(),
        supersedes: None,
        forbids_contract: None,
        contract_file_patterns: vec![],
    });
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supersede_keeps_history() {
        let mut s = demo_canon();
        s.insert(CanonRule {
            id: "CANON-31b".into(),
            statement: "no agent may mutate auth error semantics, except via migration plan".into(),
            authority: "contract C-17 rev 2".into(),
            created: "2026-10-09".into(),
            supersedes: Some("CANON-31".into()),
            forbids_contract: Some("auth.error-semantics".into()),
            contract_file_patterns: vec!["src/auth*".into()],
        });
        // old rule still retrievable (history), but not active
        assert!(s.get("CANON-31").is_some());
        let active: Vec<_> = s.active().iter().map(|r| r.id.as_str()).collect();
        assert!(!active.contains(&"CANON-31"));
        assert!(active.contains(&"CANON-31b"));
        assert!(active.contains(&"CANON-17"));
    }

    #[test]
    fn policy_derives_from_canon() {
        let p = demo_canon().to_policy();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].id, "CANON-31");
        assert!(p.rules[0].reason.contains("contract C-17"));
    }

    #[test]
    fn json_roundtrip() {
        let s = demo_canon();
        let json = serde_json::to_string(&s.active()).unwrap();
        let s2 = CanonStore::from_json(&json).unwrap();
        assert_eq!(s2.active().len(), 2);
    }
}
