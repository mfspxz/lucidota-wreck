//! wreck-demo: the nasty 5-agent scenario, end to end on real git.
//!
//! TASK: "Improve authentication." Five agents work concurrently on the
//! same subsystem. The governor classifies every change; zero human merges.
//!
//! Expected:
//!   A (token validation, lines 10-40)   -> ACCEPT
//!   B (token expiry, lines 45-75)       -> ACCEPT  (same file, disjoint)
//!   C (retry, lines 30-45)              -> REJECT (textual + semantic vs A)
//!   D (error semantics contract)        -> REJECT (policy CANON-31)
//!   E (tests, depends on A)             -> ACCEPT (after A merges)

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use wreck_adapters::{LocalGit, LocalMergePort};
use wreck_governor::Governor;
use wreck_graph::ChangeView;
use wreck_protocol::{
    ChangeClaim, Claim, ClaimKind, DecisionRecord, Evidence, EvidenceKind, ScopeItem, Sha, Verdict,
};

mod dashboard;

fn auth_baseline() -> Vec<String> {
    let mut lines: Vec<String> = vec![];
    lines.push("// auth.rs — baseline".into());
    lines.push("use std::time::Duration;".into());
    lines.push("".into());
    lines.push("pub struct Token { pub raw: String }".into());
    lines.push("pub struct Config { pub timeout: Duration }".into());
    lines.push("".into());
    lines.push("// ---- section: validation ----".into());
    lines.push("".into());
    // lines 9..=39 (1-indexed): validate_token, 31 lines
    for i in 9..=39 {
        lines.push(format!("fn validate_token_{}() {{ /* validation logic {} */ }}", i, i));
    }
    // 40..=44 separator
    for i in 40..=44 {
        lines.push(format!("// sep {}", i));
    }
    // 45..=75: token_expiry, 31 lines
    for i in 45..=75 {
        lines.push(format!("fn token_expiry_{}() {{ /* expiry logic {} */ }}", i, i));
    }
    // 76..=79 separator
    for i in 76..=79 {
        lines.push(format!("// sep {}", i));
    }
    // 80..=110: retry_policy, 31 lines
    for i in 80..=110 {
        lines.push(format!("fn retry_policy_{}() {{ /* retry logic {} */ }}", i, i));
    }
    // 111..=114 separator
    for i in 111..=114 {
        lines.push(format!("// sep {}", i));
    }
    // 115..=135: error handler, 21 lines
    for i in 115..=135 {
        lines.push(format!("fn handle_auth_error_{}() {{ /* error logic {} */ }}", i, i));
    }
    assert_eq!(lines.len(), 135);
    lines
}

/// Replace 1-indexed inclusive line range with new lines.
fn replace_lines(mut lines: Vec<String>, start: usize, end: usize, with: Vec<String>) -> String {
    let mut out: Vec<String> = lines.drain(..start - 1).collect();
    out.extend(with);
    out.extend(lines.drain(end - (start - 1)..));
    out.join("\n") + "\n"
}

fn mk_claim(
    id: &str,
    agent: &str,
    base: Sha,
    head: Sha,
    intent: &str,
    scope: Vec<ScopeItem>,
    invariants: &[&str],
) -> (ChangeClaim, Vec<String>) {
    let mut c = ChangeClaim::propose(id, agent, "task-auth-001", base, head, intent);
    c.scope = scope;
    c.claims.push(Claim {
        id: "C1".into(),
        statement: format!("{} preserves API compatibility", id),
        kind: ClaimKind::PreservesApi,
    });
    c.claims.push(Claim {
        id: "C2".into(),
        statement: format!("{} passes its invariants", id),
        kind: ClaimKind::PassesInvariant { invariant: invariants.join(",") },
    });
    c.evidence.push(Evidence {
        id: "C1-E1".into(),
        kind: EvidenceKind::Test,
        reference: "C1: test validate_compat".into(),
        digest: "sha256:deadbeef".into(),
    });
    c.evidence.push(Evidence {
        id: "C2-E1".into(),
        kind: EvidenceKind::Oracle,
        reference: "C2: oracle 31".into(),
        digest: "sha256:cafef00d".into(),
    });
    (c, invariants.iter().map(|s| s.to_string()).collect())
}

fn main() {
    let root = PathBuf::from("/tmp/wreck-demo");
    let _ = std::fs::remove_dir_all(&root);
    let git = LocalGit::new(&root);

    println!("== wreck demo: 5 agents, one auth subsystem ==\n");

    // ---- baseline ----
    let base_lines = auth_baseline();
    let base_content = base_lines.join("\n") + "\n";
    let err_baseline = "// auth_err.rs — baseline\npub fn err_kind() -> u32 { 0 }\n";
    let base = git
        .init_baseline(&[("src/auth.rs", &base_content), ("src/auth_err.rs", err_baseline)])
        .expect("init baseline");
    println!("baseline: {}", &base.as_str()[..12]);

    // ---- agent changes: (id, agent, line-range or file, new content, scope, invariants, deps) ----
    struct AgentWork {
        id: &'static str,
        agent: &'static str,
        intent: &'static str,
        edit: Edit,
        scope: Vec<ScopeItem>,
        invariants: Vec<&'static str>,
        deps: Vec<&'static str>,
    }
    enum Edit {
        Lines { start: usize, end: usize, with: Vec<String> },
        File { path: &'static str, content: String },
    }

    let works = vec![
        AgentWork { // A: token validation
            id: "change-a", agent: "agent-a", intent: "harden token validation",
            edit: Edit::Lines { start: 9, end: 39,
                with: (9..=39).map(|i| format!("fn validate_token_{}() {{ /* HARDENED {} */ }}", i, i)).collect() },
            scope: vec![ScopeItem::File { path: "src/auth.rs".into() },
                        ScopeItem::Symbol { name: "validate_token".into() }],
            invariants: vec!["AUTH-03"], deps: vec![],
        },
        AgentWork { // B: token expiry — same file, disjoint
            id: "change-b", agent: "agent-b", intent: "shorten token expiry",
            edit: Edit::Lines { start: 45, end: 75,
                with: (45..=75).map(|i| format!("fn token_expiry_{}() {{ /* SHORTER {} */ }}", i, i)).collect() },
            scope: vec![ScopeItem::File { path: "src/auth.rs".into() },
                        ScopeItem::Symbol { name: "token_expiry".into() }],
            invariants: vec!["AUTH-07"], deps: vec![],
        },
        AgentWork { // C: retry — overlaps A textually AND shares AUTH-03
            id: "change-c", agent: "agent-c", intent: "aggressive retry policy",
            edit: Edit::Lines { start: 30, end: 45,
                with: (30..=45).map(|i| format!("fn retry_policy_{}() {{ /* AGGRESSIVE {} */ }}", i, i)).collect() },
            scope: vec![ScopeItem::File { path: "src/auth.rs".into() },
                        ScopeItem::Symbol { name: "retry_policy".into() }],
            invariants: vec!["AUTH-03"], deps: vec![],
        },
        AgentWork { // D: error semantics — forbidden contract
            id: "change-d", agent: "agent-d", intent: "rewrite error handling",
            edit: Edit::File { path: "src/auth_err.rs",
                content: "// auth_err.rs — REWRITTEN\npub fn err_kind() -> u32 { 1 }\n".into() },
            scope: vec![ScopeItem::File { path: "src/auth_err.rs".into() },
                        ScopeItem::Contract { id: "auth.error-semantics".into() }],
            invariants: vec![], deps: vec![],
        },
        AgentWork { // E: tests — depends on A
            id: "change-e", agent: "agent-e", intent: "cover new validation",
            edit: Edit::File { path: "tests/auth_test.rs",
                content: "// tests\n#[test]\nfn validation_hardened() { assert!(true) }\n".into() },
            scope: vec![ScopeItem::File { path: "tests/auth_test.rs".into() }],
            invariants: vec![], deps: vec!["change-a"],
        },
    ];

    // ---- each agent forks, works, pushes (commits), proposes ----
    let mut claims: Vec<ChangeClaim> = vec![];
    let mut views: Vec<ChangeView> = vec![];
    let mut forks: HashMap<String, PathBuf> = HashMap::new();
    for w in &works {
        let fork = git.fork(w.id).expect("fork");
        let new_content: Vec<(&str, String)> = match &w.edit {
            Edit::Lines { start, end, with } => {
                vec![("src/auth.rs", replace_lines(base_lines.clone(), *start, *end, with.clone()))]
            }
            Edit::File { path, content } => vec![(*path, content.clone())],
        };
        let refs: Vec<(&str, &str)> = new_content.iter().map(|(p, c)| (*p, c.as_str())).collect();
        let head = git.commit_change(&fork, &refs, &format!("{}: {}", w.id, w.intent)).expect("commit");
        let (claim, invs) = mk_claim(w.id, w.agent, base.clone(), head.clone(), w.intent, w.scope.clone(), &w.invariants);
        let mut view = git.diff_view(w.id, &w.scope, &fork, &base, &head).expect("diff");
        // symbols: measured via tree-sitter, not declared
        git.measure_symbols(&fork, &head, &mut view).expect("measure");
        view.invariants = invs;
        view.dependencies = w.deps.iter().map(|s| s.to_string()).collect();
        forks.insert(w.id.to_string(), fork);
        claims.push(claim);
        views.push(view);
        println!("{} proposed {} -> {}", w.agent, w.id, &head.as_str()[..12]);
    }

    // ---- governor: arrival order, each checked against all previous ----
    // Policy derives from CANON: the rules carry their own WHY.
    let canon = wreck_canon::demo_canon();
    let policy = canon.to_policy();
    println!("canon rules active: {}", canon.active().len());
    let mut gov = Governor::new(policy, b"demo-authority-key-32bytes-padded!".to_vec(), "governor");
    let port = LocalMergePort { baseline: git.baseline_path(), forks };
    let mut merged: HashSet<String> = HashSet::new();
    let mut seen: Vec<ChangeView> = vec![];

    println!("\n+=========== CHANGE FIELD ===========+");
    let mut stats = (0usize, 0usize, 0usize); // accepted, rejected, blocked
    let mut decisions: Vec<Option<DecisionRecord>> = vec![None; claims.len()];
    for (idx, (claim, view)) in claims.iter_mut().zip(views.iter()).enumerate() {
        // re-evaluate blocked claims after each merge (dependency may clear)
        let ts = "2026-10-08T21:30:00Z";
        let d = gov.evaluate(claim, view, &seen, &merged, &port, ts).expect("evaluate");
        let seal: String = d.receipt.get("seal").and_then(|v| v.as_str()).unwrap_or("?")[..12].into();
        match &d.verdict {
            Verdict::Accept => {
                stats.0 += 1;
                merged.insert(claim.change_id.clone());
                println!("  {:<10} ACCEPT   seal {}   status {:?}", claim.agent_id, seal, claim.status);
            }
            Verdict::Reject { reason, rule } => {
                stats.1 += 1;
                println!("  {:<10} REJECT   [{}] {}   seal {}", claim.agent_id, rule, short(reason), seal);
            }
            Verdict::Blocked { by } => {
                stats.2 += 1;
                println!("  {:<10} BLOCKED  waiting on {:?}   seal {}", claim.agent_id, by, seal);
            }
            Verdict::NeedsRebase { onto } => {
                println!("  {:<10} REBASE   onto {}   seal {}", claim.agent_id, &onto[..12.min(onto.len())], seal);
            }
        }
        decisions[idx] = Some(d);
        seen.push(view.clone());
    }
    // second pass: retry anything still blocked (E waits on A)
    for (idx, (claim, view)) in claims.iter_mut().zip(views.iter()).enumerate() {
        if !matches!(claim.status, wreck_protocol::ChangeStatus::Proven) {
            continue;
        }
        let d = gov.evaluate(claim, view, &seen, &merged, &port, "2026-10-08T21:31:00Z").expect("re-evaluate");
        let seal: String = d.receipt.get("seal").and_then(|v| v.as_str()).unwrap_or("?")[..12].into();
        match &d.verdict {
            Verdict::Accept => {
                stats.0 += 1;
                stats.2 -= 1;
                merged.insert(claim.change_id.clone());
                println!("  {:<10} ACCEPT   (retry after dependency) seal {}", claim.agent_id, seal);
            }
            other => println!("  {:<10} still {:?} seal {}", claim.agent_id, other, seal),
        }
        decisions[idx] = Some(d);
    }
    println!("+====================================+");
    println!("\n  5 agents  |  5 changes  |  {} accepted  |  {} rejected  |  {} blocked", stats.0, stats.1, stats.2);
    println!("  human merge decisions: 0");
    println!("  decisions sealed: {}", gov.decisions_sealed());

    // ---- verify the baseline actually contains A, B, E and not C, D ----
    let final_head = git.baseline_path();
    let log_out = std::process::Command::new("git")
        .args(["log", "--oneline"])
        .current_dir(&final_head)
        .output()
        .unwrap();
    let log_str = String::from_utf8_lossy(&log_out.stdout).to_string();
    println!("\nbaseline log:\n{}", log_str);

    // ---- dashboard ----
    let rows: Vec<dashboard::Row> = claims
        .iter()
        .zip(views.iter())
        .zip(decisions.iter())
        .map(|((claim, view), d)| {
            let d = d.as_ref().expect("decision per claim");
            let (verdict, badge_class, detail) = match &d.verdict {
                Verdict::Accept => ("ACCEPT".to_string(), "accept".to_string(), "all checks passed".to_string()),
                Verdict::Reject { reason, rule } => {
                    ("REJECT".to_string(), "reject".to_string(), format!("[{}] {}", rule, short(reason)))
                }
                Verdict::Blocked { by } => {
                    ("BLOCKED".to_string(), "blocked".to_string(), format!("waiting on {:?}", by))
                }
                Verdict::NeedsRebase { onto } => {
                    ("REBASE".to_string(), "blocked".to_string(), format!("onto {}", &onto[..12.min(onto.len())]))
                }
            };
            dashboard::Row {
                agent: claim.agent_id.clone(),
                change_id: claim.change_id.clone(),
                verdict,
                badge_class,
                detail,
                conflicts: d.conflicts.iter().map(|c| format!("[{:?}] {}", c.kind, c.detail)).collect(),
                seal: d.receipt.get("seal").and_then(|v| v.as_str()).unwrap_or("?")[..12].to_string(),
                status: format!("{:?}", claim.status),
                files: view.files.iter().map(|f| f.path.clone()).collect(),
                invariants: view.invariants.clone(),
            }
        })
        .collect();
    let html = dashboard::render(
        "task-auth-001 — improve authentication",
        &rows,
        &dashboard::Stats {
            agents: 5,
            changes: claims.len(),
            accepted: stats.0,
            rejected: stats.1,
            blocked: stats.2,
            sealed: gov.decisions_sealed(),
        },
        &log_str,
    );
    let dash_path = root.join("dashboard.html");
    std::fs::write(&dash_path, html).expect("write dashboard");
    println!("\ndashboard: {}", dash_path.display());

    // ---- assertions: the demo contract ----
    let status = |id: &str| claims.iter().find(|c| c.change_id == id).unwrap().status;
    use wreck_protocol::ChangeStatus::*;
    assert_eq!(status("change-a"), Merged, "A must merge");
    assert_eq!(status("change-b"), Merged, "B must merge");
    assert_eq!(status("change-c"), Rejected, "C must be rejected (conflict vs A)");
    assert_eq!(status("change-d"), Rejected, "D must be rejected (policy)");
    assert_eq!(status("change-e"), Merged, "E must merge after A");
    println!("\nDEMO CONTRACT HOLDS: A,B,E merged | C,D rejected | 0 human merges");
}

fn short(s: &str) -> String {
    if s.len() > 90 {
        format!("{}...", &s[..90])
    } else {
        s.to_string()
    }
}
