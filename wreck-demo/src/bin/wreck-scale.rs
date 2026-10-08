//! wreck-scale: N-agent coordination proof.
//!
//! Spawns K agents against one baseline. Most edit disjoint regions
//! (compatible); a planted minority collide textually, semantically,
//! or against policy. The governor classifies all of them with zero
//! human merges. Measures decisions/sec and receipt sealing.
//!
//! Usage: wreck-scale [num_agents]  (default 50)

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Instant;
use wreck_adapters::{LocalGit, LocalMergePort};
use wreck_governor::Governor;
use wreck_graph::ChangeView;
use wreck_protocol::{
    ChangeClaim, Claim, ClaimKind, Evidence, EvidenceKind, ScopeItem, Sha, Verdict,
};

fn baseline(nfiles: usize, lines_per: usize) -> Vec<(String, String)> {
    (0..nfiles)
        .map(|f| {
            let content = (1..=lines_per)
                .map(|l| format!("// file{} line{}: baseline content", f, l))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            (format!("src/mod{}.rs", f), content)
        })
        .collect()
}

fn main() {
    let k: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let root = PathBuf::from("/tmp/wreck-scale");
    let _ = std::fs::remove_dir_all(&root);
    let git = LocalGit::new(&root);

    // 10 files x 200 lines: plenty of disjoint room
    let files = baseline(10, 200);
    let file_refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    let base = git.init_baseline(&file_refs).expect("init");
    let base_text: HashMap<String, Vec<String>> = files
        .into_iter()
        .map(|(p, c)| (p, c.lines().map(|s| s.to_string()).collect()))
        .collect();

    let canon = wreck_canon::demo_canon();
    let mut gov = Governor::new(
        canon.to_policy(),
        b"scale-authority-key-32bytes-padded".to_vec(),
        "governor",
    );

    // Plant the collision plan (deterministic):
    // - agents 0..k-8: disjoint 10-line regions (compatible)
    // - agent k-7: textual collision with agent 0 (same lines)
    // - agent k-6: semantic collision with agent 1 (same invariant AUTH-03)
    // - agent k-5: policy violation (contract auth.error-semantics)
    // - agent k-4..k-1: disjoint (compatible)
    let t0 = Instant::now();
    let mut claims = vec![];
    let mut views = vec![];
    let mut forks = HashMap::new();

    for i in 0..k {
        let id = format!("scale-{:03}", i);
        // region assignment
        let (file_idx, start, kind) = if i == k - 7 {
            (0, 11, "collide-text") // same as agent 0
        } else if i == k - 6 {
            (1, 31, "collide-sem")
        } else if i == k - 5 {
            (0, 0, "policy")
        } else {
            // disjoint: agent i -> file (i%10), lines 11+20*(i/10)
            let fi = i % 10;
            let start = 11 + 20 * (i / 10);
            (fi, start as u32, "clean")
        };
        let path = format!("src/mod{}.rs", file_idx);
        let fork = git.fork(&id).expect("fork");

        let (new_content, scope, invariants) = match kind {
            "policy" => (
                "// rewritten error semantics\n".to_string(),
                vec![
                    ScopeItem::File { path: path.clone() },
                    ScopeItem::Contract {
                        id: "auth.error-semantics".into(),
                    },
                ],
                vec![],
            ),
            _ => {
                let lines = base_text[&path].clone();
                let end = (start + 9).min(200) as usize;
                let with: Vec<String> = ((start as usize)..=end)
                    .map(|l| format!("// file{} line{}: agent{} edit", file_idx, l, i))
                    .collect();
                let mut out: Vec<String> = lines[..(start as usize - 1)].to_vec();
                out.extend(with);
                out.extend(lines[end..].to_vec());
                let content = out.join("\n") + "\n";
                let inv = if kind == "collide-sem" || i == 1 {
                    vec!["AUTH-03"]
                } else {
                    vec![]
                };
                (
                    content,
                    vec![
                        ScopeItem::File { path: path.clone() },
                        ScopeItem::Symbol {
                            name: format!("sym_{}", i),
                        },
                    ],
                    inv,
                )
            }
        };
        let head = git
            .commit_change(&fork, &[(&path, &new_content)], &format!("{}: work", id))
            .expect("commit");

        let mut c = ChangeClaim::propose(
            &id,
            &format!("agent-{}", i),
            "task-scale",
            base.clone(),
            head.clone(),
            "scale work",
        )
        .expect("valid change_id");
        c.scope = scope.clone();
        c.claims.push(Claim {
            id: "C1".into(),
            statement: "safe".into(),
            kind: ClaimKind::PreservesApi,
        });
        c.evidence.push(Evidence {
            id: "C1-E1".into(),
            kind: EvidenceKind::Test,
            reference: "C1: test scale".into(),
            digest: "sha256:x".into(),
        });
        let mut v = git
            .diff_view(&id, &scope, &fork, &base, &head)
            .expect("diff");
        v.invariants = invariants.into_iter().map(|s| s.to_string()).collect();
        forks.insert(id.clone(), fork);
        claims.push(c);
        views.push(v);
    }
    let setup_ms = t0.elapsed().as_millis();

    // govern in arrival order
    let port = LocalMergePort {
        baseline: git.baseline_path(),
        forks,
    };
    let mut merged: HashSet<String> = HashSet::new();
    let mut seen: Vec<ChangeView> = vec![];
    let (mut acc, mut rej) = (0, 0);
    let g0 = Instant::now();
    for (claim, view) in claims.iter_mut().zip(views.iter()) {
        let d = gov
            .evaluate(claim, view, &seen, &merged, &port, "2026-10-08T22:00:00Z")
            .expect("evaluate");
        match d.verdict {
            Verdict::Accept => {
                acc += 1;
                merged.insert(claim.change_id.clone());
            }
            Verdict::Reject { .. } => rej += 1,
            _ => rej += 1,
        }
        seen.push(view.clone());
    }
    let gov_ms = g0.elapsed().as_millis();

    println!("wreck-scale: {} agents", k);
    println!("  setup (fork+commit): {} ms", setup_ms);
    println!(
        "  governed: {} ms  ({:.1} decisions/sec)",
        gov_ms,
        k as f64 / (gov_ms.max(1) as f64 / 1000.0)
    );
    println!("  accepted: {}  rejected: {}", acc, rej);
    println!("  decisions sealed: {}", gov.decisions_sealed());
    println!("  human merges: 0");

    // expectations: k-3 clean accepts, 3 planted rejects
    assert_eq!(acc, k - 3, "all clean agents must merge");
    assert_eq!(rej, 3, "exactly the 3 planted collisions reject");
    println!("SCALE CONTRACT HOLDS");
}
