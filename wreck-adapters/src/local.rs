//! Local-git substrate adapter.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use wreck_graph::{ChangeView, FileChange};
use wreck_protocol::{ChangeClaim, ScopeItem, Sha};

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        // fixed identity + dates: reproducible SHAs for the demo
        .env("GIT_AUTHOR_NAME", "wreck")
        .env("GIT_AUTHOR_EMAIL", "wreck@local")
        .env("GIT_COMMITTER_NAME", "wreck")
        .env("GIT_COMMITTER_EMAIL", "wreck@local")
        .env("GIT_AUTHOR_DATE", "2026-10-08T21:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2026-10-08T21:00:00+00:00")
        .output()
        .map_err(|e| format!("wreck-adapters: git failed to spawn: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "wreck-adapters: git {:?} failed in {}: {}",
            args,
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Parse `git diff -U0` hunk headers into added/removed ranges.
fn parse_unified_zero(diff: &str) -> (Vec<(u32, u32)>, Vec<(u32, u32)>) {
    let mut added = vec![];
    let mut removed = vec![];
    for line in diff.lines() {
        let line = line.trim();
        if !line.starts_with("@@") {
            continue;
        }
        // @@ -a[,b] +c[,d] @@
        let inner = line.trim_start_matches("@@").trim_end_matches("@@").trim();
        let mut parts = inner.split_whitespace();
        let old = parts.next().unwrap_or("");
        let new = parts.next().unwrap_or("");
        let pr = |s: &str| -> Option<(u32, u32)> {
            let s = s.trim_start_matches(['-', '+']);
            let mut it = s.split(',');
            let start: u32 = it.next()?.parse().ok()?;
            let count: u32 = it.next().map(|c| c.parse().ok()).unwrap_or(Some(1))?;
            if count == 0 {
                None
            } else {
                Some((start, start + count - 1))
            }
        };
        if let Some(r) = pr(old) {
            removed.push(r);
        }
        if let Some(r) = pr(new) {
            added.push(r);
        }
    }
    (added, removed)
}

/// Local-git substrate: a baseline repo plus one fork dir per change.
pub struct LocalGit {
    pub root: PathBuf,
}

impl LocalGit {
    pub fn new(root: &Path) -> Self {
        LocalGit { root: root.to_path_buf() }
    }

    pub fn baseline_path(&self) -> PathBuf {
        self.root.join("baseline")
    }

    pub fn fork_path(&self, name: &str) -> PathBuf {
        self.root.join("forks").join(name)
    }

    /// Create the baseline repo with the given files. Returns base SHA.
    pub fn init_baseline(&self, files: &[(&str, &str)]) -> Result<Sha, String> {
        let b = self.baseline_path();
        std::fs::create_dir_all(&b).map_err(|e| e.to_string())?;
        git(&b, &["init", "-b", "main"])?;
        for (path, content) in files {
            let p = b.join(path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, content).map_err(|e| e.to_string())?;
        }
        git(&b, &["add", "-A"])?;
        git(&b, &["commit", "-m", "wreck: baseline"])?;
        self.head_of(&b)
    }

    fn head_of(&self, repo: &Path) -> Result<Sha, String> {
        Sha::new(&git(repo, &["rev-parse", "HEAD"])?)
    }

    /// Fork = full local clone at base. (Artifacts does this server-side.)
    pub fn fork(&self, name: &str) -> Result<PathBuf, String> {
        let dest = self.fork_path(name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let b = self.baseline_path();
        let out = Command::new("git")
            .args(["clone", "--quiet", b.to_str().unwrap(), dest.to_str().unwrap()])
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("clone failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        Ok(dest)
    }

    /// Apply file writes in the fork and commit. Returns head SHA.
    pub fn commit_change(
        &self,
        fork: &Path,
        files: &[(&str, &str)],
        msg: &str,
    ) -> Result<Sha, String> {
        for (path, content) in files {
            let p = fork.join(path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, content).map_err(|e| e.to_string())?;
        }
        git(fork, &["add", "-A"])?;
        git(fork, &["commit", "-m", msg])?;
        self.head_of(fork)
    }

    /// Build the mechanical ChangeView from (base, head) via git diff.
    /// Symbols/invariants/contracts come from the claim's declared scope —
    /// text is measured, semantics are declared. That split is honest.
    pub fn diff_view(
        &self,
        change_id: &str,
        scope: &[ScopeItem],
        fork: &Path,
        base: &Sha,
        head: &Sha,
    ) -> Result<ChangeView, String> {
        let mut view = ChangeView::from_scope(change_id, scope);
        let names = git(fork, &["diff", "--name-only", base.as_str(), head.as_str()])?;
        // from_scope created empty FileChanges for declared files; replace
        // with measured ranges, keep declared-only entries as-is.
        let mut measured: HashMap<String, FileChange> = HashMap::new();
        for path in names.lines().filter(|l| !l.is_empty()) {
            let diff = git(fork, &["diff", "-U0", base.as_str(), head.as_str(), "--", path])?;
            let (added, removed) = parse_unified_zero(&diff);
            measured.insert(
                path.to_string(),
                FileChange { path: path.to_string(), added, removed },
            );
        }
        for f in view.files.iter_mut() {
            if let Some(m) = measured.remove(&f.path) {
                *f = m;
            }
        }
        for (_, m) in measured {
            view.files.push(m);
        }
        // invariants live on claims, not scope items: the harness passes them
        // via `invariants_of`; default empty here.
        Ok(view)
    }
}

/// MergePort over local git: single-writer merge into baseline main.
/// (The real single-writer lease is a Durable Object on Cloudflare;
/// locally, the governor process itself is the single writer.)
pub struct LocalMergePort {
    pub baseline: PathBuf,
    pub forks: HashMap<String, PathBuf>,
}

impl wreck_governor::MergePort for LocalMergePort {
    fn name(&self) -> &str {
        "local-git"
    }

    fn merge(&self, change: &ChangeClaim) -> Result<Sha, String> {
        let fork = self.forks.get(&change.change_id).ok_or_else(|| {
            format!("wreck-adapters: no fork registered for {}", change.change_id)
        })?;
        // fetch the fork's head into the baseline, then merge --no-ff
        git(&self.baseline, &["fetch", fork.to_str().unwrap(), change.head.as_str()])?;
        git(
            &self.baseline,
            &[
                "merge",
                "--no-ff",
                "-m",
                &format!("wreck: merge {}", change.change_id),
                "FETCH_HEAD",
            ],
        )?;
        Sha::new(&git(&self.baseline, &["rev-parse", "HEAD"])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        let p = std::env::temp_dir().join(format!("wreck-adapter-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn diff_view_measures_line_ranges() {
        let root = tmp();
        let g = LocalGit::new(&root);
        let base = g.init_baseline(&[("src/auth.rs", "line1\nline2\nline3\nline4\nline5\n")]).unwrap();
        let fork = g.fork("a").unwrap();
        let head = g
            .commit_change(&fork, &[("src/auth.rs", "line1\nLINE2\nline3\nline4\nline5\nline6\n")], "change a")
            .unwrap();
        let scope = vec![ScopeItem::File { path: "src/auth.rs".into() }];
        let v = g.diff_view("change-a", &scope, &fork, &base, &head).unwrap();
        assert_eq!(v.files.len(), 1);
        // line 2 replaced -> removed (2,2); line 6 added -> added (6,6); replacement shows as (2,2) added too
        let f = &v.files[0];
        assert!(f.removed.contains(&(2, 2)), "removed: {:?}", f.removed);
        assert!(f.added.iter().any(|(s, e)| *s <= 6 && *e >= 6) || f.added.contains(&(2, 2)),
            "added: {:?}", f.added);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_hunk_headers() {
        let d = "@@ -10,5 +12,7 @@ fn foo()\n@@ -0,0 +1,3 @@\n";
        let (added, removed) = parse_unified_zero(d);
        assert!(removed.contains(&(10, 14)));
        assert!(added.contains(&(12, 18)));
        assert!(added.contains(&(1, 3)));
    }
}
