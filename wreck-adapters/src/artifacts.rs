//! Artifacts substrate adapter — the Cloudflare port.
//!
//! Implements the same traits as [`crate::LocalGit`] against real
//! Cloudflare Artifacts: REST control plane for lifecycle, git data plane
//! for pushes, repo-scoped tokens as the trust boundary.
//!
//! Spec: `docs/artifacts-adapter-spec.md` (verified against official docs
//! 2026-10-08). Live verification pending Workers Paid access.
//!
//! URL shapes and payload shapes are pure and unit-tested; HTTP calls go
//! through [`ArtifactsClient`] and are integration-tested live later.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use wreck_graph::{ChangeView, FileChange};
use wreck_protocol::{ChangeClaim, ScopeItem, Sha};

// ---------------------------------------------------------------------------
// pure URL + payload construction (unit-tested, no network)
// ---------------------------------------------------------------------------

pub fn v4_base(account_id: &str) -> String {
    format!("https://api.cloudflare.com/client/v4/accounts/{}", account_id)
}

pub fn ns_base(account_id: &str, namespace: &str) -> String {
    format!("{}/artifacts/namespaces/{}", v4_base(account_id), namespace)
}

/// Git data-plane remote for a repo.
pub fn git_remote(account_id: &str, namespace: &str, repo: &str) -> String {
    format!(
        "https://{}.artifacts.cloudflare.net/git/{}/{}.git",
        account_id, namespace, repo
    )
}

/// Split `art_v1_<hex>?expires=<unix>` into (secret, expires).
/// The git basic-auth form needs the secret WITHOUT the ?expires= suffix.
pub fn split_token(plaintext: &str) -> Result<(String, String), String> {
    let (secret, query) = plaintext
        .split_once('?')
        .ok_or("artifacts: token missing ?expires=")?;
    if !secret.starts_with("art_v1_") {
        return Err("artifacts: token missing art_v1_ prefix".into());
    }
    let expires = query
        .strip_prefix("expires=")
        .ok_or("artifacts: token query not expires=")?;
    Ok((secret.to_string(), expires.to_string()))
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateNamespace {
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRepo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_branch: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForkRepo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_branch_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MintToken {
    pub repo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct V4Envelope<T> {
    pub result: T,
    pub success: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRepoResult {
    pub name: String,
    pub remote: String,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MintTokenResult {
    pub id: String,
    pub plaintext: String,
    pub scope: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoStatus {
    pub name: String,
    pub status: String, // ready|importing|forking
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: String, // blob|tree
    pub hash: String,
    pub path: String,
}

/// Push-event payload shape (for the queue consumer).
#[derive(Debug, Clone, Deserialize)]
pub struct PushedEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub source: PushedSource,
    pub payload: PushedPayload,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushedSource {
    #[serde(rename = "type")]
    pub source_type: String,
    pub namespace: String,
    #[serde(rename = "repoName")]
    pub repo_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushedPayload {
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub before: String,
    pub after: String,
}

impl PushedEvent {
    /// Idempotency key: (namespace, repo, ref, before, after).
    pub fn dedup_key(&self) -> String {
        format!(
            "wreck:seen:{}:{}:{}:{}:{}",
            self.source.namespace,
            self.source.repo_name,
            self.payload.git_ref,
            self.payload.before,
            self.payload.after
        )
    }
    /// The governor's own merge pushes must never be re-governed.
    pub fn is_baseline(&self, baseline_repo: &str) -> bool {
        self.source.repo_name == baseline_repo
    }
}

// ---------------------------------------------------------------------------
// HTTP client (REST control plane)
// ---------------------------------------------------------------------------

pub struct ArtifactsClient {
    account_id: String,
    namespace: String,
    api_token: String,
    agent: ureq::Agent,
}

impl ArtifactsClient {
    pub fn new(account_id: &str, namespace: &str, api_token: &str) -> Self {
        ArtifactsClient {
            account_id: account_id.to_string(),
            namespace: namespace.to_string(),
            api_token: api_token.to_string(),
            agent: ureq::Agent::new(),
        }
    }

    fn post<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &impl Serialize,
    ) -> Result<T, String> {
        let resp = self
            .agent
            .post(url)
            .set("Authorization", &format!("Bearer {}", self.api_token))
            .send_json(body)
            .map_err(|e| format!("artifacts POST {}: {}", url, e))?;
        let env: V4Envelope<T> = resp.into_json().map_err(|e| format!("artifacts json: {}", e))?;
        if !env.success {
            return Err(format!("artifacts API success=false for {}", url));
        }
        Ok(env.result)
    }

    fn get<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, String> {
        let resp = self
            .agent
            .get(url)
            .set("Authorization", &format!("Bearer {}", self.api_token))
            .call()
            .map_err(|e| format!("artifacts GET {}: {}", url, e))?;
        let env: V4Envelope<T> = resp.into_json().map_err(|e| format!("artifacts json: {}", e))?;
        if !env.success {
            return Err(format!("artifacts API success=false for {}", url));
        }
        Ok(env.result)
    }

    fn delete(&self, url: &str) -> Result<(), String> {
        self.agent
            .delete(url)
            .set("Authorization", &format!("Bearer {}", self.api_token))
            .call()
            .map_err(|e| format!("artifacts DELETE {}: {}", url, e))?;
        Ok(())
    }

    fn get_bytes(&self, url: &str) -> Result<Vec<u8>, String> {
        let resp = self
            .agent
            .get(url)
            .set("Authorization", &format!("Bearer {}", self.api_token))
            .call()
            .map_err(|e| format!("artifacts GET {}: {}", url, e))?;
        let mut buf = vec![];
        use std::io::Read;
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| format!("artifacts read: {}", e))?;
        Ok(buf)
    }

    pub fn ensure_namespace(&self, jurisdiction: Option<&str>) -> Result<(), String> {
        let url = format!("{}/artifacts/namespaces", v4_base(&self.account_id));
        let body = CreateNamespace {
            namespace: self.namespace.clone(),
            jurisdiction: jurisdiction.map(|s| s.to_string()),
        };
        // 409/duplicate = already exists; treat "already exists" as success.
        match self.post::<serde_json::Value>(&url, &body) {
            Ok(_) => Ok(()),
            Err(e) if e.contains("409") || e.to_lowercase().contains("already exists") => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn create_repo(&self, name: &str) -> Result<CreateRepoResult, String> {
        let url = format!("{}/repos", ns_base(&self.account_id, &self.namespace));
        self.post(
            &url,
            &CreateRepo {
                name: name.to_string(),
                description: None,
                default_branch: Some("main".to_string()),
            },
        )
    }

    pub fn fork_repo(&self, from: &str, name: &str) -> Result<CreateRepoResult, String> {
        let url = format!("{}/repos/{}/fork", ns_base(&self.account_id, &self.namespace), from);
        // 409 while provisioning = retriable; the caller polls readiness anyway.
        self.post(
            &url,
            &ForkRepo {
                name: name.to_string(),
                default_branch_only: Some(true),
            },
        )
    }

    pub fn repo_ready(&self, name: &str) -> Result<bool, String> {
        let url = format!("{}/repos", ns_base(&self.account_id, &self.namespace));
        let list: Vec<RepoStatus> = self.get(&url)?;
        Ok(list.iter().any(|r| r.name == name && r.status == "ready"))
    }

    pub fn mint_token(&self, repo: &str, ttl_secs: u64) -> Result<MintTokenResult, String> {
        let url = format!("{}/tokens", ns_base(&self.account_id, &self.namespace));
        self.post(
            &url,
            &MintToken {
                repo: repo.to_string(),
                scope: Some("write".to_string()),
                ttl: Some(ttl_secs),
            },
        )
    }

    pub fn revoke_token(&self, token_id: &str) -> Result<(), String> {
        let url = format!("{}/tokens/{}", ns_base(&self.account_id, &self.namespace), token_id);
        self.delete(&url)
    }

    pub fn delete_repo(&self, name: &str) -> Result<(), String> {
        // 202 Accepted: async delete; the name may linger briefly.
        let url = format!("{}/repos/{}", ns_base(&self.account_id, &self.namespace), name);
        self.delete(&url)
    }

    /// Recursive tree walk: returns (path -> blob hash) for all blobs.
    pub fn tree_blobs(&self, repo: &str, hash: &str) -> Result<HashMap<String, String>, String> {
        let mut out = HashMap::new();
        let mut stack = vec![(hash.to_string(), String::new())];
        while let Some((h, prefix)) = stack.pop() {
            let url = format!(
                "{}/repos/{}/tree/{}",
                ns_base(&self.account_id, &self.namespace),
                repo,
                h
            );
            let entries: Vec<TreeEntry> = self.get(&url)?;
            for e in entries {
                let path = if prefix.is_empty() {
                    e.path.clone()
                } else {
                    format!("{}/{}", prefix, e.path)
                };
                if e.entry_type == "tree" {
                    stack.push((e.hash, path));
                } else {
                    out.insert(path, e.hash);
                }
            }
        }
        Ok(out)
    }

    pub fn blob_bytes(&self, repo: &str, hash: &str) -> Result<Vec<u8>, String> {
        let url = format!(
            "{}/repos/{}/blob/{}",
            ns_base(&self.account_id, &self.namespace),
            repo,
            hash
        );
        self.get_bytes(&url)
    }
}

// ---------------------------------------------------------------------------
// ChangeView from (before, after): tree-walk + local line diff
// ---------------------------------------------------------------------------

/// Compute added/removed line ranges between two blob texts via git.
/// (Shells to git --no-index: the same -U0 parser as the local adapter,
/// one implementation of the diff semantics.)
fn diff_ranges(old: &[u8], new: &[u8]) -> Result<(Vec<(u32, u32)>, Vec<(u32, u32)>), String> {
    let dir = std::env::temp_dir().join(format!("wreck-diff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("a"), old).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("b"), new).map_err(|e| e.to_string())?;
    let out = std::process::Command::new("git")
        .args(["diff", "--no-index", "-U0", "a", "b"])
        .current_dir(&dir)
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);
    // exit code 1 = differences found; that is the success case here
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_unified_zero(&text))
}

fn parse_unified_zero(diff: &str) -> (Vec<(u32, u32)>, Vec<(u32, u32)>) {
    let mut added = vec![];
    let mut removed = vec![];
    for line in diff.lines() {
        let line = line.trim();
        if !line.starts_with("@@") {
            continue;
        }
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

impl ArtifactsClient {
    /// Build the mechanical ChangeView from (before, after) SHAs.
    /// No server-side diff exists: walk both trees, compare blob hashes,
    /// diff changed blobs locally for line ranges.
    pub fn diff_view(
        &self,
        change_id: &str,
        scope: &[ScopeItem],
        repo: &str,
        before: &Sha,
        after: &Sha,
    ) -> Result<ChangeView, String> {
        let mut view = ChangeView::from_scope(change_id, scope);
        let old_tree = self.tree_blobs(repo, before.as_str())?;
        let new_tree = self.tree_blobs(repo, after.as_str())?;
        let mut paths: Vec<String> =
            old_tree.keys().chain(new_tree.keys()).cloned().collect();
        paths.sort();
        paths.dedup();
        let mut measured: HashMap<String, FileChange> = HashMap::new();
        for path in paths {
            let oh = old_tree.get(&path);
            let nh = new_tree.get(&path);
            if oh == nh {
                continue;
            }
            let old_bytes = match oh {
                Some(h) => self.blob_bytes(repo, h)?,
                None => vec![],
            };
            let new_bytes = match nh {
                Some(h) => self.blob_bytes(repo, h)?,
                None => vec![],
            };
            // skip likely-binary blobs (32MB cap means this is bounded anyway)
            if old_bytes.contains(&0) || new_bytes.contains(&0) {
                measured.insert(
                    path.clone(),
                    FileChange { path: path.clone(), added: vec![], removed: vec![] },
                );
                continue;
            }
            let (added, removed) = diff_ranges(&old_bytes, &new_bytes)?;
            measured.insert(path.clone(), FileChange { path, added, removed });
        }
        for f in view.files.iter_mut() {
            if let Some(m) = measured.remove(&f.path) {
                *f = m;
            }
        }
        for (_, m) in measured {
            view.files.push(m);
        }
        Ok(view)
    }
}

// ---------------------------------------------------------------------------
// MergePort over Artifacts: git data-plane merge with the governor token
// ---------------------------------------------------------------------------

pub struct ArtifactsMergePort {
    pub baseline_remote: String,
    /// repo-scoped write token for the BASELINE repo (governor-held).
    /// Stored as the full `art_v1_...?expires=...` string; the secret part
    /// is extracted at use time and never logged.
    pub governor_token: String,
    pub workdir: PathBuf,
}

impl ArtifactsMergePort {
    fn git(&self, dir: &Path, args: &[&str], token_secret: &str) -> Result<String, String> {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "wreck-governor")
            .env("GIT_AUTHOR_EMAIL", "wreck@local")
            .env("GIT_COMMITTER_NAME", "wreck-governor")
            .env("GIT_COMMITTER_EMAIL", "wreck@local")
            .env(
                "GIT_HTTP_EXTRAHEADER",
                format!("Authorization: Bearer {}", token_secret),
            )
            .output()
            .map_err(|e| format!("artifacts git: {}", e))?;
        if !out.status.success() {
            return Err(format!(
                "artifacts git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

impl wreck_governor::MergePort for ArtifactsMergePort {
    fn name(&self) -> &str {
        "artifacts"
    }

    fn merge(&self, change: &ChangeClaim) -> Result<Sha, String> {
        let (secret, _) = split_token(&self.governor_token)?;
        // fresh clone of baseline (shallow: we only need the tip + merge)
        let dir = self.workdir.join(format!("merge-{}", change.change_id));
        let _ = std::fs::remove_dir_all(&dir);
        let parent = dir.parent().unwrap();
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        // NOTE: the fork head must be fetchable; the agent's fork remote is
        // derived from the change metadata in production. Here the caller
        // stages it via `stage_fork_head`.
        self.git(parent, &["clone", "--quiet", "--depth", "1", &self.baseline_remote, dir.to_str().unwrap()], &secret)?;
        let fork_remote = std::env::var(format!("WRECK_FORK_{}", change.change_id))
            .map_err(|_| "artifacts merge: fork remote not staged (WRECK_FORK_<id>)".to_string())?;
        // fetch the fork head by SHA using the AGENT's token is wrong —
        // the governor fetches via its own baseline token only if the fork
        // grants it; in production the fork is in the same namespace and
        // the governor holds a read token for it. Simplified here.
        self.git(&dir, &["fetch", "--depth", "1", &fork_remote, change.head.as_str()], &secret)?;
        self.git(
            &dir,
            &["merge", "--no-ff", "-m", &format!("wreck: merge {}", change.change_id), "FETCH_HEAD"],
            &secret,
        )?;
        self.git(&dir, &["push", "origin", "main"], &secret)?;
        let sha = self.git(&dir, &["rev-parse", "HEAD"], &secret)?;
        let _ = std::fs::remove_dir_all(&dir);
        Sha::new(&sha)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_shapes() {
        assert_eq!(
            ns_base("aid1", "wreck"),
            "https://api.cloudflare.com/client/v4/accounts/aid1/artifacts/namespaces/wreck"
        );
        assert_eq!(
            git_remote("aid1", "wreck", "task-1"),
            "https://aid1.artifacts.cloudflare.net/git/wreck/task-1.git"
        );
    }

    #[test]
    fn token_split() {
        let t = "art_v1_abcd1234?expires=1791500000";
        let (secret, exp) = split_token(t).unwrap();
        assert_eq!(secret, "art_v1_abcd1234");
        assert_eq!(exp, "1791500000");
        assert!(split_token("nope").is_err());
        assert!(split_token("art_v1_x").is_err());
    }

    #[test]
    fn pushed_event_shapes() {
        let json = r#"{
            "type": "cf.artifacts.repo.pushed",
            "source": {"type": "artifacts.repo", "namespace": "wreck", "repoName": "task-0042"},
            "payload": {"ref": "refs/heads/main", "before": "aaa", "after": "bbb"}
        }"#;
        let e: PushedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(e.dedup_key(), "wreck:seen:wreck:task-0042:refs/heads/main:aaa:bbb");
        assert!(!e.is_baseline("baseline"));
        assert!(e.is_baseline("task-0042"));
        let mut e2 = e.clone();
        e2.source.repo_name = "baseline".into();
        assert!(e2.is_baseline("baseline"));
    }

    #[test]
    fn fork_payload_shape() {
        let f = ForkRepo { name: "task-1".into(), default_branch_only: Some(true) };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["name"], "task-1");
        assert_eq!(v["default_branch_only"], true);
    }
}
