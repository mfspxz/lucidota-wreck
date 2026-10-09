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
use std::io::Read as _;
use std::path::{Path, PathBuf};
use wreck_graph::{ChangeView, FileChange, SkippedFile};
use wreck_protocol::{ChangeClaim, ProvenanceEntry, ScopeItem, Sha};

// ---------------------------------------------------------------------------
// pure URL + payload construction (unit-tested, no network)
// ---------------------------------------------------------------------------

pub fn v4_base(account_id: &str) -> String {
    format!(
        "https://api.cloudflare.com/client/v4/accounts/{}",
        account_id
    )
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

/// H4 (cycle-06 audit): hand-written Debug — the repo token is shown once
/// by the API and must never appear in logs via a stray `{:?}`.
#[derive(Clone, Deserialize)]
pub struct CreateRepoResult {
    pub name: String,
    pub remote: String,
    pub token: String,
}

impl std::fmt::Debug for CreateRepoResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateRepoResult")
            .field("name", &self.name)
            .field("remote", &self.remote)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// H4 (cycle-06 audit): hand-written Debug — plaintext is shown once at
/// mint time; a derived Debug would print it into any debug log.
#[derive(Clone, Deserialize)]
pub struct MintTokenResult {
    pub id: String,
    pub plaintext: String,
    pub scope: String,
    pub expires_at: String,
}

impl std::fmt::Debug for MintTokenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintTokenResult")
            .field("id", &self.id)
            .field("plaintext", &"<redacted>")
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// One entry of the repo token inventory (`GET repos/:name/tokens`).
/// Carries NO plaintext: listings must never carry secret material (H4).
/// `scope`/`state` are optional because the live shape is unverified
/// pending Workers Paid; missing fields fail closed toward hiding.
#[derive(Debug, Clone, Deserialize)]
pub struct GitToken {
    pub id: String,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// User-held token class: what a user-facing inventory may show.
/// Mirrors the OS's listGitTokens filter (context-collection.ts:732-739):
/// only active write tokens are user-held. Internal / custodian tokens
/// (read scope, expired, revoked, or unknown shape) are never exposed.
pub fn is_user_held(t: &GitToken) -> bool {
    t.scope.as_deref() == Some("write") && t.state.as_deref() == Some("active")
}

/// On a freshly created repo, every token present must be platform
/// auto-created (nobody could have minted one yet). Pure: returns the ids
/// to revoke. Unit-tested without network.
fn tokens_to_revoke_on_create(tokens: &[GitToken]) -> Vec<String> {
    tokens.iter().map(|t| t.id.clone()).collect()
}

/// Result of [`ArtifactsClient::create_repo_clean`].
pub struct CleanRepo {
    pub result: CreateRepoResult,
    /// Ids of auto-created tokens that were revoked.
    pub revoked: Vec<String>,
    /// Non-fatal problems (revoke failures, inventory failures).
    pub warnings: Vec<String>,
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
        let env: V4Envelope<T> = resp
            .into_json()
            .map_err(|e| format!("artifacts json: {}", e))?;
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
        let env: V4Envelope<T> = resp
            .into_json()
            .map_err(|e| format!("artifacts json: {}", e))?;
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

    fn get_bytes_capped(&self, url: &str, cap: u64) -> Result<Vec<u8>, String> {
        let resp = self
            .agent
            .get(url)
            .set("Authorization", &format!("Bearer {}", self.api_token))
            .call()
            .map_err(|e| format!("artifacts GET {}: {}", url, e))?;
        read_capped(resp.into_reader(), cap, &format!("blob {url}"))
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
        let url = format!(
            "{}/repos/{}/fork",
            ns_base(&self.account_id, &self.namespace),
            from
        );
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
        let url = format!(
            "{}/tokens/{}",
            ns_base(&self.account_id, &self.namespace),
            token_id
        );
        self.delete(&url)
    }

    /// Token inventory for one repo.
    /// Endpoint is doc-grounded (spec §5: `GET $BASE/repos/:name/tokens`).
    pub fn list_repo_tokens(&self, repo: &str) -> Result<Vec<GitToken>, String> {
        let url = format!(
            "{}/repos/{}/tokens",
            ns_base(&self.account_id, &self.namespace),
            repo
        );
        self.get(&url)
    }

    /// User-facing token inventory: only the user-held class.
    /// Mirrors the OS's listGitTokens filter (context-collection.ts:732-739).
    /// Checklist rule: a token list is NEVER exposed unfiltered — internal /
    /// custodian tokens stay invisible.
    pub fn list_user_tokens(&self, repo: &str) -> Result<Vec<GitToken>, String> {
        Ok(self
            .list_repo_tokens(repo)?
            .into_iter()
            .filter(is_user_held)
            .collect())
    }

    /// Create a repo and immediately revoke the platform's auto-created
    /// initial token(s), matching the OS's context-collection.ts:196-205
    /// ("We don't want or need this token").
    ///
    /// On a freshly created repo every token present must be auto-created —
    /// nobody could have minted one yet. Revoke failures are warnings, never
    /// errors: the repo was created; failing here would mislead the caller
    /// into thinking it doesn't exist (OS warn-on-failure, artifact-sync.ts).
    ///
    /// UNVERIFIED live: whether the `create` endpoint actually auto-creates a
    /// token (the OS code asserts it does; wreck's live path awaits
    /// Workers Paid). Until verified, expect a possible inventory warning.
    pub fn create_repo_clean(&self, name: &str) -> Result<CleanRepo, String> {
        let result = self.create_repo(name)?;
        let mut revoked = vec![];
        let mut warnings = vec![];
        match self.list_repo_tokens(name) {
            Ok(tokens) => {
                for id in tokens_to_revoke_on_create(&tokens) {
                    match self.revoke_token(&id) {
                        Ok(()) => revoked.push(id),
                        Err(e) => {
                            warnings.push(format!("create_repo_clean: revoke {id} failed: {e}"))
                        }
                    }
                }
            }
            Err(e) => warnings.push(format!(
                "create_repo_clean: token inventory failed, auto-created tokens may stand: {e}"
            )),
        }
        Ok(CleanRepo {
            result,
            revoked,
            warnings,
        })
    }

    pub fn delete_repo(&self, name: &str) -> Result<(), String> {
        // 202 Accepted: async delete; the name may linger briefly.
        let url = format!(
            "{}/repos/{}",
            ns_base(&self.account_id, &self.namespace),
            name
        );
        self.delete(&url)
    }

    /// Recursive tree walk: returns (path -> blob hash) for all blobs.
    /// Bounded (M2): the walk refuses past MAX_TREE_DEPTH / MAX_TREE_ENTRIES.
    pub fn tree_blobs(&self, repo: &str, hash: &str) -> Result<HashMap<String, String>, String> {
        walk_tree(hash, |h| {
            let url = format!(
                "{}/repos/{}/tree/{}",
                ns_base(&self.account_id, &self.namespace),
                repo,
                h
            );
            self.get::<Vec<TreeEntry>>(&url)
        })
    }

    pub fn blob_bytes(&self, repo: &str, hash: &str) -> Result<Vec<u8>, String> {
        let url = format!(
            "{}/repos/{}/blob/{}",
            ns_base(&self.account_id, &self.namespace),
            repo,
            hash
        );
        self.get_bytes_capped(&url, MAX_BLOB_BYTES)
    }
}

/// L3 (cycle-06 audit): the old get_bytes read unboundedly — the "32MB cap"
/// was an assumption, never an enforcement. Blobs are now read through a
/// hard per-blob cap, and diff_view enforces a total byte budget across
/// files. Both fail closed: reject-never-truncate, never silent partial.
pub const MAX_BLOB_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_TOTAL_DIFF_BYTES: u64 = 64 * 1024 * 1024;

/// Read at most `cap` bytes; fail closed past the cap (reject, never
/// truncate). Pure over Read: unit-testable without network.
fn read_capped<R: std::io::Read>(r: R, cap: u64, what: &str) -> Result<Vec<u8>, String> {
    let mut limited = r.take(cap + 1);
    let mut buf = vec![];
    limited
        .read_to_end(&mut buf)
        .map_err(|e| format!("artifacts read {what}: {e}"))?;
    if buf.len() as u64 > cap {
        return Err(format!(
            "artifacts: {what} exceeds {cap} byte cap — refusing unbounded read"
        ));
    }
    Ok(buf)
}

/// True when `e` is a byte-cap rejection (reject-never-truncate), as opposed
/// to a transport failure. Tied to `read_capped`'s message above; a new
/// capped reader must keep the "byte cap" marker.
fn is_cap_rejection(e: &str) -> bool {
    e.contains("byte cap")
}

/// Per-file resolution of a diff pair.
enum FileOutcome {
    Measured { change: FileChange, bytes: u64 },
    Skipped { path: String, reason: String },
}

/// Per-file resolution of a diff pair, plus the blob provenance emitted for
/// the bytes actually read (cycle-19, observation-log pattern).
///
/// `old`/`new` are `None` when the side was absent (added/deleted file —
/// nothing fetched, nothing emitted, never faked). `Some(Ok(bytes))` emits
/// one Blob entry binding the exact bytes read; `Some(Err(_))` emits
/// nothing: cap rejections skip-with-warn, transport failures are fatal.
///
/// Pure over its inputs: unit-testable without network, including the
/// tamper case — a mocked fetch returning wrong bytes yields an entry
/// whose hash matches the *actual* bytes, never the claimed digest.
fn resolve_file(
    path: &str,
    old: Option<Result<Vec<u8>, String>>,
    new: Option<Result<Vec<u8>, String>>,
) -> Result<(FileOutcome, Vec<ProvenanceEntry>), String> {
    let mut prov = Vec::new();
    let old_bytes = match old {
        None => vec![],
        Some(Ok(b)) => {
            prov.push(wreck_protocol::blob_provenance_entry(path, &b));
            b
        }
        Some(Err(e)) if is_cap_rejection(&e) => {
            return Ok((
                FileOutcome::Skipped {
                    path: path.to_string(),
                    reason: format!("old blob: {e}"),
                },
                prov,
            ))
        }
        Some(Err(e)) => return Err(e),
    };
    let new_bytes = match new {
        None => vec![],
        Some(Ok(b)) => {
            prov.push(wreck_protocol::blob_provenance_entry(path, &b));
            b
        }
        Some(Err(e)) if is_cap_rejection(&e) => {
            return Ok((
                FileOutcome::Skipped {
                    path: path.to_string(),
                    reason: format!("new blob: {e}"),
                },
                prov,
            ))
        }
        Some(Err(e)) => return Err(e),
    };
    let bytes = (old_bytes.len() + new_bytes.len()) as u64;
    // likely-binary blobs: measured with empty ranges (pre-existing behavior)
    if old_bytes.contains(&0) || new_bytes.contains(&0) {
        return Ok((
            FileOutcome::Measured {
                change: FileChange {
                    path: path.to_string(),
                    added: vec![],
                    removed: vec![],
                },
                bytes,
            },
            prov,
        ));
    }
    let (added, removed) = diff_ranges(&old_bytes, &new_bytes)?;
    Ok((
        FileOutcome::Measured {
            change: FileChange {
                path: path.to_string(),
                added,
                removed,
            },
            bytes,
        },
        prov,
    ))
}

/// Running byte budget for one diff_view: fail-closed when exhausted.
struct ByteBudget {
    remaining: u64,
}

impl ByteBudget {
    fn new(cap: u64) -> Self {
        Self { remaining: cap }
    }

    fn take(&mut self, n: u64, what: &str) -> Result<(), String> {
        if n > self.remaining {
            return Err(format!(
                "artifacts: diff of {what} would exceed the {MAX_TOTAL_DIFF_BYTES} byte total budget — refusing"
            ));
        }
        self.remaining -= n;
        Ok(())
    }
}

/// M2 (cycle-06 audit): bounds on the tree walk. A hostile tree in a
/// compromised agent fork must not exhaust memory: fail closed past the
/// caps, never hang, never silently truncate.
pub const MAX_TREE_DEPTH: usize = 64;
pub const MAX_TREE_ENTRIES: usize = 100_000;

/// Pure tree walk over a fetch closure (unit-testable without network).
fn walk_tree<F>(root: &str, fetch: F) -> Result<HashMap<String, String>, String>
where
    F: Fn(&str) -> Result<Vec<TreeEntry>, String>,
{
    let mut out = HashMap::new();
    let mut stack = vec![(root.to_string(), String::new(), 0usize)];
    while let Some((h, prefix, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(format!(
                "artifacts: tree depth {} exceeds cap {} — refusing unbounded walk",
                depth, MAX_TREE_DEPTH
            ));
        }
        let entries = fetch(&h)?;
        if out.len() + entries.len() > MAX_TREE_ENTRIES {
            return Err(format!(
                "artifacts: tree entries exceed cap {} — refusing unbounded walk",
                MAX_TREE_ENTRIES
            ));
        }
        for e in entries {
            let path = if prefix.is_empty() {
                e.path.clone()
            } else {
                format!("{}/{}", prefix, e.path)
            };
            if e.entry_type == "tree" {
                stack.push((e.hash, path, depth + 1));
            } else {
                out.insert(path, e.hash);
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// ChangeView from (before, after): tree-walk + local line diff
// ---------------------------------------------------------------------------

/// M1 (cycle-06 audit): unique scratch dir per diff_ranges call, created
/// 0700 with 0600 blob files. The old fixed `wreck-diff-<pid>` path let
/// concurrent calls clobber each other (remove_dir_all + recreate races)
/// and left blob bytes world-readable at 0644.
fn make_diff_dir() -> Result<PathBuf, String> {
    static DIFF_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = DIFF_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir =
        std::env::temp_dir().join(format!("wreck-diff-{}-{}-{}", std::process::id(), nanos, n));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

#[cfg(unix)]
fn write_blob_file(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?
        .write_all(data)
        .map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn write_blob_file(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| e.to_string())
}

/// Compute added/removed line ranges between two blob texts via git.
/// (Shells to git --no-index: the same -U0 parser as the local adapter,
/// one implementation of the diff semantics.)
fn diff_ranges(old: &[u8], new: &[u8]) -> Result<(Vec<(u32, u32)>, Vec<(u32, u32)>), String> {
    let dir = make_diff_dir()?;
    write_blob_file(&dir.join("a"), old)?;
    write_blob_file(&dir.join("b"), new)?;
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
        let mut paths: Vec<String> = old_tree.keys().chain(new_tree.keys()).cloned().collect();
        paths.sort();
        paths.dedup();
        // L3: a hostile fork could touch thousands of 32MB blobs; the total
        // diff budget fails closed before memory pressure becomes a DoS.
        // Per-blob cap rejections skip-with-warn (cycle-15, OS artifact-sync
        // pattern: oversized CONTENT is skipped, oversized ENVELOPES reject);
        // the total budget below still fails closed (transfer-level).
        let mut budget = ByteBudget::new(MAX_TOTAL_DIFF_BYTES);
        let mut measured: HashMap<String, FileChange> = HashMap::new();
        for path in paths {
            let oh = old_tree.get(&path);
            let nh = new_tree.get(&path);
            if oh == nh {
                continue;
            }
            let old = oh.map(|h| self.blob_bytes(repo, h));
            let new = nh.map(|h| self.blob_bytes(repo, h));
            // Cycle-19: blob provenance rides the view — one entry per blob
            // whose bytes were actually read (absent/cap-rejected sides
            // emit nothing). The governor consumes these; it never
            // synthesizes Blob entries.
            let (outcome, prov) = resolve_file(&path, old, new)?;
            view.blob_provenance.extend(prov);
            match outcome {
                FileOutcome::Skipped { path, reason } => {
                    view.skipped.push(SkippedFile { path, reason });
                }
                FileOutcome::Measured { change, bytes } => {
                    budget.take(bytes, &change.path)?;
                    measured.insert(change.path.clone(), change);
                }
            }
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
    /// L6 (cycle-06 audit): hostile local git config (custom merge drivers,
    /// merge.conflictstyle, core.hooksPath) must not alter merge semantics.
    /// Every git invocation ignores system + global config files.
    fn pinned_git_env() -> [(&'static str, &'static str); 2] {
        [
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ]
    }

    /// -c overrides for the merge invocation (must precede the subcommand).
    fn merge_pin_args() -> [&'static str; 2] {
        ["-c", "merge.conflictstyle=merge"]
    }

    fn git_cmd(dir: &Path, args: &[&str], token_secret: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new("git");
        cmd.args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "wreck-governor")
            .env("GIT_AUTHOR_EMAIL", "wreck@local")
            .env("GIT_COMMITTER_NAME", "wreck-governor")
            .env("GIT_COMMITTER_EMAIL", "wreck@local")
            .env(
                "GIT_HTTP_EXTRAHEADER",
                format!("Authorization: Bearer {}", token_secret),
            );
        for (k, v) in Self::pinned_git_env() {
            cmd.env(k, v);
        }
        cmd
    }

    fn git(&self, dir: &Path, args: &[&str], token_secret: &str) -> Result<String, String> {
        let out = Self::git_cmd(dir, args, token_secret)
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
        // L5 (cycle-06 audit): no unwrap on the workdir parent.
        let parent = dir
            .parent()
            .ok_or("artifacts merge: workdir has no parent")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        // NOTE: the fork head must be fetchable; the agent's fork remote is
        // derived from the change metadata in production. Here the caller
        // stages it via `stage_fork_head`.
        self.git(
            parent,
            &[
                "clone",
                "--quiet",
                "--depth",
                "1",
                &self.baseline_remote,
                dir.to_str().unwrap(),
            ],
            &secret,
        )?;
        let fork_remote = std::env::var(format!("WRECK_FORK_{}", change.change_id))
            .map_err(|_| "artifacts merge: fork remote not staged (WRECK_FORK_<id>)".to_string())?;
        // fetch the fork head by SHA using the AGENT's token is wrong —
        // the governor fetches via its own baseline token only if the fork
        // grants it; in production the fork is in the same namespace and
        // the governor holds a read token for it. Simplified here.
        self.git(
            &dir,
            &["fetch", "--depth", "1", &fork_remote, change.head.as_str()],
            &secret,
        )?;
        let pin = Self::merge_pin_args();
        self.git(
            &dir,
            &[
                pin[0],
                pin[1],
                "merge",
                "--no-ff",
                "-m",
                &format!("wreck: merge {}", change.change_id),
                "FETCH_HEAD",
            ],
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
        assert_eq!(
            e.dedup_key(),
            "wreck:seen:wreck:task-0042:refs/heads/main:aaa:bbb"
        );
        assert!(!e.is_baseline("baseline"));
        assert!(e.is_baseline("task-0042"));
        let mut e2 = e.clone();
        e2.source.repo_name = "baseline".into();
        assert!(e2.is_baseline("baseline"));
    }

    #[test]
    fn fork_payload_shape() {
        let f = ForkRepo {
            name: "task-1".into(),
            default_branch_only: Some(true),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["name"], "task-1");
        assert_eq!(v["default_branch_only"], true);
    }

    // H4 regression: secret-bearing structs must never print secrets.
    #[test]
    fn create_repo_result_debug_redacts_token() {
        let r = CreateRepoResult {
            name: "n".into(),
            remote: "https://example.invalid/git/n.git".into(),
            token: "art_v1_SUPERSECRET?expires=123".into(),
        };
        let dbg = format!("{:?}", r);
        assert!(!dbg.contains("SUPERSECRET"), "leaked: {}", dbg);
        assert!(dbg.contains("<redacted>"), "missing marker: {}", dbg);
        assert!(dbg.contains('n'), "name lost: {}", dbg);
    }

    #[test]
    fn mint_token_result_debug_redacts_plaintext() {
        let r = MintTokenResult {
            id: "id-1".into(),
            plaintext: "art_v1_SUPERSECRET?expires=123".into(),
            scope: "write".into(),
            expires_at: "2026-10-09T00:00:00Z".into(),
        };
        let dbg = format!("{:?}", r);
        assert!(!dbg.contains("SUPERSECRET"), "leaked: {}", dbg);
        assert!(dbg.contains("<redacted>"), "missing marker: {}", dbg);
        assert!(dbg.contains("id-1"), "id lost: {}", dbg);
    }

    // M1 regression: scratch dirs are unique per call and 0700.
    #[test]
    fn diff_dirs_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let d = make_diff_dir().unwrap();
            assert!(seen.insert(d.clone()), "duplicate dir: {:?}", d);
            let _ = std::fs::remove_dir_all(&d);
        }
    }

    #[cfg(unix)]
    #[test]
    fn diff_dir_is_0700() {
        use std::os::unix::fs::MetadataExt;
        let d = make_diff_dir().unwrap();
        let mode = std::fs::metadata(&d).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "dir mode: {:o}", mode);
        let _ = std::fs::remove_dir_all(&d);
    }

    // M1 regression: concurrent diff_ranges calls must not clobber each
    // other (the old fixed per-PID path corrupted results under threads).
    #[test]
    fn diff_ranges_is_thread_safe() {
        let handles: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    let old = format!("line{}\n", i).into_bytes();
                    let new = format!("line{}\nline{}\n", i, i + 100).into_bytes();
                    diff_ranges(&old, &new).unwrap()
                })
            })
            .collect();
        for (i, h) in handles.into_iter().enumerate() {
            let (added, removed) = h.join().unwrap();
            // new file gained line 2; nothing removed
            assert_eq!(added, vec![(2, 2)], "thread {}: {:?}", i, added);
            assert!(removed.is_empty(), "thread {}: {:?}", i, removed);
        }
    }

    // M2 regression: the tree walk refuses hostile shapes, fail-closed.
    fn tree_entry(name: &str, entry_type: &str, hash: &str) -> TreeEntry {
        TreeEntry {
            name: name.into(),
            entry_type: entry_type.into(),
            hash: hash.into(),
            path: name.into(),
        }
    }

    #[test]
    fn walk_tree_rejects_deep_chains() {
        // 70 nested single-child trees: exceeds MAX_TREE_DEPTH (64)
        let fetch = |h: &str| -> Result<Vec<TreeEntry>, String> {
            let depth: usize = h.parse().unwrap();
            if depth >= 70 {
                return Ok(vec![]);
            }
            Ok(vec![tree_entry("child", "tree", &(depth + 1).to_string())])
        };
        let err = walk_tree("0", fetch).unwrap_err();
        assert!(err.contains("depth"), "err: {}", err);
        assert!(err.contains("refusing"), "err: {}", err);
    }

    #[test]
    fn walk_tree_rejects_entry_flood() {
        // one directory with more blobs than the entry cap
        let fetch = |_h: &str| -> Result<Vec<TreeEntry>, String> {
            Ok((0..MAX_TREE_ENTRIES + 1)
                .map(|i| tree_entry(&format!("f{}", i), "blob", "h"))
                .collect())
        };
        let err = walk_tree("root", fetch).unwrap_err();
        assert!(err.contains("entries"), "err: {}", err);
        assert!(err.contains("refusing"), "err: {}", err);
    }

    #[test]
    fn walk_tree_accepts_normal_trees() {
        let fetch = |h: &str| -> Result<Vec<TreeEntry>, String> {
            match h {
                "root" => Ok(vec![
                    tree_entry("a.txt", "blob", "ha"),
                    tree_entry("sub", "tree", "sub"),
                ]),
                "sub" => Ok(vec![tree_entry("b.txt", "blob", "hb")]),
                _ => Ok(vec![]),
            }
        };
        let m = walk_tree("root", fetch).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m["a.txt"], "ha");
        assert_eq!(m["sub/b.txt"], "hb");
    }

    // --- L3 (cycle-09): capped reads + total diff budget -----------------

    #[test]
    fn read_capped_accepts_at_cap() {
        use std::io::Cursor;
        let data = vec![0xABu8; 100];
        let out = read_capped(Cursor::new(data), 100, "test").unwrap();
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn read_capped_rejects_over_cap() {
        use std::io::Cursor;
        let data = vec![0xABu8; 101];
        let err = read_capped(Cursor::new(data), 100, "test").unwrap_err();
        assert!(err.contains("exceeds 100 byte cap"), "unexpected: {err}");
    }

    #[test]
    fn read_capped_accepts_empty() {
        use std::io::Cursor;
        let out = read_capped(Cursor::new(vec![]), 100, "test").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn byte_budget_exhausts_fail_closed() {
        let mut b = ByteBudget::new(100);
        b.take(60, "a").unwrap();
        b.take(40, "b").unwrap();
        let err = b.take(1, "c").unwrap_err();
        assert!(err.contains("total budget"), "unexpected: {err}");
    }

    #[test]
    fn byte_budget_single_take_over_cap() {
        let mut b = ByteBudget::new(100);
        assert!(b.take(101, "x").is_err());
    }

    // --- L6 (cycle-09): pinned git config --------------------------------

    #[test]
    fn git_env_pins_config_files_off() {
        let cmd = ArtifactsMergePort::git_cmd(std::path::Path::new("/tmp"), &["status"], "sekret");
        // get_envs yields (key, Option<value>); explicitly-removed values are None.
        let env_of = |k: &str| -> Option<String> {
            cmd.get_envs()
                .filter_map(|(key, val)| {
                    if key == k {
                        val.and_then(|v| v.to_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                })
                .next()
        };
        assert_eq!(env_of("GIT_CONFIG_NOSYSTEM"), Some("1".to_string()));
        assert_eq!(env_of("GIT_CONFIG_GLOBAL"), Some("/dev/null".to_string()));
        // auth header still present (ps-safe: env, never argv)
        let extra = env_of("GIT_HTTP_EXTRAHEADER").unwrap_or_default();
        assert!(extra.starts_with("Authorization: Bearer "));
    }

    #[test]
    fn merge_pins_conflictstyle() {
        let pin = ArtifactsMergePort::merge_pin_args();
        assert_eq!(pin, ["-c", "merge.conflictstyle=merge"]);
    }

    // ---- cycle-15: token inventory hygiene + skip-with-warn ----

    fn tok(id: &str, scope: Option<&str>, state: Option<&str>) -> GitToken {
        GitToken {
            id: id.to_string(),
            scope: scope.map(|s| s.to_string()),
            state: state.map(|s| s.to_string()),
        }
    }

    #[test]
    fn fresh_repo_revokes_every_token_present() {
        // On a fresh repo every token present is auto-created: revoke all.
        let tokens = vec![
            tok("a", Some("write"), Some("active")),
            tok("b", None, None),
        ];
        assert_eq!(
            tokens_to_revoke_on_create(&tokens),
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(tokens_to_revoke_on_create(&[]).is_empty());
    }

    #[test]
    fn user_inventory_hides_internal_tokens() {
        let tokens = vec![
            tok("u1", Some("write"), Some("active")), // user-held: shown
            tok("i1", Some("read"), Some("active")),  // custodian read token: hidden
            tok("u2", Some("write"), Some("expired")), // dead grant: hidden
            tok("u3", Some("write"), Some("revoked")), // dead grant: hidden
            tok("i2", None, None),                    // unknown shape: hidden (fail-closed)
        ];
        let shown: Vec<String> = tokens
            .iter()
            .filter(|t| is_user_held(t))
            .map(|t| t.id.clone())
            .collect();
        assert_eq!(shown, vec!["u1".to_string()]);
    }

    fn cap_err() -> String {
        // A genuine read_capped rejection, not a hand-written string.
        read_capped(std::io::Cursor::new(vec![0u8; 11]), 10, "test").unwrap_err()
    }

    #[test]
    fn resolve_file_skips_on_cap_rejection() {
        // Old side over cap: skip-with-warn, never fatal to the diff.
        // Nothing was read on the old side, so no provenance is emitted.
        let (r, prov) =
            resolve_file("big.bin", Some(Err(cap_err())), Some(Ok(vec![1, 2, 3]))).unwrap();
        match r {
            FileOutcome::Skipped { path, reason } => {
                assert_eq!(path, "big.bin");
                assert!(reason.contains("old blob"));
            }
            _ => panic!("expected Skipped"),
        }
        assert!(prov.is_empty());
        // New side over cap: same — but the old side WAS read, so its
        // entry is honestly emitted before the skip.
        let (r, prov) = resolve_file("big.bin", Some(Ok(vec![])), Some(Err(cap_err()))).unwrap();
        assert!(matches!(r, FileOutcome::Skipped { .. }));
        assert_eq!(prov.len(), 1);
        assert_eq!(prov[0].id, "big.bin");
    }

    #[test]
    fn resolve_file_fails_on_transport_error() {
        // Transport failures still fail the diff — only cap rejections skip.
        let r = resolve_file(
            "x",
            Some(Err("artifacts GET https://x: 500".into())),
            Some(Ok(vec![])),
        );
        assert!(r.is_err());
    }

    #[test]
    fn resolve_file_measures_normal_pairs() {
        let (r, prov) = resolve_file(
            "a.txt",
            Some(Ok(b"a\n".to_vec())),
            Some(Ok(b"b\n".to_vec())),
        )
        .unwrap();
        match r {
            FileOutcome::Measured { change, bytes } => {
                assert_eq!(change.path, "a.txt");
                assert_eq!(bytes, 4);
                assert!(!change.added.is_empty() || !change.removed.is_empty());
            }
            _ => panic!("expected Measured"),
        }
        // Both sides read → two Blob entries, in side order.
        assert_eq!(prov.len(), 2);
        for e in &prov {
            assert_eq!(e.kind, wreck_protocol::ProvenanceKind::Blob);
            assert_eq!(e.id, "a.txt");
        }
        assert_eq!(prov[0].hash, wreck_protocol::sha256_hex(b"a\n"));
        assert_eq!(prov[1].hash, wreck_protocol::sha256_hex(b"b\n"));
    }

    #[test]
    fn resolve_file_provenance_reflects_actual_bytes_not_claimed() {
        // Tamper case: the mocked fetch returns bytes that are NOT what
        // the blob hash claimed. The entry must bind the ACTUAL bytes
        // read — never an expected/claimed digest.
        let tampered = b"tampered-content";
        let expected = b"expected-content";
        let (_, prov) = resolve_file(
            "x.txt",
            Some(Ok(tampered.to_vec())),
            Some(Ok(expected.to_vec())),
        )
        .unwrap();
        assert_eq!(prov.len(), 2);
        assert_eq!(prov[0].hash, wreck_protocol::sha256_hex(tampered));
        assert_eq!(prov[1].hash, wreck_protocol::sha256_hex(expected));
        // The tampered side's entry does NOT match the "expected" digest:
        // provenance records what was read, not what was requested.
        assert_ne!(prov[0].hash, wreck_protocol::sha256_hex(expected));
    }

    #[test]
    fn resolve_file_absent_side_emits_nothing() {
        // Added file: old side absent → only the new side's read is
        // recorded. Absence is never faked into an entry.
        let (r, prov) = resolve_file("new.txt", None, Some(Ok(b"x".to_vec()))).unwrap();
        assert!(matches!(r, FileOutcome::Measured { .. }));
        assert_eq!(prov.len(), 1);
        assert_eq!(prov[0].id, "new.txt");
        assert_eq!(prov[0].hash, wreck_protocol::sha256_hex(b"x"));
    }
}
