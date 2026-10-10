//! wreck as organelles (Tier A native migration).
//!
//! Two organelles on the codebase's own seam ("the governor core never
//! touches a network"):
//!
//! - `wreck-govern` (codon `wg`): the deterministic merge authority.
//!   propose / validate_change_id / classify / decide / canon_insert /
//!   canon_get / canon_active / canon_to_policy. Proven, ReadOnly except
//!   canon_insert. The sealing key comes from `WRECK_SEAL_KEY` env (64-hex);
//!   never in the manifest, never in receipts.
//! - `wreck-ports` (codon `wp`): substrate execution ports. Local git
//!   workspaces (init/fork/commit/diff/merge) + capability-token custody.
//!   Candidate, Write-gated. Workspaces are temp dirs owned by the organelle
//!   (declared ephemeral).

use organelle_host::{CallContext, HostRef, Organelle, OrganelleError};
use organelle_manifest::{
    Authority, Contract, MutationClass, OrganelleManifest, ReceiptPolicy, Transport, Valence,
    MANIFEST_SCHEMA_VERSION, RECEIPT_ALGORITHM,
};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use wreck_adapters::local::{LocalGit, LocalMergePort};
use wreck_adapters::token_custodian::{Adjudication, MintedToken, Minter, TokenCustodian};
use wreck_canon::{CanonRule, CanonStore};
use wreck_governor::{DecideOutcome, Governor, MergePort};
use wreck_graph::{ChangeView, Policy};
use wreck_protocol::{ChangeClaim, ScopeItem, Sha};

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn str_in(v: &Value, key: &str) -> Result<String, OrganelleError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| OrganelleError::failed(format!("missing string field {key:?}")))
}

fn failed(s: String) -> OrganelleError {
    OrganelleError::failed(s)
}

fn contract(op: &str, description: &str, schema: Value) -> Contract {
    Contract { op: op.to_string(), description: description.to_string(), input_schema: schema, mutation_class: None, required_capability: None }
}

fn contract_gated(op: &str, description: &str, schema: Value, class: MutationClass, cap: &str) -> Contract {
    Contract { op: op.to_string(), description: description.to_string(), input_schema: schema, mutation_class: Some(class), required_capability: Some(cap.to_string()) }
}

fn obj_schema(props: Value, required: &[&str]) -> Value {
    serde_json::json!({ "type": "object", "properties": props, "required": required })
}

fn file_list_schema() -> Value {
    serde_json::json!({
        "type": "array",
        "items": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"]}
    })
}

fn parse_files(v: &Value) -> Result<Vec<(String, String)>, OrganelleError> {
    let arr = v.get("files").and_then(|x| x.as_array())
        .ok_or_else(|| failed("missing files array".to_string()))?;
    arr.iter().map(|f| {
        Ok((str_in(f, "path")?, str_in(f, "content")?))
    }).collect()
}

fn to_json<T: serde::Serialize>(t: &T) -> Result<Value, OrganelleError> {
    serde_json::to_value(t).map_err(|e| failed(format!("serialize: {e}")))
}

fn from_json<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, OrganelleError> {
    serde_json::from_value(v.clone()).map_err(|e| failed(format!("deserialize: {e}")))
}

fn manifest_base(name: &str, codon: &str, version: &str, description: &str, contracts: Vec<Contract>, valence: Valence, transports: Vec<Transport>) -> OrganelleManifest {
    OrganelleManifest {
        schema_version: MANIFEST_SCHEMA_VERSION.to_string(),
        name: name.to_string(),
        codon: codon.to_string(),
        version: version.to_string(),
        description: description.to_string(),
        contracts,
        authority: Authority {
            mutation_class: MutationClass::ReadOnly,
            declared_valence: valence,
            required_capability: None,
            granted_capabilities: vec![],
        },
        transports,
        receipt_policy: ReceiptPolicy { content_addressed: true, algorithm: RECEIPT_ALGORITHM.to_string(), chain: true },
    }
}

// ---------------------------------------------------------------------------
// wreck-govern (wg)
// ---------------------------------------------------------------------------

fn wg_manifest() -> OrganelleManifest {
    manifest_base(
        "wreck-govern", "wg", "0.1.0",
        "deterministic merge authority: change claims, policy classification, sealed verdicts, canon rules",
        vec![
            contract("propose", "propose a change claim (PROPOSED)",
                obj_schema(serde_json::json!({"change_id": {"type": "string"}, "agent_id": {"type": "string"}, "task_id": {"type": "string"}, "base": {"type": "string"}, "head": {"type": "string"}, "intent": {"type": "string"}}), &["change_id", "agent_id", "task_id", "base", "head", "intent"])),
            contract("validate_change_id", "validate a change_id at the boundary",
                obj_schema(serde_json::json!({"id": {"type": "string"}}), &["id"])),
            contract("classify", "classify conflicts between two change views under a policy",
                obj_schema(serde_json::json!({"a": {"type": "object"}, "b": {"type": "object"}, "merged": {"type": "array", "items": {"type": "string"}}, "policy": {"type": "object"}}), &["a", "b", "policy"])),
            contract("decide", "run the deterministic governor: claim + view -> sealed verdict",
                obj_schema(serde_json::json!({"claim": {"type": "object"}, "view": {"type": "object"}, "in_flight": {"type": "array", "items": {"type": "object"}}, "merged": {"type": "array", "items": {"type": "string"}}, "ts": {"type": "string"}}), &["claim", "view"])),
            contract_gated("canon_insert", "insert a canon rule (append-only; supersession via supersedes)",
                obj_schema(serde_json::json!({"rule": {"type": "object"}}), &["rule"]),
                MutationClass::Write, "wg.canon.write"),
            contract("canon_get", "resolve a canon rule by id",
                obj_schema(serde_json::json!({"id": {"type": "string"}}), &["id"])),
            contract("canon_active", "all active (non-superseded) canon rules",
                obj_schema(serde_json::json!({}), &[])),
            contract("canon_to_policy", "compile the canon store to a governor Policy",
                obj_schema(serde_json::json!({}), &[])),
        ],
        Valence::Proven,
        Transport::all().to_vec(),
    )
}

fn seal_key() -> Result<Vec<u8>, OrganelleError> {
    let hex = std::env::var("WRECK_SEAL_KEY")
        .map_err(|_| failed("WRECK_SEAL_KEY env not set (64 hex chars)".to_string()))?;
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(failed("WRECK_SEAL_KEY must be 64 hex chars".to_string()));
    }
    (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|e| failed(e.to_string()))).collect()
}

pub struct GovernOrganelle {
    manifest: OrganelleManifest,
    canon: Mutex<CanonStore>,
    seal_key: Vec<u8>,
}

pub fn govern_organelle() -> Result<Arc<dyn Organelle>, OrganelleError> {
    Ok(Arc::new(GovernOrganelle { manifest: wg_manifest(), canon: Mutex::new(CanonStore::new()), seal_key: seal_key()? }))
}

impl Organelle for GovernOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(&self, _ctx: &CallContext, _host: &dyn HostRef, op: &str, input: Value) -> Result<Value, OrganelleError> {
        match op {
            "propose" => {
                let claim = ChangeClaim::propose(
                    &str_in(&input, "change_id")?, &str_in(&input, "agent_id")?,
                    &str_in(&input, "task_id")?,
                    Sha::new(&str_in(&input, "base")?).map_err(failed)?,
                    Sha::new(&str_in(&input, "head")?).map_err(failed)?,
                    &str_in(&input, "intent")?,
                ).map_err(failed)?;
                to_json(&claim)
            }
            "validate_change_id" => {
                ChangeClaim::validate_change_id(&str_in(&input, "id")?).map_err(failed)?;
                Ok(serde_json::json!({"valid": true}))
            }
            "classify" => {
                let a: ChangeView = from_json(input.get("a").ok_or_else(|| failed("missing a".to_string()))?)?;
                let b: ChangeView = from_json(input.get("b").ok_or_else(|| failed("missing b".to_string()))?)?;
                let policy: Policy = from_json(input.get("policy").ok_or_else(|| failed("missing policy".to_string()))?)?;
                let merged: HashSet<String> = input.get("merged").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                let conflicts = wreck_graph::classify(&a, &b, &merged, &policy);
                to_json(&conflicts)
            }
            "decide" => {
                let mut claim: ChangeClaim = from_json(input.get("claim").ok_or_else(|| failed("missing claim".to_string()))?)?;
                let view: ChangeView = from_json(input.get("view").ok_or_else(|| failed("missing view".to_string()))?)?;
                let in_flight: Vec<ChangeView> = input.get("in_flight").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                let merged: HashSet<String> = input.get("merged").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                let ts = input.get("ts").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let policy = self.canon.lock().map_err(|_| failed("canon lock poisoned".to_string()))?.to_policy();
                let mut gov = Governor::new(policy, self.seal_key.clone(), "wreck-govern");
                match gov.decide(&mut claim, &view, &in_flight, &merged, &ts).map_err(failed)? {
                    DecideOutcome::AcceptPending { draft } => Ok(serde_json::json!({"outcome": "accept_pending", "record": to_json(&draft)?})),
                    DecideOutcome::Decided(rec) => Ok(serde_json::json!({"outcome": "decided", "record": to_json(&rec)?})),
                }
            }
            "canon_insert" => {
                let rule: CanonRule = from_json(input.get("rule").ok_or_else(|| failed("missing rule".to_string()))?)?;
                let id = rule.id.clone();
                self.canon.lock().map_err(|_| failed("canon lock poisoned".to_string()))?.insert(rule);
                Ok(serde_json::json!({"inserted": id}))
            }
            "canon_get" => {
                let g = self.canon.lock().map_err(|_| failed("canon lock poisoned".to_string()))?;
                match g.get(&str_in(&input, "id")?) {
                    Some(r) => Ok(serde_json::json!({"found": true, "rule": to_json(r)?})),
                    None => Ok(serde_json::json!({"found": false})),
                }
            }
            "canon_active" => {
                let g = self.canon.lock().map_err(|_| failed("canon lock poisoned".to_string()))?;
                to_json(&g.active())
            }
            "canon_to_policy" => {
                let g = self.canon.lock().map_err(|_| failed("canon lock poisoned".to_string()))?;
                to_json(&g.to_policy())
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// wreck-ports (wp)
// ---------------------------------------------------------------------------

/// Production-quality ephemeral minter: CSPRNG token material from
/// /dev/urandom, TTL enforced by the custodian. No custom crypto — just
/// random bearer tokens with a revocation set.
struct EphemeralMinter;

fn urandom_hex(n: usize) -> Result<String, String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

impl Minter for EphemeralMinter {
    fn mint(&self, _repo: &str, ttl_secs: u64) -> Result<MintedToken, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(MintedToken {
            id: format!("ephem-{}", urandom_hex(8)?),
            plaintext: format!("wreck-{}", urandom_hex(16)?),
            expires_at_unix: now + ttl_secs,
        })
    }
    fn revoke(&self, _token_id: &str) -> Result<(), String> {
        Ok(())
    }
}

struct Workspace {
    _tmp: TempDir,
    git: LocalGit,
    base: Sha,
    forks: HashMap<String, PathBuf>,
    heads: HashMap<String, Sha>,
}

fn wp_manifest() -> OrganelleManifest {
    manifest_base(
        "wreck-ports", "wp", "0.1.0",
        "substrate execution ports: local git workspaces and capability-token custody",
        vec![
            contract_gated("workspace_init", "init a local git workspace from files -> base SHA",
                obj_schema(serde_json::json!({"ws": {"type": "string"}, "files": file_list_schema()}), &["ws", "files"]),
                MutationClass::Write, "wp.workspace"),
            contract_gated("workspace_fork", "fork the baseline in a workspace",
                obj_schema(serde_json::json!({"ws": {"type": "string"}, "name": {"type": "string"}}), &["ws", "name"]),
                MutationClass::Write, "wp.workspace"),
            contract_gated("workspace_commit", "commit files on a fork -> head SHA",
                obj_schema(serde_json::json!({"ws": {"type": "string"}, "fork": {"type": "string"}, "message": {"type": "string"}, "files": file_list_schema()}), &["ws", "fork", "files", "message"]),
                MutationClass::Write, "wp.workspace"),
            contract("workspace_diff", "build the ChangeView (base, head) for a fork",
                obj_schema(serde_json::json!({"ws": {"type": "string"}, "fork": {"type": "string"}, "change_id": {"type": "string"}, "scope": {"type": "array"}}), &["ws", "fork", "change_id"])),
            contract_gated("workspace_merge", "execute the merge port for a claim -> new SHA",
                obj_schema(serde_json::json!({"ws": {"type": "string"}, "claim": {"type": "object"}}), &["ws", "claim"]),
                MutationClass::Write, "wp.merge"),
            contract_gated("token_for", "mint (or return cached) short-lived token for a repo",
                obj_schema(serde_json::json!({"repo": {"type": "string"}}), &["repo"]),
                MutationClass::Write, "wp.tokens"),
            contract_gated("token_adjudicate", "adjudicate a presented token after a provider rejection",
                obj_schema(serde_json::json!({"repo": {"type": "string"}, "presented": {"type": "string"}}), &["repo", "presented"]),
                MutationClass::Write, "wp.tokens"),
            contract_gated("token_revoke", "revoke a repo's token",
                obj_schema(serde_json::json!({"repo": {"type": "string"}}), &["repo"]),
                MutationClass::Write, "wp.tokens"),
        ],
        Valence::Candidate,
        vec![Transport::Native, Transport::UnixSocket],
    )
}

pub struct PortsOrganelle {
    manifest: OrganelleManifest,
    workspaces: Mutex<HashMap<String, Workspace>>,
    custodian: TokenCustodian<EphemeralMinter>,
}

pub fn ports_organelle() -> Arc<dyn Organelle> {
    Arc::new(PortsOrganelle {
        manifest: wp_manifest(),
        workspaces: Mutex::new(HashMap::new()),
        custodian: TokenCustodian::new(EphemeralMinter, 3600, 300),
    })
}

impl PortsOrganelle {
    fn ws_mut<F, T>(&self, ws: &str, f: F) -> Result<T, OrganelleError>
    where F: FnOnce(&mut Workspace) -> Result<T, String> {
        let mut map = self.workspaces.lock().map_err(|_| failed("workspace lock poisoned".to_string()))?;
        let w = map.get_mut(ws).ok_or_else(|| failed(format!("unknown workspace {ws:?}")))?;
        f(w).map_err(failed)
    }
}

impl Organelle for PortsOrganelle {
    fn manifest(&self) -> OrganelleManifest {
        self.manifest.clone()
    }

    fn handle(&self, _ctx: &CallContext, _host: &dyn HostRef, op: &str, input: Value) -> Result<Value, OrganelleError> {
        match op {
            "workspace_init" => {
                let ws = str_in(&input, "ws")?;
                let files = parse_files(&input)?;
                let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
                let tmp = TempDir::new().map_err(|e| failed(e.to_string()))?;
                let git = LocalGit::new(tmp.path());
                let base = git.init_baseline(&refs).map_err(failed)?;
                let base_s = base.as_str().to_string();
                self.workspaces.lock().map_err(|_| failed("workspace lock poisoned".to_string()))?
                    .insert(ws.clone(), Workspace { _tmp: tmp, git, base, forks: HashMap::new(), heads: HashMap::new() });
                Ok(serde_json::json!({"ws": ws, "base": base_s}))
            }
            "workspace_fork" => {
                let ws = str_in(&input, "ws")?;
                let name = str_in(&input, "name")?;
                self.ws_mut(&ws, |w| {
                    let p = w.git.fork(&name)?;
                    w.forks.insert(name.clone(), p.clone());
                    Ok(serde_json::json!({"ws": ws, "fork": name, "path": p.to_string_lossy()}))
                })
            }
            "workspace_commit" => {
                let ws = str_in(&input, "ws")?;
                let fork = str_in(&input, "fork")?;
                let message = str_in(&input, "message")?;
                let files = parse_files(&input)?;
                self.ws_mut(&ws, |w| {
                    let path = w.forks.get(&fork).cloned().ok_or_else(|| format!("unknown fork {fork:?}"))?;
                    let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
                    let head = w.git.commit_change(&path, &refs, &message)?;
                    let head_s = head.as_str().to_string();
                    w.heads.insert(fork.clone(), head);
                    Ok(serde_json::json!({"ws": ws, "fork": fork, "head": head_s}))
                })
            }
            "workspace_diff" => {
                let ws = str_in(&input, "ws")?;
                let fork = str_in(&input, "fork")?;
                let change_id = str_in(&input, "change_id")?;
                let scope: Vec<ScopeItem> = input.get("scope").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
                self.ws_mut(&ws, |w| {
                    let path = w.forks.get(&fork).cloned().ok_or_else(|| format!("unknown fork {fork:?}"))?;
                    let head = w.heads.get(&fork).cloned().ok_or_else(|| format!("no commit on fork {fork:?}"))?;
                    let view = w.git.diff_view(&change_id, &scope, &path, &w.base, &head)?;
                    Ok(to_json(&view).map_err(|e| e.to_string())?)
                })
            }
            "workspace_merge" => {
                let ws = str_in(&input, "ws")?;
                let claim: ChangeClaim = from_json(input.get("claim").ok_or_else(|| failed("missing claim".to_string()))?)?;
                self.ws_mut(&ws, |w| {
                    let port = LocalMergePort { baseline: w.git.baseline_path(), forks: w.forks.clone() };
                    let sha = port.merge(&claim)?;
                    Ok(serde_json::json!({"merge_sha": sha.as_str()}))
                })
            }
            "token_for" => {
                let t = self.custodian.token_for(&str_in(&input, "repo")?).map_err(failed)?;
                Ok(serde_json::json!({"token_prefix": &t[..8.min(t.len())], "len": t.len()}))
            }
            "token_adjudicate" => {
                let a = self.custodian.adjudicate(&str_in(&input, "repo")?, &str_in(&input, "presented")?);
                let s = match a {
                    Adjudication::Superseded => "superseded",
                    Adjudication::Current => "current",
                };
                Ok(serde_json::json!({"adjudication": s}))
            }
            "token_revoke" => {
                self.custodian.revoke(&str_in(&input, "repo")?).map_err(failed)?;
                Ok(serde_json::json!({"revoked": true}))
            }
            _ => Err(OrganelleError::not_found(format!("unknown op {op}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use organelle_host::Host;
    use organelle_manifest::validate_manifest_json;

    fn set_seal_key() {
        // SAFETY: test-only; set once before any govern_organelle() call.
        unsafe { std::env::set_var("WRECK_SEAL_KEY", "ab".repeat(32).as_str()) };
    }

    fn caps() -> Vec<String> {
        vec!["wg.canon.write".to_string(), "wp.workspace".to_string(), "wp.merge".to_string(), "wp.tokens".to_string()]
    }

    #[test]
    fn static_manifests_validate() {
        for (path, name, codon) in [
            ("../organelles/wreck-govern.manifest.json", "wreck-govern", "wg"),
            ("../organelles/wreck-ports.manifest.json", "wreck-ports", "wp"),
        ] {
            let txt = std::fs::read_to_string(path).expect("manifest file reads");
            let v: Value = serde_json::from_str(&txt).expect("manifest JSON parses");
            let m = validate_manifest_json(&v).expect("static manifest must validate");
            assert_eq!(m.name, name);
            assert_eq!(m.codon, codon);
        }
    }

    #[test]
    fn rust_manifests_match_static_json() {
        for (rust, path) in [(wg_manifest(), "../organelles/wreck-govern.manifest.json"), (wp_manifest(), "../organelles/wreck-ports.manifest.json")] {
            let txt = std::fs::read_to_string(path).unwrap();
            let from_file: Value = serde_json::from_str(&txt).unwrap();
            assert_eq!(serde_json::to_value(rust).unwrap(), from_file, "Rust manifest() and organelles/*.json must agree for {path}");
        }
    }

    #[test]
    fn govern_registers_and_decides_with_receipts() {
        set_seal_key();
        let host = Host::new();
        host.register(govern_organelle().expect("govern registration")).expect("register");
        let ctx = CallContext::new("wg-test", caps());
        let sha = "a".repeat(40);

        // propose a claim through the real protocol constructor
        let claim = host.call(&ctx, "wg", "propose", serde_json::json!({
            "change_id": "chg-1", "agent_id": "agent-9", "task_id": "t-1",
            "base": sha, "head": sha, "intent": "test the organelle",
        })).expect("propose");
        assert_eq!(claim["change_id"], "chg-1");
        assert_eq!(claim["status"], "PROPOSED");

        // boundary validation rejects traversal
        assert!(host.call(&ctx, "wg", "validate_change_id", serde_json::json!({"id": "../../x"})).is_err());

        // canon rule roundtrip through the real store
        host.call(&ctx, "wg", "canon_insert", serde_json::json!({"rule": {
            "id": "R-1", "statement": "no merges on Fridays", "authority": "test",
            "created": "2026-10-10", "supersedes": null,
            "forbids_contract": null, "contract_file_patterns": []}})).expect("canon_insert");
        let g = host.call(&ctx, "wg", "canon_get", serde_json::json!({"id": "R-1"})).expect("canon_get");
        assert_eq!(g["found"], true);

        // decide runs the real governor; empty view + no evidence -> decided (rejected)
        let view = serde_json::json!({"change_id": "chg-1", "files": [], "symbols": [], "invariants": [], "contracts": [], "dependencies": []});
        let d = host.call(&ctx, "wg", "decide", serde_json::json!({
            "claim": claim, "view": view, "in_flight": [], "merged": [], "ts": "2026-10-10T00:00:00Z",
        })).expect("decide");
        assert_eq!(d["outcome"], "decided");
        assert_eq!(d["record"]["change_id"], "chg-1");

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 6, "expected >=6 receipts, got {n}");
    }

    #[test]
    fn ports_drive_a_real_git_workspace_with_receipts() {
        let host = Host::new();
        host.register(ports_organelle()).expect("ports registration");
        let ctx = CallContext::new("wp-test", caps());

        // full local-git roundtrip: init -> fork -> commit -> diff -> merge
        let init = host.call(&ctx, "wp", "workspace_init", serde_json::json!({
            "ws": "w1", "files": [{"path": "a.txt", "content": "hello"}],
        })).expect("init");
        assert_eq!(init["base"].as_str().unwrap().len(), 40);

        host.call(&ctx, "wp", "workspace_fork", serde_json::json!({"ws": "w1", "name": "chg-1"})).expect("fork");
        let commit = host.call(&ctx, "wp", "workspace_commit", serde_json::json!({
            "ws": "w1", "fork": "chg-1", "message": "change a",
            "files": [{"path": "a.txt", "content": "hello world"}],
        })).expect("commit");
        assert_eq!(commit["head"].as_str().unwrap().len(), 40);

        let view = host.call(&ctx, "wp", "workspace_diff", serde_json::json!({
            "ws": "w1", "fork": "chg-1", "change_id": "chg-1", "scope": [],
        })).expect("diff");
        assert!(view.get("change_id").is_some());

        // token custody through the real custodian
        let t1 = host.call(&ctx, "wp", "token_for", serde_json::json!({"repo": "r1"})).expect("token_for");
        assert!(t1["len"].as_u64().unwrap() > 16);
        let adj = host.call(&ctx, "wp", "token_adjudicate", serde_json::json!({"repo": "r1", "presented": "bogus"})).expect("adjudicate");
        assert!(adj["adjudication"].is_string());

        let n = host.verify_chain().expect("receipt chain must verify");
        assert!(n >= 6, "expected >=6 receipts, got {n}");
    }
}

