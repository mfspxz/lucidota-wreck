//! TokenCustodian — Gatekeeper-pattern credential rotation for wreck.
//!
//! Extracted from Cloudflare OS #661 (token-refresh) per
//! `cloudflare-os-research/notes/2026-10-08-cycle03-reverify-refresh.md`.
//! The custodian is the ONLY component that ever sees refresh material
//! (the Artifacts API token used to mint). Callers get short-lived repo
//! tokens and nothing else.
//!
//! Rules ported:
//!  1. Custodian != consumer. Governor holds repo tokens; agents get
//!     short-lived material only.
//!  2. Refresh material never crosses the boundary (no accessor exposes it).
//!  3. Skew-aware proactive refresh (default 60s skew on 900s tokens).
//!  4. SingleFlight coalescing: concurrent mint requests on the same repo
//!     share ONE mint, keyed by the identity fence.
//!  5. Complete-record handling: Artifacts tokens are self-contained
//!     (id/plaintext/expires_at); the minted record replaces, never merges.
//!  6. Fenced commit: capture the PER-REPO identity before I/O, re-check
//!     after; fenced-out mints are discarded (revoked), never stored.
//!     A rotation on repo A never fences repo B's in-flight mint (M-A).
//!  7. Adjudicated 401s: superseded -> retry once with a fresh token;
//!     current -> refresh-or-expire. Provider rejections are never trusted
//!     blindly.
//!  8. revoke() fences BEFORE its first I/O: a mint landing mid-revoke is
//!     discarded, never stored-then-deleted-unrevoked.
//!
//! Deliberately NOT ported: async machinery (this crate is sync;
//! singleflight is condvar-based); OAuth field-merge (no provider-omitted
//! fields for Artifacts tokens); death-notification latching
//! (notifyCredentialsExpiredOnce — no notification surface in the adapter
//! yet); consumer-side replay-reads-on-401 (that lives in the Worker, not
//! the custodian); inbound body caps (separate input-handling thread).

use std::collections::{HashMap, HashSet};
use std::sync::{Condvar, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_TTL_SECS: u64 = 900;
pub const DEFAULT_SKEW_SECS: u64 = 60;

/// A self-contained token record. The custodian hands `plaintext` to
/// callers; `id` is for revocation; `expires_at_unix` drives skew refresh.
///
/// H4 (cycle-06 audit): hand-written Debug — plaintext must never appear
/// in logs via a stray `{:?}`.
#[derive(Clone)]
pub struct MintedToken {
    pub id: String,
    pub plaintext: String,
    pub expires_at_unix: u64,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken")
            .field("id", &self.id)
            .field("plaintext", &"<redacted>")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// The minting capability. Implementations hold the refresh material
/// (e.g. the Artifacts API token); the custodian never exposes it.
pub trait Minter: Send + Sync {
    fn mint(&self, repo: &str, ttl_secs: u64) -> Result<MintedToken, String>;
    fn revoke(&self, token_id: &str) -> Result<(), String>;
}

/// Verdict on a provider rejection (401) for a presented token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adjudication {
    /// Presented token was replaced mid-flight: retry once with a fresh token.
    Superseded,
    /// Presented token is the current one: the grant may be dead;
    /// refresh-or-expire past it. Also the fail-closed default when the
    /// custodian holds nothing for the repo.
    Current,
}

#[derive(Clone)]
struct Cached {
    id: String,
    plaintext: String,
    expires_at_unix: u64,
}

// L-E (cycle-11): overwrite a secret string in place. Volatile writes so
// the compiler cannot elide them as dead stores; no `zeroize` crate in the
// dependency tree, and Cached is the only secret-bearing struct here.
//
// SAFETY: the caller must guarantee `s` is a valid, owned string slice.
// Zeroing preserves the UTF-8 invariant (NUL is valid UTF-8) and never
// changes the length, so the string stays well-formed.
unsafe fn scrub_secret(s: &mut str) {
    for b in s.as_bytes_mut().iter_mut() {
        std::ptr::write_volatile(b, 0);
    }
}

impl Drop for Cached {
    fn drop(&mut self) {
        // SAFETY: self.plaintext is an owned String; zeroing is in-place.
        unsafe { scrub_secret(&mut self.plaintext) };
    }
}

struct State {
    /// Per-repo fence generations. Bumped on that repo's rotation/revoke.
    /// A mint that captured an older identity for ITS repo is fenced out
    /// at commit and discarded. M-A (cycle-11): this used to be ONE u64
    /// for the whole custodian — repo A's rotation fenced out repo B's
    /// in-flight mint, wasting it (discard + revoke + retry).
    fences: HashMap<String, u64>,
    cached: HashMap<String, Cached>,
    in_flight: HashSet<String>,
}

pub struct TokenCustodian<M: Minter> {
    minter: M,
    ttl_secs: u64,
    skew_secs: u64,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
    state: Mutex<State>,
    changed: Condvar,
}

impl<M: Minter> TokenCustodian<M> {
    pub fn new(minter: M, ttl_secs: u64, skew_secs: u64) -> Self {
        Self::with_clock(
            minter,
            ttl_secs,
            skew_secs,
            Box::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }),
        )
    }

    pub fn with_clock(
        minter: M,
        ttl_secs: u64,
        skew_secs: u64,
        now: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        TokenCustodian {
            minter,
            ttl_secs,
            skew_secs,
            now,
            state: Mutex::new(State {
                fences: HashMap::new(),
                cached: HashMap::new(),
                in_flight: HashSet::new(),
            }),
            changed: Condvar::new(),
        }
    }

    /// Fresh while MORE than `skew` remains: refresh when < skew remains.
    fn is_fresh(&self, c: &Cached, now: u64) -> bool {
        now.saturating_add(self.skew_secs) <= c.expires_at_unix
    }

    /// Short-lived token for `repo`. Coalesces concurrent mints; refreshes
    /// proactively inside the skew window. Returns only the token material.
    pub fn token_for(&self, repo: &str) -> Result<String, String> {
        loop {
            // --- decide under lock: fast path, join flight, or lead ---
            let fence: u64 = {
                let mut st = self.state.lock().unwrap();
                let now = (self.now)();
                if let Some(c) = st.cached.get(repo) {
                    if self.is_fresh(c, now) {
                        return Ok(c.plaintext.clone());
                    }
                }
                if st.in_flight.contains(repo) {
                    // Join the in-flight mint; on wake, re-check the cache.
                    let guard = self
                        .changed
                        .wait_while(st, |s| s.in_flight.contains(repo))
                        .unwrap();
                    drop(guard);
                    continue;
                }
                // M-A (cycle-11): fence is per-repo. Capture BEFORE network I/O.
                let fence: u64 = st.fences.get(repo).copied().unwrap_or(0);
                st.in_flight.insert(repo.to_string());
                fence
            };

            // --- leader: mint outside the lock ---
            let minted = self.minter.mint(repo, self.ttl_secs);

            // --- fenced commit ---
            enum Outcome {
                Stored(String),
                Discarded(Option<MintedToken>),
                Failed(String),
            }
            let outcome: Outcome = {
                let mut st = self.state.lock().unwrap();
                st.in_flight.remove(repo);
                let out = if st.fences.get(repo).copied().unwrap_or(0) != fence {
                    // Fenced out mid-mint (rotate/revoke for THIS repo
                    // landed): discard, never store. The minted token must
                    // be revoked, not just dropped, or an untracked live
                    // token exists.
                    Outcome::Discarded(minted.ok())
                } else {
                    match minted {
                        Ok(m) => {
                            let out = m.plaintext.clone();
                            st.cached.insert(
                                repo.to_string(),
                                Cached {
                                    id: m.id,
                                    plaintext: m.plaintext,
                                    expires_at_unix: m.expires_at_unix,
                                },
                            );
                            // new generation for THIS repo only (M-A)
                            let g = st.fences.get(repo).copied().unwrap_or(0);
                            st.fences.insert(repo.to_string(), g.wrapping_add(1));
                            Outcome::Stored(out)
                        }
                        Err(e) => Outcome::Failed(e),
                    }
                };
                self.changed.notify_all();
                out
            };
            // I/O (revoke of a discarded mint) happens OUTSIDE the lock.
            match outcome {
                Outcome::Stored(t) => return Ok(t),
                Outcome::Discarded(m) => {
                    if let Some(mut m) = m {
                        let _ = self.minter.revoke(&m.id);
                        // L-E: no plaintext residue. SAFETY: owned String, in-place zeroing.
                        unsafe { scrub_secret(&mut m.plaintext) };
                    }
                    continue; // retry as follower or new leader
                }
                Outcome::Failed(e) => return Err(e),
            }
        }
    }

    /// Adjudicate a provider rejection against the PRESENTED token.
    /// L2 (cycle-06 audit): the presented token is attacker-influenced; `==`
    /// leaks prefix-match timing to a local observer. Constant-time over
    /// the bytes. Length still leaks (tokens are fixed-format) — acceptable.
    fn ct_eq(a: &str, b: &str) -> bool {
        let (x, y) = (a.as_bytes(), b.as_bytes());
        if x.len() != y.len() {
            return false;
        }
        let mut acc = 0u8;
        for i in 0..x.len() {
            acc |= x[i] ^ y[i];
        }
        acc == 0
    }

    pub fn adjudicate(&self, repo: &str, presented: &str) -> Adjudication {
        let st = self.state.lock().unwrap();
        match st.cached.get(repo) {
            Some(c) if Self::ct_eq(&c.plaintext, presented) => Adjudication::Current,
            Some(_) => Adjudication::Superseded,
            None => Adjudication::Current, // fail-closed: refresh past it
        }
    }

    /// Refresh-or-expire: fence out THIS repo's in-flight mints and drop its
    /// cache. The next `token_for` mints fresh. (The old token is NOT
    /// revoked here; use `revoke` when the grant is known-good but must
    /// die.) M-A: other repos' in-flight mints are untouched.
    pub fn rotate(&self, repo: &str) {
        let mut st = self.state.lock().unwrap();
        let g = st.fences.get(repo).copied().unwrap_or(0);
        st.fences.insert(repo.to_string(), g.wrapping_add(1));
        st.cached.remove(repo);
        // An in-flight mint keeps its entry; its commit is fenced out.
    }

    /// Fences BEFORE its first I/O: a mint landing mid-revoke is discarded,
    /// never stored-then-deleted-unrevoked. Residual risk: if the provider
    /// revoke fails, the token lives until expiry (<= ttl); callers must
    /// not treat revoke as proof of server-side death.
    pub fn revoke(&self, repo: &str) -> Result<(), String> {
        let id = {
            let mut st = self.state.lock().unwrap();
            let g = st.fences.get(repo).copied().unwrap_or(0);
            st.fences.insert(repo.to_string(), g.wrapping_add(1)); // fence first
            match st.cached.remove(repo) {
                // E0509: Cached implements Drop (L-E scrubbing), so the id
                // is cloned — the plaintext is scrubbed on drop regardless.
                Some(c) => c.id.clone(),
                None => return Ok(()),
            }
        };
        self.minter.revoke(&id)
    }
}

/// Result of [`TokenCustodian::with_one_shot`].
#[derive(Debug)]
pub struct OneShot<T> {
    pub value: T,
    /// Non-fatal problems (revoke-after-use failures). Never errors:
    /// the operation's own outcome decides success.
    pub warnings: Vec<String>,
}

impl<M: Minter> TokenCustodian<M> {
    /// One-shot token use for low-frequency paths — the OS artifact-sync.ts
    /// pattern (cycle-14/15): mint fresh per call, run `op`, revoke in a
    /// finally-equivalent, warn-on-failure (never throw on revoke).
    ///
    /// Bypasses the shared cache entirely: no skew math, no singleflight,
    /// no cache pollution. Use for provisioning and one-off reads; the
    /// hot path keeps `token_for`.
    ///
    /// Revoke failures are warnings, never errors — expiry (`ttl_secs`) is
    /// the backstop, exactly as in the OS design. Plaintext is scrubbed
    /// after use (L-E).
    pub fn with_one_shot<T>(
        &self,
        repo: &str,
        ttl_secs: u64,
        op: impl FnOnce(&str) -> Result<T, String>,
    ) -> Result<OneShot<T>, String> {
        let mut minted = self.minter.mint(repo, ttl_secs)?;
        let outcome = op(&minted.plaintext);
        // finally-equivalent: revoke regardless of the op outcome.
        let mut warnings = vec![];
        if let Err(e) = self.minter.revoke(&minted.id) {
            warnings.push(format!("one-shot: revoke {} failed: {e}", minted.id));
        }
        // L-E: no plaintext residue. SAFETY: owned String, in-place zeroing.
        unsafe { scrub_secret(&mut minted.plaintext) };
        match outcome {
            Ok(value) => Ok(OneShot { value, warnings }),
            Err(e) => {
                let mut msg = e;
                for w in warnings {
                    msg.push_str(" [");
                    msg.push_str(&w);
                    msg.push(']');
                }
                Err(msg)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    /// No-network fake: counts mints/revokes, controllable clock and release.
    struct FakeMinter {
        calls: Mutex<Vec<String>>,
        next_id: Mutex<u64>,
        expires_at: u64,
        entered_tx: mpsc::Sender<()>,
        release_rx: Mutex<Option<mpsc::Receiver<()>>>,
        delay: Duration,
        fail_revoke: Mutex<bool>,
    }

    impl FakeMinter {
        fn new(expires_at: u64) -> (Self, mpsc::Receiver<()>) {
            let (tx, rx) = mpsc::channel();
            (
                FakeMinter {
                    calls: Mutex::new(vec![]),
                    next_id: Mutex::new(0),
                    expires_at,
                    entered_tx: tx,
                    release_rx: Mutex::new(None),
                    delay: Duration::from_millis(0),
                    fail_revoke: Mutex::new(false),
                },
                rx,
            )
        }
        fn make_revoke_fail(&self) {
            *self.fail_revoke.lock().unwrap() = true;
        }
        fn mint_count(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("mint"))
                .count()
        }
        fn revoke_count(&self) -> usize {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("revoke"))
                .count()
        }
        fn revoked_ids(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter_map(|c| c.strip_prefix("revoke ").map(|s| s.to_string()))
                .collect()
        }
    }

    impl Minter for FakeMinter {
        fn mint(&self, repo: &str, _ttl: u64) -> Result<MintedToken, String> {
            self.calls.lock().unwrap().push(format!("mint {}", repo));
            let _ = self.entered_tx.send(());
            if self.delay > Duration::from_millis(0) {
                thread::sleep(self.delay);
            }
            if let Some(rx) = self.release_rx.lock().unwrap().as_ref() {
                let _ = rx.recv();
            }
            let mut n = self.next_id.lock().unwrap();
            *n += 1;
            Ok(MintedToken {
                id: format!("tok-{}", *n),
                plaintext: format!("secret-{}", *n),
                expires_at_unix: self.expires_at,
            })
        }
        fn revoke(&self, token_id: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("revoke {}", token_id));
            if *self.fail_revoke.lock().unwrap() {
                return Err("fake: revoke failed".to_string());
            }
            Ok(())
        }
    }

    fn clock_at(now: Arc<AtomicU64>) -> Box<dyn Fn() -> u64 + Send + Sync> {
        Box::new(move || now.load(Ordering::SeqCst))
    }

    #[test]
    fn skew_triggers_refresh() {
        // 900s token, 60s skew: fresh while >60s remains, refresh when <60s.
        let now = Arc::new(AtomicU64::new(1000));
        let (m, _entered) = FakeMinter::new(1900);
        let m = Arc::new(m);
        let c = TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now.clone()),
        );
        let t1 = c.token_for("r").unwrap();
        assert_eq!(m.mint_count(), 1);
        // well outside skew: no new mint
        assert_eq!(c.token_for("r").unwrap(), t1);
        assert_eq!(m.mint_count(), 1);
        // exactly 60s remain: still fresh (refresh when <60s remains)
        now.store(1840, Ordering::SeqCst);
        assert_eq!(c.token_for("r").unwrap(), t1);
        assert_eq!(m.mint_count(), 1);
        // 59s remain: inside skew window -> proactive refresh
        now.store(1841, Ordering::SeqCst);
        let t2 = c.token_for("r").unwrap();
        assert_ne!(t1, t2);
        assert_eq!(m.mint_count(), 2);
    }

    // Arc-wrapper so the trait (Send+Sync) is satisfied in tests.
    struct FakeMinterRef(Arc<FakeMinter>);
    impl Minter for FakeMinterRef {
        fn mint(&self, repo: &str, ttl: u64) -> Result<MintedToken, String> {
            self.0.mint(repo, ttl)
        }
        fn revoke(&self, token_id: &str) -> Result<(), String> {
            self.0.revoke(token_id)
        }
    }

    #[test]
    fn singleflight_coalesces_concurrent_mints() {
        let now = Arc::new(AtomicU64::new(1000));
        let (mut m, _entered) = FakeMinter::new(1900);
        m.delay = Duration::from_millis(120); // slow mint: all threads pile in
        let m = Arc::new(m);
        let c = Arc::new(TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        ));
        let mut handles = vec![];
        for _ in 0..8 {
            let c2 = c.clone();
            handles.push(thread::spawn(move || c2.token_for("r").unwrap()));
        }
        let mut outs: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        outs.dedup();
        assert_eq!(outs.len(), 1, "all callers share one mint");
        assert_eq!(m.mint_count(), 1, "exactly one provider mint");
    }

    #[test]
    fn fenced_commit_discards_overtaken_mint() {
        let now = Arc::new(AtomicU64::new(1000));
        let (m, entered) = FakeMinter::new(1900);
        let (rel_tx, rel_rx) = mpsc::channel::<()>();
        *m.release_rx.lock().unwrap() = Some(rel_rx);
        let m = Arc::new(m);
        let c = Arc::new(TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        ));
        // leader starts a mint and blocks inside it
        let c2 = c.clone();
        let h = thread::spawn(move || c2.token_for("r").unwrap());
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("leader entered mint");
        // rotate lands mid-mint: fences the in-flight mint out
        c.rotate("r");
        // release the mint; the leader must discard, not store
        let _ = rel_tx.send(());
        // the leader retries into a second mint: release that one too
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("leader retried into second mint");
        let _ = rel_tx.send(());
        let final_token = h.join().unwrap();
        // first mint was discarded (revoked), second mint produced the token
        assert_eq!(m.mint_count(), 2);
        assert_eq!(m.revoke_count(), 1);
        assert_eq!(m.revoked_ids(), vec!["tok-1".to_string()]);
        assert_eq!(final_token, "secret-2");
        // and the cached token is the second one
        assert_eq!(c.token_for("r").unwrap(), "secret-2");
        assert_eq!(m.mint_count(), 2, "no third mint");
    }

    #[test]
    fn adjudication() {
        let now = Arc::new(AtomicU64::new(1000));
        let (m, _entered) = FakeMinter::new(1900);
        let m = Arc::new(m);
        let c = TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        );
        let t1 = c.token_for("r").unwrap();
        assert_eq!(c.adjudicate("r", &t1), Adjudication::Current);
        c.rotate("r");
        let t2 = c.token_for("r").unwrap();
        assert_ne!(t1, t2);
        // presented the replaced token: superseded -> retry once with fresh
        assert_eq!(c.adjudicate("r", &t1), Adjudication::Superseded);
        assert_eq!(c.adjudicate("r", &t2), Adjudication::Current);
        // unknown repo: fail-closed -> Current (refresh past it)
        assert_eq!(c.adjudicate("nope", "whatever"), Adjudication::Current);
    }

    #[test]
    fn revoke_fences_before_io() {
        let now = Arc::new(AtomicU64::new(1000));
        let (m, _entered) = FakeMinter::new(1900);
        let m = Arc::new(m);
        let c = TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        );
        let t1 = c.token_for("r").unwrap();
        c.revoke("r").unwrap();
        assert_eq!(m.revoke_count(), 1);
        // next request mints fresh; the revoked token is adjudicated superseded
        let t2 = c.token_for("r").unwrap();
        assert_ne!(t1, t2);
        assert_eq!(c.adjudicate("r", &t1), Adjudication::Superseded);
    }

    // --- L2 (cycle-09): constant-time token comparison --------------------

    #[test]
    fn ct_eq_equal() {
        assert!(TokenCustodian::<FakeMinterRef>::ct_eq("abc123", "abc123"));
    }

    #[test]
    fn ct_eq_differs_one_byte() {
        assert!(!TokenCustodian::<FakeMinterRef>::ct_eq("abc123", "abc124"));
    }

    #[test]
    fn ct_eq_length_mismatch() {
        assert!(!TokenCustodian::<FakeMinterRef>::ct_eq("abc123", "abc12"));
        assert!(!TokenCustodian::<FakeMinterRef>::ct_eq("", "x"));
    }

    #[test]
    fn ct_eq_empty() {
        assert!(TokenCustodian::<FakeMinterRef>::ct_eq("", ""));
    }
    // --- M-A (cycle-11): per-repo fence ---------------------------------

    #[test]
    fn rotate_other_repo_does_not_fence_this_mint() {
        // Repo A's mint is in flight (blocked inside the fake). A rotation
        // on repo B must NOT fence it out: the mint is stored, not
        // discarded+revoked+retried.
        let now = Arc::new(AtomicU64::new(1000));
        let (m, entered) = FakeMinter::new(1900);
        let (rel_tx, rel_rx) = mpsc::channel::<()>();
        *m.release_rx.lock().unwrap() = Some(rel_rx);
        let m = Arc::new(m);
        let c = Arc::new(TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        ));
        let c2 = c.clone();
        let h = thread::spawn(move || c2.token_for("a").unwrap());
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("leader entered mint for a");
        c.rotate("b"); // rotation on a DIFFERENT repo
        let _ = rel_tx.send(());
        let tok = h.join().unwrap();
        assert_eq!(tok, "secret-1", "mint for a must be stored, not fenced out");
        assert_eq!(m.mint_count(), 1, "no retry mint");
        assert_eq!(m.revoke_count(), 0, "nothing revoked");
        assert_eq!(c.token_for("a").unwrap(), "secret-1");
    }

    #[test]
    fn same_repo_rotate_still_fences_its_own_mint() {
        // Per-repo fencing must not weaken the same-repo guarantee:
        // rotate("a") mid-mint for "a" still discards + revokes.
        let now = Arc::new(AtomicU64::new(1000));
        let (m, entered) = FakeMinter::new(1900);
        let (rel_tx, rel_rx) = mpsc::channel::<()>();
        *m.release_rx.lock().unwrap() = Some(rel_rx);
        let m = Arc::new(m);
        let c = Arc::new(TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        ));
        let c2 = c.clone();
        let h = thread::spawn(move || c2.token_for("a").unwrap());
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("leader entered mint");
        c.rotate("a");
        let _ = rel_tx.send(());
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("leader retried into second mint");
        let _ = rel_tx.send(());
        assert_eq!(h.join().unwrap(), "secret-2");
        assert_eq!(m.mint_count(), 2);
        assert_eq!(m.revoke_count(), 1);
        assert_eq!(m.revoked_ids(), vec!["tok-1".to_string()]);
    }

    // --- L-E (cycle-11): plaintext scrubbing --------------------------------
    //
    // Memory scrubbing itself is not unit-observable (no safe way to read
    // freed memory); these tests pin the API-visible half — after rotate /
    // revoke / replacement the old plaintext is unreachable through the
    // custodian — and the Drop impl is verified by code read.

    #[test]
    fn old_plaintext_unrecoverable_after_rotate() {
        let now = Arc::new(AtomicU64::new(1000));
        let (m, _entered) = FakeMinter::new(1900);
        let m = Arc::new(m);
        let c = TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        );
        let t1 = c.token_for("r").unwrap();
        c.rotate("r");
        // cache is empty: adjudicate falls to the fail-closed default
        // (Current = "refresh past it"), and the next token_for mints
        // fresh — the old plaintext is never served again.
        assert_eq!(c.adjudicate("r", &t1), Adjudication::Current);
        let t2 = c.token_for("r").unwrap();
        assert_ne!(t1, t2);
        assert_eq!(m.mint_count(), 2);
    }

    #[test]
    fn old_plaintext_unrecoverable_after_revoke() {
        let now = Arc::new(AtomicU64::new(1000));
        let (m, _entered) = FakeMinter::new(1900);
        let m = Arc::new(m);
        let c = TokenCustodian::with_clock(
            FakeMinterRef(m.clone()),
            DEFAULT_TTL_SECS,
            DEFAULT_SKEW_SECS,
            clock_at(now),
        );
        let t1 = c.token_for("r").unwrap();
        c.revoke("r").unwrap();
        assert_eq!(c.adjudicate("r", &t1), Adjudication::Current);
        assert_eq!(m.revoke_count(), 1);
        let t2 = c.token_for("r").unwrap();
        assert_ne!(t1, t2);
    }

    // ---- cycle-15: one-shot mint/use/revoke (OS artifact-sync pattern) ----

    fn one_shot_custodian(m: Arc<FakeMinter>) -> TokenCustodian<FakeMinterRef> {
        let now = Arc::new(AtomicU64::new(1000));
        TokenCustodian::with_clock(FakeMinterRef(m), 900, 60, clock_at(now))
    }

    #[test]
    fn one_shot_mints_uses_revokes_and_bypasses_cache() {
        let (m, _entered) = FakeMinter::new(9999);
        let m = Arc::new(m);
        let c = one_shot_custodian(m.clone());
        let r = c
            .with_one_shot("r", 300, |tok| {
                assert!(tok.starts_with("secret-"));
                Ok::<_, String>(tok.len())
            })
            .unwrap();
        assert!(r.warnings.is_empty());
        assert_eq!(m.mint_count(), 1);
        // the one-shot token was revoked after use (revoke-after-use)
        assert_eq!(m.revoked_ids(), vec!["tok-1".to_string()]);
        // and it never touched the shared cache: token_for mints fresh
        let _ = c.token_for("r").unwrap();
        assert_eq!(m.mint_count(), 2);
    }

    #[test]
    fn one_shot_revokes_even_when_op_fails() {
        let (m, _entered) = FakeMinter::new(9999);
        let m = Arc::new(m);
        let c = one_shot_custodian(m.clone());
        let r = c.with_one_shot("r", 300, |_| Err::<(), String>("op blew up".into()));
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("op blew up"));
        // finally-equivalent: the token was still revoked
        assert_eq!(m.revoked_ids(), vec!["tok-1".to_string()]);
    }

    #[test]
    fn one_shot_revoke_failure_is_a_warning_not_an_error() {
        let (m, _entered) = FakeMinter::new(9999);
        let m = Arc::new(m);
        m.make_revoke_fail();
        let c = one_shot_custodian(m.clone());
        let r = c
            .with_one_shot("r", 300, |_| Ok::<_, String>("done"))
            .unwrap();
        assert_eq!(r.value, "done");
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("revoke tok-1 failed"));
        // and on op failure the revoke warning rides along on the error
        let e = c
            .with_one_shot("r", 300, |_| Err::<(), String>("op blew up".into()))
            .unwrap_err();
        assert!(e.contains("op blew up"));
        assert!(e.contains("revoke tok-2 failed"));
    }
}
#[cfg(test)]
mod h4_redaction_tests {
    use super::*;

    #[test]
    fn minted_token_debug_redacts_plaintext() {
        let t = MintedToken {
            id: "tok-1".into(),
            plaintext: "art_v1_SUPERSECRET?expires=123".into(),
            expires_at_unix: 999,
        };
        let dbg = format!("{:?}", t);
        assert!(!dbg.contains("SUPERSECRET"), "leaked: {}", dbg);
        assert!(
            dbg.contains("<redacted>"),
            "missing redaction marker: {}",
            dbg
        );
        // non-secret fields still visible for operability
        assert!(dbg.contains("tok-1"), "id lost: {}", dbg);
    }
}
