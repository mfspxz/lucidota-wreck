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
//!  6. Fenced commit: capture identity before I/O, re-check after;
//!     fenced-out mints are discarded (revoked), never stored.
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
#[derive(Debug, Clone)]
pub struct MintedToken {
    pub id: String,
    pub plaintext: String,
    pub expires_at_unix: u64,
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

struct State {
    /// Fence generation. Bumped on every rotation/revoke. A mint that
    /// captured an older identity is fenced out at commit and discarded.
    identity: u64,
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
                identity: 0,
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
                let fence = st.identity; // capture fence BEFORE network I/O
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
                let out = if st.identity != fence {
                    // Fenced out mid-mint (rotate/revoke landed): discard,
                    // never store. The minted token must be revoked, not
                    // just dropped, or an untracked live token exists.
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
                            st.identity = st.identity.wrapping_add(1); // new generation
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
                    if let Some(m) = m {
                        let _ = self.minter.revoke(&m.id);
                    }
                    continue; // retry as follower or new leader
                }
                Outcome::Failed(e) => return Err(e),
            }
        }
    }

    /// Adjudicate a provider rejection against the PRESENTED token.
    pub fn adjudicate(&self, repo: &str, presented: &str) -> Adjudication {
        let st = self.state.lock().unwrap();
        match st.cached.get(repo) {
            Some(c) if c.plaintext == presented => Adjudication::Current,
            Some(_) => Adjudication::Superseded,
            None => Adjudication::Current, // fail-closed: refresh past it
        }
    }

    /// Refresh-or-expire: fence out everything in flight and drop the cache.
    /// The next `token_for` mints fresh. (The old token is NOT revoked here;
    /// use `revoke` when the grant is known-good but must die.)
    pub fn rotate(&self, repo: &str) {
        let mut st = self.state.lock().unwrap();
        st.identity = st.identity.wrapping_add(1);
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
            st.identity = st.identity.wrapping_add(1); // fence first
            match st.cached.remove(repo) {
                Some(c) => c.id,
                None => return Ok(()),
            }
        };
        self.minter.revoke(&id)
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
                },
                rx,
            )
        }
        fn mint_count(&self) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| c.starts_with("mint")).count()
        }
        fn revoke_count(&self) -> usize {
            self.calls.lock().unwrap().iter().filter(|c| c.starts_with("revoke")).count()
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
            self.calls.lock().unwrap().push(format!("revoke {}", token_id));
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
        entered.recv_timeout(Duration::from_secs(5)).expect("leader entered mint");
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
}
