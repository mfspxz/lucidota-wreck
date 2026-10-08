//! wreck-adapters: substrate implementations of the governor's ports.
//!
//! The governor core never touches a network. It talks to `MergePort`
//! (merge execution) and reads `ChangeView`s built by the adapter from
//! (base, head) SHAs. Local git works today; the Artifacts binding
//! implements the same traits when Workers Paid lands.

pub mod artifacts;
pub mod local;
pub mod token_custodian;

pub use artifacts::{ArtifactsClient, ArtifactsMergePort, PushedEvent};
pub use local::{LocalGit, LocalMergePort};
pub use token_custodian::{Adjudication, MintedToken, Minter, TokenCustodian};
