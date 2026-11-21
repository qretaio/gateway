//! The seatlock error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("landlock: {0}")]
    Landlock(String),
    /// The policy itself cannot be expressed — e.g. a relative path in a
    /// deny list would silently rule nothing.
    #[error("policy: {0}")]
    Policy(String),
    /// This process is already inside a Seatbelt sandbox. macOS cannot
    /// install a second profile — a sandboxed process applying another
    /// one fails (or worse, `sandbox-exec` refuses to even start). The
    /// caller must run the confinement OUTSIDE the outer sandbox, or the
    /// outer sandbox must be the confinement.
    #[error(
        "nested sandbox: this process already runs inside a Seatbelt sandbox, and macOS \
         cannot install a second profile — run the confinement outside the outer sandbox \
         (check the caller's own launcher: `sandbox-exec`, a hardened IDE agent, or a CI \
         runner may have applied one)"
    )]
    Nested,
    /// The posture cannot be enforced on this platform.
    #[error("{0}")]
    Unsupported(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
