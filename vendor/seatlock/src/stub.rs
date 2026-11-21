//! No enforcement on this platform: both APIs are no-ops that succeed.
//! pie only builds for macOS and Linux (a compile_error guards the rest),
//! so this module exists to keep the surface total.

use super::error::Error;
use super::policy::Policy;

/// No-op.
///
/// # Errors
/// Never fails.
pub fn apply(_policy: &Policy) -> Result<(), Error> {
    Ok(())
}

/// No-op.
///
/// # Errors
/// Never fails.
pub fn install(_command: &mut std::process::Command, _policy: &Policy) -> Result<(), Error> {
    Ok(())
}
