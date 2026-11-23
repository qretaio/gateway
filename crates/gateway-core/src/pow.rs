//! Proof-of-work challenge law for edge bot mitigation.
//!
//! A WAF `Challenge` verdict does not flat-block: it issues a small,
//! HMAC-signed puzzle that a real browser solves in JavaScript (a few
//! milliseconds of SHA-256 work) while a naive scraper cannot. The
//! solution rides back in a cookie; the gateway verifies the signature
//! AND the work, then treats that client as challenged-pass for a window
//! so it is not re-issued on every request.
//!
//! Pure law — no clock, no I/O, no HTTP. The caller supplies `now_ms`
//! and the secret; this module only decides "is this a valid, unexpired,
//! correctly-solved challenge". `forbid(unsafe)` (crate-wide).
//!
//! Wire format (all base64url, no padding):
//!   challenge = b64( `<issued_ms>:<nonce>:<tag>` )
//!   solution  = b64( `<issued_ms>:<nonce>:<work>:<tag>` )
//! tag = hex(HMAC-SHA256(secret, `<issued_ms>:<nonce>` [`:<work>`]))
//! work is valid when SHA256(`<issued_ms>:<nonce>:<work>`) begins with
//! `difficulty` zero bits.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// PoW configuration (`[pow]`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowConfig {
    /// HMAC secret. MUST be set to enable challenges; an empty secret
    /// makes every challenge fail closed (no signed puzzle can be made).
    #[serde(default)]
    pub secret: String,
    /// Leading zero bits required in SHA256(challenge:work).
    pub difficulty: u8,
    /// Challenge lifetime in seconds.
    pub ttl_secs: u64,
    /// How long a solved client is trusted (seconds).
    pub verify_ttl_secs: u64,
    /// Cookie name the challenge/solution rides in.
    pub cookie: String,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            secret: String::new(),
            difficulty: 16,
            ttl_secs: 60,
            verify_ttl_secs: 3600,
            cookie: "__gateway_pow".to_owned(),
        }
    }
}

impl PowConfig {
    /// Validate at config load: a challenge with no secret is inert
    /// (fail closed), but difficulty must be sane (1..=32) or a browser
    /// could never solve it / it would be trivial.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=32).contains(&self.difficulty) {
            return Err(format!("pow difficulty {} out of 1..=32", self.difficulty));
        }
        if self.ttl_secs == 0 || self.verify_ttl_secs == 0 {
            return Err("pow ttl_secs and verify_ttl_secs must be > 0".to_owned());
        }
        Ok(())
    }

    pub fn enabled(&self) -> bool {
        !self.secret.is_empty()
    }
}

fn tag(secret: &[u8], payload: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(payload.as_bytes());
    let out = mac.finalize().into_bytes();
    hex(&out)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0x0f) as usize] as char);
    }
    s
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut bits = 0;
    for &b in bytes {
        if b == 0 {
            bits += 8;
            continue;
        }
        bits += b.leading_zeros();
        break;
    }
    bits
}

/// Issue a challenge for `now_ms`. Returns the base64url token to place
/// in the cookie and a JS-embedded payload the client can solve.
#[must_use]
pub fn issue(cfg: &PowConfig, nonce: &[u8], now_ms: i64) -> String {
    let nonce = B64.encode(nonce);
    let payload = format!("{now_ms}:{nonce}");
    let t = tag(cfg.secret.as_bytes(), &payload);
    B64.encode(format!("{payload}:{t}").as_bytes())
}

/// Verify a solved challenge. `solution` is the base64url token the
/// client produced. Returns `true` only when: signature matches, issue
/// time is within `[now-ttl, now]`, and the work has enough leading zero
/// bits. All string comparisons of tags are constant-time.
#[must_use]
pub fn verify(cfg: &PowConfig, solution: &str, now_ms: i64) -> bool {
    let Some(decoded) = B64.decode(solution.as_bytes()).ok() else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let parts: Vec<&str> = text.split(':').collect();
    if parts.len() != 4 {
        return false;
    }
    let (issued, nonce, work, presented) = (parts[0], parts[1], parts[2], parts[3]);
    let Ok(issued_ms) = issued.parse::<i64>() else {
        return false;
    };
    if issued_ms > now_ms || now_ms.saturating_sub(issued_ms) > (cfg.ttl_secs as i64) * 1000 {
        return false;
    }
    // The tag signs the WHOLE solution payload (issued:nonce:work),
    // matching what solve() produced.
    let expected = tag(cfg.secret.as_bytes(), &format!("{issued}:{nonce}:{work}"));
    if expected.as_bytes().ct_eq(presented.as_bytes()).unwrap_u8() != 1 {
        return false;
    }
    let mut hasher = Sha256::new();
    hasher.update(format!("{issued}:{nonce}:{work}").as_bytes());
    let digest = hasher.finalize();
    leading_zero_bits(&digest) >= u32::from(cfg.difficulty)
}

/// Find a solution for a challenge (used by the in-browser JS and by
/// tests). Returns the full base64url solution token, or `None` if no
/// nonce was found within `max_attempts`.
#[must_use]
pub fn solve(cfg: &PowConfig, challenge: &str, max_attempts: u64) -> Option<String> {
    let decoded = B64.decode(challenge.as_bytes()).ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let (payload, presented) = text.rsplit_once(':')?;
    // The challenge tag signs the issued/nonce payload; re-check it so
    // solve() never works on a forged challenge.
    let expected = tag(cfg.secret.as_bytes(), payload);
    if expected.as_bytes().ct_eq(presented.as_bytes()).unwrap_u8() != 1 {
        return None;
    }
    for i in 0..max_attempts {
        let work = i.to_string();
        let mut hasher = Sha256::new();
        hasher.update(format!("{payload}:{work}").as_bytes());
        if leading_zero_bits(&hasher.finalize()) >= u32::from(cfg.difficulty) {
            let solved_payload = format!("{payload}:{work}");
            let t = tag(cfg.secret.as_bytes(), &solved_payload);
            return Some(B64.encode(format!("{solved_payload}:{t}").as_bytes()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PowConfig {
        PowConfig {
            secret: "test-secret".to_owned(),
            difficulty: 8,
            ..Default::default()
        }
    }

    #[test]
    fn solve_then_verify_roundtrip() {
        let c = cfg();
        let challenge = issue(&c, b"nonce-1", 1_000_000);
        let solution = solve(&c, &challenge, 1_000_000).expect("solvable");
        assert!(verify(&c, &solution, 1_000_100));
    }

    #[test]
    fn expired_and_forged_solutions_fail() {
        let c = cfg();
        let challenge = issue(&c, b"n", 1_000);
        let solution = solve(&c, &challenge, 1_000_000).unwrap();
        assert!(!verify(&c, &solution, 1_000 + 61_000)); // expired
        assert!(!verify(&c, "not-base64!!", 1_000)); // malformed
        let mut forged = solution.clone();
        forged.push('A');
        assert!(!verify(&c, &forged, 1_000)); // bad signature
    }

    #[test]
    fn config_validation() {
        let mut c = cfg();
        assert!(c.validate().is_ok());
        c.difficulty = 0;
        assert!(c.validate().is_err());
        c.difficulty = 33;
        assert!(c.validate().is_err());
    }
}
