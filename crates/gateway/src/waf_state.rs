//! The live WAF ruleset: static TOML rules plus the rules watched from
//! `WafRule` CRs, folded into one compiled [`WafRules`] and swapped in
//! only when the watched CR set changes. The request path reads a cheap
//! `Arc` clone; recompilation (expression parse + wirefilter compile)
//! happens off the hot path, on the first request after a watch delta.
//!
//! The CR half is fail-safe: a CR whose rules fail to compile is skipped
//! and logged rather than poisoning the whole ruleset — the previous
//! good ruleset stays live. Bad TOML expressions are a boot refusal
//! (validated at config load), so they never reach here.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use gateway_core::waf::{WafRule, WafRules};

/// The compiled WAF state shared across serving tasks.
pub struct WafState {
    /// The rules from the gateway TOML config, always first in order.
    static_rules: Arc<[WafRule]>,
    /// The static-only compiled ruleset — used for verified bots, which
    /// are exempt from configurable (TOML + watched-CR) rules but still
    /// subject to the built-in private-path deny. Compiled once at boot
    /// so a bot request never recompiles the live (CR-folded) set.
    static_only: Arc<WafRules>,
    /// The cached compiled ruleset. `RwLock` because a watch delta
    /// swaps it; reads take the shared lock and clone the `Arc`.
    compiled: std::sync::RwLock<Arc<WafRules>>,
    /// The generation of the watched CR set the cached ruleset reflects.
    generation: AtomicU64,
    /// The last generation whose compile we attempted, including a
    /// failed one. A generation that failed to compile is not retried
    /// on every request (and logged once); the controller fixes the CR
    /// with a new delta, which brings a new generation.
    attempted: AtomicU64,
}

impl WafState {
    /// Seed the state from the static TOML rules. The CR set is empty at
    /// boot; the first request after the watch seeds its generation
    /// folds the CRs in.
    pub fn new(static_rules: &[WafRule]) -> Self {
        let compiled = Arc::new(
            WafRules::compile(static_rules).expect("the TOML rules were validated at config load"),
        );
        Self {
            static_rules: static_rules.to_vec().into(),
            static_only: Arc::clone(&compiled),
            compiled: std::sync::RwLock::new(compiled),
            generation: AtomicU64::new(0),
            attempted: AtomicU64::new(0),
        }
    }

    /// The built-in-deny-only ruleset: NO configurable rules at all, so
    /// even TOML `Challenge`/`Block` rules are skipped. Used for clients
    /// that proved their humanity via PoW (and for verified bots) — they
    /// still cannot reach private/admin paths (that deny is in every set).
    #[must_use]
    pub fn builtin_only(&self) -> Arc<WafRules> {
        static BUILTIN: std::sync::LazyLock<Arc<WafRules>> =
            std::sync::LazyLock::new(|| Arc::new(WafRules::compile(&[]).expect("empty ruleset")));
        Arc::clone(&BUILTIN)
    }

    /// The static-only ruleset (TOML rules, no watched CRs). Retained for
    /// callers that want TOML rules but not dynamic CRs.
    #[must_use]
    pub fn static_rules(&self) -> Arc<WafRules> {
        Arc::clone(&self.static_only)
    }

    /// The current compiled ruleset. When `watched_generation` differs
    /// from the last compile, fold the watched CR rules into the static
    /// ones, recompile, and swap. A compile failure keeps the last good
    /// ruleset and logs the reason (the CR controller marks the row
    /// not-ready too).
    pub fn rules(&self, watched_rules: &[WafRule], watched_generation: u64) -> Arc<WafRules> {
        if watched_generation != self.generation.load(Ordering::Acquire)
            && watched_generation != self.attempted.load(Ordering::Acquire)
        {
            self.attempted.store(watched_generation, Ordering::Release);
            let mut combined = Vec::with_capacity(self.static_rules.len() + watched_rules.len());
            combined.extend_from_slice(&self.static_rules);
            combined.extend_from_slice(watched_rules);
            match WafRules::compile(&combined) {
                Ok(next) => {
                    let next = Arc::new(next);
                    *self.compiled.write().expect("waf compiled lock") = Arc::clone(&next);
                    self.generation.store(watched_generation, Ordering::Release);
                    return next;
                }
                Err(err) => {
                    // A bad watched rule must not take down the WAF: keep
                    // the previous good ruleset. The generation is NOT
                    // advanced, but the attempt is recorded so we neither
                    // recompile nor re-log on every request — the
                    // controller fixes the CR with a new delta (new
                    // generation), which is attempted then.
                    eprintln!("[gateway] WafRule CR set refused: {err}");
                }
            }
        }
        Arc::clone(&self.compiled.read().expect("waf compiled lock"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str, expression: &str) -> WafRule {
        WafRule {
            name: name.to_owned(),
            expression: expression.to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn static_rules_compile_at_seed() {
        let state = WafState::new(&[rule("static", r#"http.ua contains "curl""#)]);
        let rules = state.rules(&[], 0);
        assert!(!rules.is_empty());
    }

    #[test]
    fn a_watched_delta_folds_its_rules_in() {
        let state = WafState::new(&[rule("static", r#"http.ua contains "curl""#)]);
        let rules = state.rules(&[rule("watched", r#"http.method == "POST""#)], 1);
        // Two rules now active — the generation advanced.
        assert_eq!(state.generation.load(Ordering::Acquire), 1);
        drop(rules);
    }

    #[test]
    fn a_bad_watched_rule_keeps_the_last_good_ruleset() {
        let state = WafState::new(&[rule("static", r#"http.ua contains "curl""#)]);
        let _ = state.rules(&[rule("bad", "http.method ===")], 7);
        // The generation did not advance; the old ruleset is still live.
        assert_eq!(state.generation.load(Ordering::Acquire), 0);
    }
}
