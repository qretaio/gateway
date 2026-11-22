//! WAF filter engine bake-off: Cloudflare wirefilter 0.7 (the gateway's
//! WAF law, via `gateway_core::waf`) vs CEL (`cel-interpreter`).
//!
//! Run with:
//!
//! ```sh
//! cargo bench -p gateway-core --bench waf_engines
//! ```
//!
//! Both engines answer the SAME four WAF questions over the SAME request
//! snapshot. The gateway compiles wirefilter rules ONCE at boot (0.7's
//! `Filter` is `Send + Sync`, so `WafRules` is a shared `Arc`), while
//! CEL's `Program` is likewise precompilable — so the headline numbers
//! are the steady-state, request-time costs. A compile+eval scenario is
//! kept for reference (it is roughly what wirefilter 0.6.1 cost per
//! request before the 0.7 migration).
//!
//! Every scenario checks the result with `black_box`, so neither engine
//! can be optimized away. The benchmark asserts both engines return the
//! same verdict before measuring.

use cel_interpreter::{Context, Program, Value as CelValue};
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use gateway_core::waf::{WafRequest, WafRule, WafRules};

/// The request snapshot shared by all benchmarks — a plausible inbound
/// API call that a WAF would inspect.
fn request() -> WafRequest<'static> {
    WafRequest {
        method: "POST",
        host: "orders.example.com",
        path: "/api/v1/orders",
        query: "include=items&token=abc",
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        referer: "https://orders.example.com/",
        content_type: "application/json",
        client_ip: Some("192.0.2.9".parse().unwrap()),
        client_port: 443,
        tls: true,
    }
}

/// The four equivalent rules, one per engine. Each pair answers the
/// same question; ordering matches so the chain scenario is fair.
const WIREFILTER_RULES: [&str; 4] = [
    r#"http.method == "DELETE""#,                                // miss
    r#"http.path contains "/admin""#,                            // miss
    r#"http.ua contains "sqlmap""#,                              // miss
    r#"http.method == "POST" and http.query contains "token=""#, // match
];

const CEL_RULES: [&str; 4] = [
    r#"method == "DELETE""#,
    r#"path.contains("/admin")"#,
    r#"ua.contains("sqlmap")"#,
    r#"method == "POST" && query.contains("token=")"#,
];

fn waf_rules() -> Vec<WafRule> {
    WIREFILTER_RULES
        .iter()
        .enumerate()
        .map(|(i, expr)| WafRule {
            name: format!("rule-{i}"),
            expression: (*expr).to_owned(),
            ..Default::default()
        })
        .collect()
}

/// Mirror the gateway's field setup for a CEL context. CEL uses flat
/// variable names and its own string methods; the values are the same.
fn cel_context<'a>(req: &'a WafRequest<'a>) -> Context<'a> {
    let mut ctx = Context::default();
    ctx.add_variable("method", req.method).unwrap();
    ctx.add_variable("host", req.host).unwrap();
    ctx.add_variable("path", req.path).unwrap();
    ctx.add_variable("query", req.query).unwrap();
    ctx.add_variable("ua", req.user_agent).unwrap();
    ctx.add_variable("referer", req.referer).unwrap();
    ctx.add_variable("content_type", req.content_type).unwrap();
    ctx.add_variable("port", req.client_port).unwrap();
    ctx.add_variable("tls", req.tls).unwrap();
    // CEL has no first-class IP type here; carry the client IP as its
    // string form. These four rules do not use IP/CIDR matching.
    ctx.add_variable("client_ip", req.client_ip.unwrap().to_string())
        .unwrap();
    ctx
}

/// Run all four CEL rules against a context, returning the index of the
/// first match (or None), mirroring `WafRules::evaluate`'s first-match-
/// wins law.
fn cel_eval(programs: &[Program], ctx: &Context) -> Option<usize> {
    programs
        .iter()
        .position(|program| matches!(program.execute(ctx), Ok(CelValue::Bool(true))))
}

pub fn bench_waf_engines(c: &mut Criterion) {
    let req = request();
    let rule_defs = waf_rules();
    let waf = WafRules::compile(&rule_defs).unwrap();
    let cel_programs = CEL_RULES
        .iter()
        .map(|expr| Program::compile(expr).unwrap())
        .collect::<Vec<_>>();

    // Sanity-check equivalence before measuring: both must answer the
    // same question (the fourth rule, "token=", matches).
    assert_eq!(waf.evaluate(&req).rule(), Some("rule-3"));
    assert_eq!(cel_eval(&cel_programs, &cel_context(&req)), Some(3));

    let mut group = c.benchmark_group("waf engines");

    // 1. The gateway's real regime: both engines precompiled at boot.
    group.bench_function(BenchmarkId::new("precompiled", "wirefilter"), |b| {
        b.iter(|| {
            let verdict = black_box(&waf).evaluate(black_box(&req));
            black_box(verdict.rule());
        });
    });
    group.bench_function(BenchmarkId::new("precompiled", "cel"), |b| {
        b.iter(|| {
            let ctx = cel_context(black_box(&req));
            black_box(cel_eval(black_box(&cel_programs), &ctx));
        });
    });

    // 2. Context-building floors — work both engines cannot avoid on a
    // request. Useful for decomposing the numbers above. (wirefilter's
    // ExecutionContext is built inside WafRules::evaluate; we can't time
    // it alone from out here, so this is a CEL-only floor.)
    group.bench_function(BenchmarkId::new("precompiled", "cel context only"), |b| {
        b.iter(|| {
            black_box(cel_context(black_box(&req)));
        });
    });

    // 3. Compile + eval — the historical per-request regime (what
    // wirefilter 0.6.1 did, and what CEL would do without caching).
    group.bench_function(BenchmarkId::new("compile+eval", "wirefilter"), |b| {
        b.iter(|| {
            let waf = WafRules::compile(black_box(&rule_defs)).unwrap();
            black_box(waf.evaluate(black_box(&req)).rule());
        });
    });
    group.bench_function(BenchmarkId::new("compile+eval", "cel"), |b| {
        b.iter(|| {
            let programs = CEL_RULES
                .iter()
                .map(|expr| Program::compile(expr).unwrap())
                .collect::<Vec<_>>();
            let ctx = cel_context(black_box(&req));
            black_box(cel_eval(&programs, &ctx));
        });
    });

    // 4. Single-rule latency — the fourth rule only (the one that
    // matches). Shows the per-rule cost with a simple expression.
    let matching_def = vec![rule_defs[3].clone()];
    let matching_waf = WafRules::compile(&matching_def).unwrap();
    let matching_cel = vec![Program::compile(CEL_RULES[3]).unwrap()];
    group.bench_function(BenchmarkId::new("single rule", "wirefilter"), |b| {
        b.iter(|| {
            black_box(black_box(&matching_waf).evaluate(black_box(&req)).rule());
        });
    });
    group.bench_function(BenchmarkId::new("single rule", "cel (precompiled)"), |b| {
        b.iter(|| {
            let ctx = cel_context(black_box(&req));
            black_box(cel_eval(black_box(&matching_cel), &ctx));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_waf_engines);
criterion_main!(benches);
