//! The inbound trim law (edge.spec FR-008): every client-supplied
//! `x-qreta-*` header is stripped before
//! any routing, so the namespace is only ever what the host mints. The
//! trim happens FIRST at the edge; the node re-applies the same law on
//! tunnel and private-listener ingress (defense in depth). A presented
//! bearer rides through UNJUDGED — verification is the app's.

/// The host-reserved header namespace, lowercase (listener keys are
/// already lowercase; trimming stays case-insensitive regardless).
pub const HEADER_PREFIX: &str = "x-qreta-";

/// Strip every client-supplied `x-qreta-*` header. Runs before anything
/// else so the namespace is only ever what the host mints. Byte-wise,
/// so no key shape can panic the slice.
pub fn trim_qreta(headers: &mut std::collections::BTreeMap<String, String>) {
    let prefix = HEADER_PREFIX.as_bytes();
    headers.retain(|k, _| {
        !k.as_bytes()
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn trim_is_case_insensitive() {
        let mut headers = BTreeMap::from([
            ("X-QRETA-Sub".into(), "spoofed".into()),
            ("x-Qreta-Iss".into(), "evil".into()),
        ]);
        trim_qreta(&mut headers);
        assert!(headers.is_empty());
    }

    #[test]
    fn trim_keeps_everything_else() {
        // A bearer rides through UNJUDGED; the app's own headers and
        // the host-minted x-qreta facts survive only if the EDGE mints
        // them AFTER the trim (the trim runs on client headers only).
        let mut headers = BTreeMap::from([
            ("authorization".into(), "Bearer something".into()),
            ("host".into(), "orders.example.com".into()),
            ("x-forwarded-for".into(), "203.0.113.9".into()),
            ("x-custom".into(), "keep".into()),
        ]);
        trim_qreta(&mut headers);
        assert_eq!(headers.len(), 4);
        assert_eq!(headers["x-custom"], "keep");
        // An empty and a prefix-only key are stripped too; a key whose
        // prefix merely CONTAINS the namespace is not.
        let mut headers = BTreeMap::from([
            (String::new(), "empty name".into()),
            ("x-qreta-".into(), "bare prefix".into()),
            ("xqreta-sub".into(), "no dash: keep".into()),
            ("x-qreta-extra-facts".into(), "minted by the host".into()),
        ]);
        trim_qreta(&mut headers);
        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("xqreta-sub"));
    }
}
