//! The host route matcher (edge.spec FR-001): a route pattern is
//! `host` or `host/path` or `host/path*`; a request matches when the
//! pattern's host equals the request's Host case-insensitively and the
//! pattern's path is a prefix of the request's path. Specificity — the
//! matched `host + path` length — is the longest-prefix sort key; the
//! caller sorts by it (ties break by org, the serving layer's rule).
//! No wildcards: the `*` in a pattern is a prefix-open marker, not a
//! glob (boundary.rs's egress grammar is a different law).

/// Match specificity: `None` = no match; `Some(len)` = matched prefix
/// length (`host + path`), the longest-prefix sort key.
pub fn route_specificity(pattern: &str, host: &str, path: &str) -> Option<usize> {
    let (p_host, p_path) = match pattern.split_once('/') {
        Some((h, p)) => (h.to_ascii_lowercase(), format!("/{p}")),
        None => (pattern.to_ascii_lowercase(), "/".to_owned()),
    };
    if p_host != host {
        return None;
    }
    let p_path = p_path.trim_end_matches('*');
    let request_path = if path.is_empty() { "/" } else { path };
    if request_path.starts_with(p_path) {
        Some(p_host.len() + p_path.len())
    } else {
        None
    }
}

/// Boolean face over [`route_specificity`].
pub fn route_matches(pattern: &str, host: &str, path: &str) -> bool {
    route_specificity(pattern, host, path).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_is_exact_and_case_blind() {
        // The PATTERN host folds; the REQUEST host is taken as-given —
        // the serving path lowercases it at entry (ServeNode::route),
        // so the ci law holds end to end with each side folding once.
        assert!(route_matches(
            "Orders.Example.com/",
            "orders.example.com",
            "/"
        ));
        assert!(route_matches(
            "ORDERS.example.com",
            "orders.example.com",
            "/x"
        ));
        assert!(!route_matches(
            "Orders.Example.com",
            "Orders.Example.com",
            "/x"
        ));
        // A different host never matches, whatever the path.
        assert!(!route_matches(
            "orders.example.com",
            "other.example.com",
            "/"
        ));
        assert!(!route_matches(
            "orders.example.com",
            "orders.example.com.evil",
            "/"
        ));
    }

    #[test]
    fn the_longest_prefix_wins_and_sorts() {
        // Bare-host patterns match every path (the pattern path is "/").
        assert!(route_matches(
            "orders.example.com",
            "orders.example.com",
            "/a/b"
        ));
        assert!(route_matches(
            "orders.example.com/",
            "orders.example.com",
            "/a/b"
        ));
        // A path pattern is a prefix law: `/api` matches `/api/v1` and
        // `/apix` alike (a prefix, not a segment match) — the behavior
        // as it ships; callers disambiguate with more specific routes.
        assert!(route_matches("h/api", "h", "/api/v1"));
        assert!(route_matches("h/api", "h", "/apix"));
        assert!(!route_matches("h/api", "h", "/ap"));
        assert!(!route_matches("h/api", "h", "/"));
        // The trailing `*` is the same prefix with the marker trimmed.
        assert_eq!(
            route_specificity("h/api*", "h", "/api/v1"),
            route_specificity("h/api", "h", "/api/v1")
        );
        // Specificity grows with the matched prefix, so a longer
        // pattern sorts over a shorter one on the same request.
        let deep = route_specificity("h/api/v1", "h", "/api/v1/x").unwrap();
        let shallow = route_specificity("h/api", "h", "/api/v1/x").unwrap();
        let bare = route_specificity("h", "h", "/api/v1/x").unwrap();
        assert!(deep > shallow && shallow > bare);
        assert_eq!(deep, "h/api/v1".len());
    }

    #[test]
    fn an_empty_request_path_is_the_root() {
        assert_eq!(route_specificity("h", "h", ""), Some("h/".len()));
        assert!(route_matches("h/", "h", ""));
    }
}
