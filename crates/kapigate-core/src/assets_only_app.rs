//! The AssetsOnlyApp RGD's wire types (the gateway's asset source of
//! truth). A `AssetsOnlyApp` row binds a `public/` virtual filesystem to
//! an optional HTTPRoute backend: a request whose path is in
//! `status.public_paths` is served from that tree; otherwise the
//! referenced HTTPRoute's backend handles it — or a 404 when no route
//! is named.
//!
//! Pure serde types only (this crate is I/O-free). The CRD derive lives
//! in the consumer that owns `kube` (wisolate's crdgen); the gateway and
//! the kapi controller parse/emit these types over the generic CR surface.
//!
//! Validation law: exactly one of `oci` / `volume`. The group is
//! `kapi.qreta.io/v1alpha1` (owner directive B), never the upstream
//! `gateway.networking.k8s.io` group.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// What a request does when no `public/` path matches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotFoundHandling {
    /// A plain 404.
    #[default]
    None,
    /// Serve a `404.html` page from the public tree when present.
    NotFoundPage,
    /// Serve `index.html` (client-side routing).
    SinglePageApplication,
}

/// The AssetsOnlyApp spec. Exactly one of `oci` / `volume` is valid.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetsOnlyAppSpec {
    /// An OCI image ref whose `public/` tree holds the assets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci: Option<String>,
    /// A standard k8s volume name holding the assets under `public/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// The HTTPRoute whose backend handles non-asset paths. Absent = 404.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_route_ref: Option<String>,
    /// What to serve/answer when no public path matches and there is no
    /// route backend.
    #[serde(default)]
    pub not_found_handling: NotFoundHandling,
}

impl AssetsOnlyAppSpec {
    /// The exactly-one-of validation law.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.oci.is_some() != self.volume.is_some()
    }

    /// The source label for diagnostics/logs — never a wire value.
    #[must_use]
    pub fn source_kind(&self) -> &'static str {
        match (&self.oci, &self.volume) {
            (Some(_), None) => "oci",
            (None, Some(_)) => "volume",
            _ => "invalid",
        }
    }
}

/// The resolved asset facts the gateway serves from. Populated by the
/// no controller (definition-only RGD) (wisolate writes the spec, kapi resolves
/// the tree into these facts). The gateway is read-only on these.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetsOnlyAppStatus {
    /// url path (no leading slash) -> byte length, under `public/`.
    #[serde(default)]
    pub public_paths: BTreeMap<String, u64>,
    /// url path (no leading slash) -> sha256 hex (feeds the ETag).
    #[serde(default)]
    pub hashes: BTreeMap<String, String>,
    /// `_headers` rules: url pattern -> header name/value map.
    #[serde(default)]
    pub header_rules: Vec<crate::assets::HeaderRule>,
    /// A controller note when the source could not be resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_of_oci_or_volume() {
        let oci = AssetsOnlyAppSpec {
            oci: Some("ghcr.io/a/b:sha".to_owned()),
            volume: None,
            ..Default::default()
        };
        assert!(oci.valid());
        assert_eq!(oci.source_kind(), "oci");
        let vol = AssetsOnlyAppSpec {
            volume: Some("my-vol".to_owned()),
            ..Default::default()
        };
        assert!(vol.valid());
        assert_eq!(vol.source_kind(), "volume");
        let neither = AssetsOnlyAppSpec::default();
        assert!(!neither.valid());
        let both = AssetsOnlyAppSpec {
            oci: Some("x".to_owned()),
            volume: Some("y".to_owned()),
            ..Default::default()
        };
        assert!(!both.valid());
    }

    #[test]
    fn route_ref_is_optional_and_default_handling_is_none() {
        let s: AssetsOnlyAppSpec = serde_json::from_str(r#"{"volume":"v"}"#).expect("parses");
        assert_eq!(s.http_route_ref, None);
        assert_eq!(s.not_found_handling, NotFoundHandling::None);
    }
}
