//! The OCI pull GRAMMAR the edge's asset pulls speak: reference
//! parsing and normalization, the URL laws, digest verification (in
//! memory), the image-index descent rule, the unit wrapper's
//! custom-section payload walk, and the metadata caps. NO I/O lives
//! here: no HTTP client, no registry auth, no filesystem — the pulls
//! ride the edge's reqwest client (the asset store), which imports
//! these names as its vocabulary.
#![forbid(unsafe_code)]

use anyhow::{Context, Result, bail};

/// A parsed registry reference: `<registry>/<repository>[:tag][@digest]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Registry host (`index.docker.io` after normalization).
    pub registry: String,
    /// Repository path (`library/nginx` for docker.io short forms).
    pub repository: String,
    /// Tag or `sha256:<64 hex chars>` digest; `latest` when neither is given.
    pub reference: String,
    /// True when pinned by digest (no resolution, no tag mutation).
    pub digest_pinned: bool,
}

impl Reference {
    /// Parse + normalize. Handles the docker.io implicit forms: a bare
    /// `repo` or `repo:tag` resolves to `index.docker.io/library/repo`.
    /// A tag may ride along with a digest pin (`repo:tag@sha256:…`) —
    /// the tag is stripped; the digest is the identity.
    pub fn parse(s: &str) -> Result<Self> {
        let (rest, digest) = match s.split_once('@') {
            Some((rest, d)) => {
                if !d.starts_with("sha256:") || d.len() != 71 {
                    bail!("digest must be sha256:<64 hex chars>, got {d:?}");
                }
                (rest, Some(d.to_owned()))
            }
            None => (s, None),
        };

        // Split registry from repository: the first `/`-separated
        // component is a registry iff it contains '.' or ':' or is
        // `localhost` (docker's distribution convention).
        let (mut registry, mut repository) = match rest.split_once('/') {
            Some((first, tail))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_owned(), tail.to_owned())
            }
            _ => ("index.docker.io".to_owned(), rest.to_owned()),
        };
        // docker.io is the marketing site; the distribution API lives
        // on index.docker.io.
        if registry == "docker.io" {
            registry = "index.docker.io".to_owned();
        }
        if registry == "index.docker.io" && !repository.contains('/') {
            repository = format!("library/{repository}");
        }

        // A `:tag` on the repo path is only a tag when the suffix has
        // no `/` (ports live in the registry part). Tags are the last
        // path segment, so hand the repo back intact.
        let mut tag = None;
        if let Some(colon) = repository.rfind(':') {
            let t = &repository[colon + 1..];
            anyhow::ensure!(!t.is_empty(), "empty tag in {s:?}");
            if !t.contains('/') {
                tag = Some(repository[colon + 1..].to_owned());
                repository.truncate(colon);
            }
        }
        let digest_pinned = digest.is_some();
        let reference = match digest {
            Some(d) => d,
            None => tag.unwrap_or_else(|| "latest".to_owned()),
        };
        Ok(Self {
            registry,
            repository,
            reference,
            digest_pinned,
        })
    }

    /// `http` for loopback registries (localhost / 127.0.0.1 — the
    /// on-host convention, and it makes the flow testable in-process),
    /// `https` everywhere else.
    fn scheme(&self) -> &'static str {
        scheme_for_registry(&self.registry)
    }

    /// The distribution-API manifest URL for this reference.
    pub fn manifest_url(&self) -> String {
        format!(
            "{scheme}://{registry}/v2/{repo}/manifests/{reference}",
            scheme = self.scheme(),
            registry = self.registry,
            repo = self.repository,
            reference = self.reference
        )
    }

    /// The distribution-API blob URL for `digest`.
    pub fn blob_url(&self, digest: &str) -> String {
        format!(
            "{scheme}://{registry}/v2/{repo}/blobs/{digest}",
            scheme = self.scheme(),
            registry = self.registry,
            repo = self.repository,
            digest = digest
        )
    }
}

/// The manifest-route Accept header the pull negotiates with —
/// carried here beside the reference grammar it serves.
pub const ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
                      application/vnd.oci.image.manifest.v1+json, \
                      application/vnd.docker.distribution.manifest.list.v2+json, \
                      application/vnd.docker.distribution.manifest.v2+json";

/// Manifests and image indexes are registry METADATA — kilobytes in
/// every real image. The read is capped: a registry (or a misbehaving
/// mirror) answering a manifest route with a body dump must never ride
/// into the heap unbounded.
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// The custom-section name of a UNIT WRAPPER: the packed artifact
/// carries a WorkerJs unit tree (script + assets/) as the tar.gz
/// payload of a wasm module whose ONLY content is this custom section.
/// Why: the push transport is `wkg oci push` (wkg speaks the registry
/// and accepts real wasm only); a custom section is the wasm-native
/// carrier for a non-wasm payload. The module parses (wkg validates
/// it), the bytes ride the `application/wasm` layer verbatim, and the
/// unpack reads the section back out and untars the tree. The name is
/// the contract with the client (the builder's UNIT_SECTION).
pub const UNIT_WRAPPER_SECTION: &str = "wisolate.unit.v1";

/// Hex-encode the SHA-256 of `bytes` — the one hashing idiom for the
/// crate.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Verify `bytes` against a `sha256:<64 hex>` digest.
pub fn verify_digest(digest: &str, bytes: &[u8]) -> Result<()> {
    let Some(expected) = digest.strip_prefix("sha256:") else {
        bail!("unsupported digest algorithm: {digest:?}");
    };
    let got = sha256_hex(bytes);
    if got != expected {
        bail!("digest mismatch: expected {expected}, got {got}");
    }
    Ok(())
}

/// The unit wrapper's payload — `Some(tar.gz bytes)` when `wasm` is a
/// module carrying nothing but the [`UNIT_WRAPPER_SECTION`] custom
/// section; `None` for real wasm (any code-bearing section, or a
/// component). Malformed wasm is an error, not `None`: a layer that
/// claims wasm and parses as neither is a broken image.
pub fn unit_wrapper_payload(wasm: &[u8]) -> Result<Option<Vec<u8>>> {
    let mut payload = None;
    for item in wasmparser::Parser::new(0).parse_all(wasm) {
        match item.context("parse wasm layer")? {
            wasmparser::Payload::CustomSection(s) if s.name() == UNIT_WRAPPER_SECTION => {
                payload = Some(s.data().to_vec());
            }
            wasmparser::Payload::Version { .. } | wasmparser::Payload::End(_) => {}
            _ => return Ok(None),
        }
    }
    Ok(payload)
}

/// `http` for loopback registries (localhost / 127.0.0.1 — the
/// on-host convention, and it keeps the login flows testable
/// in-process), `https` everywhere else.
#[must_use]
pub fn scheme_for_registry(host: &str) -> &'static str {
    let bare = host.split(':').next().unwrap_or_default();
    // `*.localhost` is the RFC 6761 loopback name — always this machine,
    // never TLS. The inbuilt registry app's host is a natural resident.
    if bare == "localhost" || bare == "127.0.0.1" || bare == "::1" || bare.ends_with(".localhost") {
        "http"
    } else {
        "https"
    }
}

/// A manifest-list wrapper rather than a bare manifest?
#[must_use]
pub fn is_index(manifest_bytes: &[u8]) -> bool {
    serde_json::from_slice::<oci_spec::image::ImageIndex>(manifest_bytes)
        .map(|_| true)
        .unwrap_or(false)
}

#[must_use]
pub fn is_linux_amd64(descriptor: &oci_spec::image::Descriptor) -> bool {
    descriptor
        .platform()
        .as_ref()
        .is_some_and(|p| p.architecture().to_string() == "amd64" && p.os().to_string() == "linux")
}

/// The image-index descent rule, named once: the first linux/amd64
/// entry, else the first entry (the payload is platform-independent
/// wasm). Every digest a reference resolves to goes through here, so
/// a poll's digest and a pull's digest cannot drift.
pub fn index_entry(index: &oci_spec::image::ImageIndex) -> Result<&oci_spec::image::Descriptor> {
    index
        .manifests()
        .iter()
        .find(|d| is_linux_amd64(d))
        .or_else(|| index.manifests().first())
        .context("empty image index")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_references() {
        let r = Reference::parse("orders").unwrap();
        assert_eq!(r.registry, "index.docker.io");
        assert_eq!(r.repository, "library/orders");
        assert_eq!(r.reference, "latest");

        let r = Reference::parse("qretaio/orders:v1").unwrap();
        assert_eq!(r.registry, "index.docker.io");
        // Namespaced repos keep their path; only bare names get `library/`.
        assert_eq!(r.repository, "qretaio/orders");
        assert_eq!(r.reference, "v1");

        let r = Reference::parse("ghcr.io/qretaio/orders").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "qretaio/orders");
        assert_eq!(r.reference, "latest");
        assert!(!r.digest_pinned);

        let r = Reference::parse("localhost:5000/wasm/app@sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "wasm/app");
        assert!(r.digest_pinned);

        // A tag may ride along with a digest pin: the digest is the
        // identity and the tag must NOT stay embedded in the repository
        // (it would corrupt every URL: /v2/repo:tag/manifests/<tag>).
        let r = Reference::parse("ghcr.io/qretaio/orders:v1@sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "qretaio/orders");
        assert_eq!(
            r.reference,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert!(r.digest_pinned);
        assert_eq!(
            r.manifest_url(),
            "https://ghcr.io/v2/qretaio/orders/manifests/sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );

        assert!(Reference::parse("repo@sha256:tooshort").is_err());
        assert!(
            Reference::parse(
                "repo@md5:0000000000000000000000000000000000000000000000000000000000000000"
            )
            .is_err()
        );
    }

    #[test]
    fn urls_are_well_formed() {
        let r = Reference::parse("ghcr.io/qretaio/orders:v1").unwrap();
        assert_eq!(
            r.manifest_url(),
            "https://ghcr.io/v2/qretaio/orders/manifests/v1"
        );
        assert_eq!(
            r.blob_url("sha256:ab"),
            "https://ghcr.io/v2/qretaio/orders/blobs/sha256:ab"
        );
    }

    #[test]
    fn loopback_registries_speak_http() {
        let r = Reference::parse("localhost:63046/test/app:latest").unwrap();
        assert!(
            r.manifest_url().starts_with("http://"),
            "{}",
            r.manifest_url()
        );
        let r = Reference::parse("127.0.0.1:63047/test/app").unwrap();
        assert!(
            r.manifest_url().starts_with("http://"),
            "{}",
            r.manifest_url()
        );
        let r = Reference::parse("ghcr.io/x/y").unwrap();
        assert!(r.manifest_url().starts_with("https://"));
    }

    #[test]
    fn digest_verification_refuses_mismatches() {
        let good = format!("sha256:{}", sha256_hex(b"payload-bytes"));
        verify_digest(&good, b"payload-bytes").unwrap();
        let bad = format!("sha256:{}", sha256_hex(b"other-bytes"));
        assert!(verify_digest(&bad, b"payload-bytes").is_err());
    }

    /// The unit wrapper the builder emits: a wasm module whose only
    /// section is the unit section carrying the unit tar.gz.
    fn unit_wrapper(files: &std::collections::BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let tar = {
            let mut b = tar::Builder::new(Vec::new());
            for (name, data) in files {
                let mut h = tar::Header::new_ustar();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, name, &data[..]).unwrap();
            }
            b.into_inner().unwrap()
        };
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, &tar).unwrap();
        let payload = gz.finish().unwrap();
        fn leb(mut n: usize, out: &mut Vec<u8>) {
            loop {
                let b = (n & 0x7f) as u8;
                n >>= 7;
                if n == 0 {
                    out.push(b);
                    return;
                }
                out.push(b | 0x80);
            }
        }
        let name = UNIT_WRAPPER_SECTION.as_bytes();
        let mut body = Vec::new();
        leb(name.len(), &mut body);
        body.extend_from_slice(name);
        body.extend_from_slice(&payload);
        let mut module = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00];
        leb(body.len(), &mut module);
        module.extend_from_slice(&body);
        module
    }

    #[test]
    fn a_unit_wrapper_carries_its_tar_gz_payload_and_refuses_real_wasm() {
        let files: std::collections::BTreeMap<String, Vec<u8>> = [
            ("script.js".to_owned(), b"export default {}".to_vec()),
            ("assets/index.html".to_owned(), b"<h1>hi</h1>".to_vec()),
        ]
        .into();
        let wasm = unit_wrapper(&files);
        assert_eq!(
            unit_wrapper_payload(&wasm).unwrap().map(|p| !p.is_empty()),
            Some(true)
        );
        // A real (empty) module is NOT a wrapper; garbage is an error.
        assert_eq!(
            unit_wrapper_payload(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0, 0, 0]).unwrap(),
            None
        );
        assert!(unit_wrapper_payload(b"not wasm").is_err());
    }
}
