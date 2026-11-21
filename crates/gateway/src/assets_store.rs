//! The gateway-side asset store (kapi.spec EDGE-FR-007, the store half): the
//! app's artifact pulled through the OCI distribution protocol, the
//! asset tree extracted in memory, files answered by the asset law —
//! no backend wakes for a static hit. The reference/URL/digest laws
//! ride this crate's `oci` module (one home); this module carries only the I/O around
//! them. The tree invalidates on the row's image reference — a new
//! ref re-pulls, the old tree orphans. A pull failure is a
//! fall-through to the backend (never a 5xx from a half-pulled tree).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::oci::{
    ACCEPT, MAX_MANIFEST_BYTES, Reference, is_index, scheme_for_registry, unit_wrapper_payload,
    verify_digest,
};
use crate::table::RegistryAuth;

/// Mint a scoped Bearer token from an OCI 401 `WWW-Authenticate` Bearer
/// challenge (`realm="…",service="…"`), using the namespace's
/// dockerconfigjson Basic credential. The same exchange wisolate's
/// `auth::fetch_token` performs; returns `None` on a malformed challenge
/// or a token endpoint that does not answer with `{"token": "…"}`.
async fn mint_bearer(
    client: &reqwest::Client,
    challenge: &str,
    scope: &str,
    auth: Option<&RegistryAuth>,
) -> Option<String> {
    let bearer = challenge.strip_prefix("Bearer ")?;
    // realm="…",service="…" — find `key="`, take up to the next quote.
    let field = |key: &str| -> Option<String> {
        let marker = format!("{key}=\"");
        let at = bearer.find(&marker)? + marker.len();
        let rest = &bearer[at..];
        let end = rest.find('"')?;
        Some(rest[..end].to_owned())
    };
    let realm = field("realm")?;
    let service = field("service").unwrap_or_default();
    let mut req = client.get(&realm).query(&[("scope", scope)]);
    if !service.is_empty() {
        req = req.query(&[("service", &service)]);
    }
    if let Some(auth) = auth {
        match auth {
            RegistryAuth::Basic(_) => {
                req = req.header("Authorization", auth.header());
            }
            RegistryAuth::Bearer(token) => {
                req = req.header("Authorization", format!("Bearer {token}"));
            }
        }
    }
    let value: serde_json::Value = req
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    value
        .get("token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// One extracted tree: the files (rel path -> bytes, the `assets/`
/// root stripped) and the AssetSpec the row carries (hashes feed the
/// ETag, header_rules the `_headers` rules).
#[derive(Debug, Clone)]
pub struct Tree {
    pub image: String,
    pub files: BTreeMap<String, Arc<Vec<u8>>>,
    pub spec: gateway_core::assets::AssetSpec,
}

/// Per-file cap: an asset bigger than this refuses the tree (the
/// node's own serving bodies ride the same 16 MiB discipline).
const MAX_ASSET_BYTES: usize = 16 * 1024 * 1024;

/// The whole store's cap (all apps): a fleet of fat static sites
/// bounces further pulls at the door.
const MAX_STORE_BYTES: usize = 256 * 1024 * 1024;

/// The store. Mutex'd BTreeMap — pulls are rare (per image ref), reads
/// are the hot path and take the same lock (a read is a map lookup +
/// an Arc clone).
#[derive(Default)]
pub struct AssetStore {
    trees: std::sync::Mutex<BTreeMap<(String, String), Tree>>,
    tokens: BTreeMap<String, RegistryAuth>,
}

impl AssetStore {
    /// `tokens`: registry host -> credential (the `[registry.<host>]`
    /// map + the env ladder, Bearer as always); a host absent from the
    /// map pulls unauthenticated — loopback, or through the namespace
    /// Secret the caller resolves per pull (the namespace rules).
    pub fn new(tokens: BTreeMap<String, RegistryAuth>) -> Self {
        Self {
            trees: std::sync::Mutex::new(BTreeMap::new()),
            tokens,
        }
    }

    /// The serving face: GET only, a tree-backed hit answers through
    /// the asset law (304s ride `If-None-Match`), a miss is `None` —
    /// the caller forwards (the worker may own the path, and
    /// `run_worker_first` apps never answer from the store at all).
    pub async fn serve(
        &self,
        resolved: &crate::table::Resolved,
        method: &str,
        path: &str,
        query: &str,
        req_headers: &BTreeMap<String, String>,
        secret_lookup: &(dyn Fn(&str, &str) -> Option<crate::table::RegistryAuth> + Send + Sync),
    ) -> Option<http::Response<Vec<u8>>> {
        if method != "GET" {
            return None;
        }
        // run_worker_first apps never answer from the store (the row's
        // own law); no spec = no store for the app.
        let spec = resolved.assets.as_ref()?;
        if spec.run_worker_first {
            return None;
        }
        let (org, app) = (&resolved.org, &resolved.app);
        if spec.run_worker_first {
            return None;
        }
        let image = resolved.image.as_ref()?;
        {
            let trees = self.trees.lock().unwrap();
            if let Some(tree) = trees.get(&(org.clone(), app.clone()))
                && &tree.image == image
            {
                return self.answer(tree, path, query, req_headers);
            }
        }
        // Pull (outside the lock — the next reader either waits for the
        // fresh tree or serves the old one; a pull failure leaves the
        // old tree standing).
        let image = image.clone();
        match self.pull(&image, spec, org, secret_lookup).await {
            Ok(tree) => {
                let answer = self.answer(&tree, path, query, req_headers);
                self.trees
                    .lock()
                    .unwrap()
                    .insert((org.clone(), app.clone()), tree);
                answer
            }
            Err(e) => {
                eprintln!("[gateway] asset pull {org}/{app} {image}: {e}");
                // The old tree (if any) still serves; a miss falls
                // through to the node.
                let trees = self.trees.lock().unwrap();
                trees
                    .get(&(org.clone(), app.clone()))
                    .and_then(|tree| self.answer(tree, path, query, req_headers))
            }
        }
    }

    fn answer(
        &self,
        tree: &Tree,
        path: &str,
        query: &str,
        req_headers: &BTreeMap<String, String>,
    ) -> Option<http::Response<Vec<u8>>> {
        let files: BTreeMap<String, u64> = tree
            .files
            .iter()
            .map(|(k, v)| (k.clone(), v.len() as u64))
            .collect();
        let rel = gateway_core::assets::resolve_asset(&files, path)?;
        let bytes = tree.files.get(&rel)?;
        // `query` never reaches the store — the tree is
        // content-addressed by path.
        let _ = query;
        Some(gateway_core::assets::asset_response(
            &tree.spec.hashes,
            &tree.spec.header_rules,
            &rel,
            200,
            bytes.as_ref().clone(),
            req_headers,
        ))
    }

    /// Pull the artifact and extract the asset tree: the manifest (or
    /// its index descent), every tar layer and every unit-wrapper
    /// payload untars into the tree; digests verify before use.
    async fn pull(
        &self,
        image: &str,
        spec: &gateway_core::assets::AssetSpec,
        org: &str,
        secret_lookup: &(dyn Fn(&str, &str) -> Option<crate::table::RegistryAuth> + Send + Sync),
    ) -> Result<Tree, String> {
        let reference = Reference::parse(image).map_err(|e| format!("reference: {e}"))?;
        let scheme = scheme_for_registry(&reference.registry);
        let _base = format!("{scheme}://{}", reference.registry);
        // THE NAMESPACE RULES: the app's own namespace's
        // dockerconfigjson Secret answers first (per-tenant, applied
        // to the server, live through the watch); the boot ladder
        // (config map, env) is the fallback; no credential anywhere
        // pulls unauthenticated (loopback registries).
        let auth = secret_lookup(org, &reference.registry)
            .or_else(|| self.tokens.get(&reference.registry).cloned());
        let client = reqwest::Client::new();
        // One Bearer challenge exchange per (registry, scope), cached for
        // this pull. GHCR (and every spec-compliant registry) answers an
        // anonymous manifest GET with 401 + WWW-Authenticate Bearer; the
        // scoped token is minted from that challenge with the namespace's
        // dockerconfigjson credential — the same mechanism wisolate's OCI
        // client uses, not a proactively-sent Basic header.
        let bearer: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let get = |url: String, accept: &str, cap: u64| {
            let client = client.clone();
            let auth = auth.clone();
            let bearer = bearer.clone();
            let scope = format!("repository:{}:pull", reference.repository);
            let accept = accept.to_owned();
            async move {
                let mut req = client.get(&url).header("Accept", accept.clone());
                if let Some(token) = bearer.lock().unwrap().get(&scope).cloned() {
                    req = req.header("Authorization", format!("Bearer {token}"));
                }
                let mut resp = req
                    .timeout(std::time::Duration::from_secs(30))
                    .send()
                    .await
                    .map_err(|e| format!("GET {url}: {e}"))?;
                if resp.status() == 401 {
                    // Parse the Bearer challenge and mint a scoped token.
                    let challenge = resp
                        .headers()
                        .get(reqwest::header::WWW_AUTHENTICATE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_owned();
                    if let Some(token) =
                        mint_bearer(&client, &challenge, &scope, auth.as_ref()).await
                    {
                        bearer.lock().unwrap().insert(scope.clone(), token.clone());
                        resp = client
                            .get(&url)
                            .header("Accept", accept)
                            .header("Authorization", format!("Bearer {token}"))
                            .timeout(std::time::Duration::from_secs(30))
                            .send()
                            .await
                            .map_err(|e| format!("GET {url}: {e}"))?;
                    }
                }
                let resp = resp
                    .error_for_status()
                    .map_err(|e| format!("GET {url}: {e}"))?;
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| format!("read {url}: {e}"))?
                    .to_vec();
                if bytes.len() as u64 > cap {
                    return Err(format!("GET {url}: {} bytes over the cap", bytes.len()));
                }
                Ok(bytes)
            }
        };

        let mut manifest_bytes = get(reference.manifest_url(), ACCEPT, MAX_MANIFEST_BYTES).await?;
        if is_index(&manifest_bytes) {
            // The index descent law (the oci module): pick the linux/amd64
            // entry, fetch ITS manifest, pin the digest.
            let index: oci_spec::image::ImageIndex =
                serde_json::from_slice(&manifest_bytes).map_err(|e| format!("index: {e}"))?;
            let entry =
                crate::oci::index_entry(&index).map_err(|e| format!("index descent: {e}"))?;
            let digest = entry.digest().to_string();
            manifest_bytes = get(reference.blob_url(&digest), ACCEPT, MAX_MANIFEST_BYTES).await?;
            verify_digest(&digest, &manifest_bytes)
                .map_err(|e| format!("manifest {digest}: {e}"))?;
        }
        let manifest: oci_spec::image::ImageManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| format!("manifest: {e}"))?;

        let mut files: BTreeMap<String, Arc<Vec<u8>>> = BTreeMap::new();
        let mut total = 0usize;
        for layer in manifest.layers() {
            let media = layer.media_type().to_string();
            let digest = layer.digest().to_string();
            let bytes = get(reference.blob_url(&digest), "*/*", MAX_ASSET_BYTES as u64).await?;
            verify_digest(&digest, &bytes).map_err(|e| format!("layer {digest}: {e}"))?;
            // The tar half: a gzip-tar layer OR the unit wrapper's
            // section payload (the qreta build shape — the wasm is the
            // carrier, the tree rides its custom section).
            let tar_bytes: Option<Vec<u8>> = if media.contains("tar") {
                Some(if bytes.starts_with(&[0x1f, 0x8b]) {
                    gunzip(&bytes)?
                } else {
                    bytes
                })
            } else if media.contains("wasm") {
                match unit_wrapper_payload(&bytes).map_err(|e| format!("wrapper {digest}: {e}"))? {
                    Some(tar_gz) => Some(gunzip(&tar_gz)?),
                    None => None, // the app.wasm layer — not the asset store's business
                }
            } else {
                None
            };
            let Some(tar_bytes) = tar_bytes else {
                continue;
            };
            let mut archive = tar::Archive::new(tar_bytes.as_slice());
            for entry in archive.entries().map_err(|e| format!("tar: {e}"))? {
                let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                let path: String = entry
                    .path()
                    .map_err(|e| format!("tar path: {e}"))?
                    .to_string_lossy()
                    .into_owned();
                // Both roots strip: the node's version tree uses
                // `assets/`, a typed PublicAssets source uses `public/`.
                // Either way the tree addresses files rel to that root.
                let rel = path
                    .strip_prefix("assets/")
                    .or_else(|| path.strip_prefix("public/"))
                    .unwrap_or(&path)
                    .to_owned();
                if rel.is_empty() {
                    continue;
                }
                // The layer blob was capped at fetch, so every file
                // inside is bounded by it; the length check re-asserts
                // the per-file cap after the read.
                let mut body = Vec::new();
                use std::io::Read as _;
                entry
                    .read_to_end(&mut body)
                    .map_err(|e| format!("tar read {rel}: {e}"))?;
                if body.len() > MAX_ASSET_BYTES {
                    return Err(format!("asset {rel} over the cap"));
                }
                total += body.len();
                if total > MAX_STORE_BYTES {
                    return Err("the asset store is over its cap".to_owned());
                }
                files.insert(rel, Arc::new(body));
            }
        }
        if files.is_empty() {
            return Err("the artifact carries no asset tree".to_owned());
        }
        Ok(Tree {
            image: image.to_owned(),
            files,
            spec: spec.clone(),
        })
    }
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .read_to_end(&mut out)
        .map_err(|e| format!("gunzip: {e}"))?;
    Ok(out)
}
