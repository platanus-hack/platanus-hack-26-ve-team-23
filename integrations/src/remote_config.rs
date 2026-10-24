//! Remote configuration for the enterprise edition (ADR-0027).
//!
//! An enterprise pipeline (infrastructure as code) publishes the next signed
//! configuration to S3; the Core reads it and applies it only if it is
//! signed by the enterprise signer the owner authorised and it is exactly the
//! next link of the configuration chain. This module only fetches the bytes;
//! all checks happen in the Core.

use crate::archive::{ArchiveConfig, Store};

/// Largest configuration document accepted.
const MAX_CONFIG: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct RemoteConfigSettings {
    pub s3: ArchiveConfig,
    /// Object key of the latest signed configuration.
    pub key: String,
    pub poll_secs: u64,
}

impl RemoteConfigSettings {
    /// `CONFIG_BUCKET` (or `ARCHIVE_BUCKET`) enables it. Endpoint and region
    /// fall back to the archive's; credentials are separate (`CONFIG_ACCESS_KEY`,
    /// `CONFIG_SECRET_KEY`): read-only on the configuration key, while the
    /// archive's credential can only write.
    pub fn from_env() -> Option<Self> {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        if get("CONFIG_REMOTE").as_deref() != Some("1") {
            return None;
        }
        let bucket = get("CONFIG_BUCKET").or_else(|| get("ARCHIVE_BUCKET"))?;
        Some(Self {
            s3: ArchiveConfig {
                endpoint: get("CONFIG_ENDPOINT")
                    .or_else(|| get("ARCHIVE_ENDPOINT"))
                    .unwrap_or_else(|| "https://s3.amazonaws.com".into()),
                region: get("CONFIG_REGION")
                    .or_else(|| get("ARCHIVE_REGION"))
                    .unwrap_or_else(|| "us-east-1".into()),
                bucket,
                prefix: String::new(),
                access_key: get("CONFIG_ACCESS_KEY").unwrap_or_default(),
                secret_key: get("CONFIG_SECRET_KEY").unwrap_or_default(),
            },
            key: get("CONFIG_KEY").unwrap_or_else(|| "config/latest.json".into()),
            poll_secs: get("CONFIG_POLL_SECS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
        })
    }
}

pub struct RemoteConfig {
    store: Store,
    key: String,
}

impl std::fmt::Debug for RemoteConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteConfig")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl RemoteConfig {
    pub fn new(settings: &RemoteConfigSettings) -> Result<Self, String> {
        Ok(Self {
            store: Store::new(&settings.s3)?,
            key: settings.key.clone(),
        })
    }

    /// The published signed configuration, if any.
    pub async fn fetch(&self) -> Result<Option<Vec<u8>>, String> {
        self.store.get(&self.key, MAX_CONFIG).await
    }
}
