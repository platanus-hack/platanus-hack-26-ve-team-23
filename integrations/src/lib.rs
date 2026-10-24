//! Integrations with the systems an organisation already runs (ADR-0018,
//! ADR-0020):
//!
//! - `Firewall`: quarantine and release a host on the network equipment, so
//!   containment holds even against a host the agent fully controls.
//! - `EventSink`: publish event metadata to Kafka or a webhook. Sinks never
//!   block decisions and never receive the sealed content of the record.

#![forbid(unsafe_code)]

use std::{fmt, future::Future, net::IpAddr, pin::Pin};

use serde::Serialize;

pub mod client;
pub mod dry_run;
#[cfg(feature = "kafka")]
pub mod kafka;
#[cfg(feature = "mikrotik")]
pub mod mikrotik;
#[cfg(feature = "openwrt")]
pub mod openwrt;
pub mod sinks;
pub mod tls;
#[cfg(feature = "webhook")]
pub mod webhook;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallError {
    /// The router could not be reached or did not answer in time.
    Unreachable(String),
    /// The router answered with an error.
    Rejected(String),
    /// Configuration is missing or invalid.
    Config(String),
}

impl fmt::Display for FirewallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(why) => write!(f, "firewall unreachable: {why}"),
            Self::Rejected(why) => write!(f, "firewall rejected the change: {why}"),
            Self::Config(why) => write!(f, "firewall configuration: {why}"),
        }
    }
}

impl std::error::Error for FirewallError {}

/// Network containment of a host (ADR-0018). Implementations must be
/// idempotent: quarantining a quarantined host, or releasing a free one,
/// succeeds.
pub trait Firewall: fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn quarantine<'a>(
        &'a self,
        host: IpAddr,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>>;
    fn release(&self, host: IpAddr) -> BoxFuture<'_, Result<(), FirewallError>>;
}

/// Metadata published to sinks. Never the sealed content (ADR-0020).
#[derive(Debug, Clone, Serialize)]
pub struct SinkEvent {
    /// `decisions`, `alerts`, `containment` or `heads`.
    pub family: &'static str,
    pub seq: u64,
    pub timestamp_ms: u64,
    /// Key for partitioning, usually the host.
    pub key: String,
    pub body: serde_json::Value,
}

pub trait EventSink: fmt::Debug + Send + Sync {
    fn name(&self) -> &'static str;
    fn publish<'a>(&'a self, events: &'a [SinkEvent]) -> BoxFuture<'a, Result<(), String>>;
}

/// Builds the firewall named in `GUARDIAN_FIREWALL` (`dry-run` by default).
/// Configuration errors fall back to dry run with an error in the log, so a
/// mistyped variable never stops the Core from deciding.
pub fn firewall_from_env() -> Box<dyn Firewall> {
    let kind = std::env::var("GUARDIAN_FIREWALL").unwrap_or_else(|_| "dry-run".into());
    let built: Result<Box<dyn Firewall>, FirewallError> = match kind.as_str() {
        "dry-run" => Ok(Box::new(dry_run::DryRun::default())),
        #[cfg(feature = "mikrotik")]
        "mikrotik" => mikrotik::MikroTik::from_env().map(|f| Box::new(f) as Box<dyn Firewall>),
        #[cfg(feature = "openwrt")]
        "openwrt" => openwrt::OpenWrt::from_env().map(|f| Box::new(f) as Box<dyn Firewall>),
        other => Err(FirewallError::Config(format!("unknown firewall '{other}'"))),
    };
    built.unwrap_or_else(|err| {
        tracing::error!(%err, "falling back to dry-run firewall");
        Box::new(dry_run::DryRun::default())
    })
}

/// Reads a required environment variable.
pub(crate) fn env(name: &str) -> Result<String, FirewallError> {
    std::env::var(name).map_err(|_| FirewallError::Config(format!("{name} is not set")))
}
