//! Messages between our edges over QUIC (ADR-0023). One request and one
//! response per stream, JSON-encoded inside length-prefixed frames.

use serde::{Deserialize, Serialize};

use crate::{keys::CorePublic, Decision, SignedHead, ToolCall};

/// What the owner can configure from the app (ADR-0024). Signed by the owner
/// over `configure_message(&config)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConfig {
    pub name: String,
    pub firewall: FirewallConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirewallConfig {
    DryRun,
    Mikrotik {
        url: String,
        user: String,
        password: String,
        cert_sha256: Option<String>,
        list: Option<String>,
    },
    Openwrt {
        url: String,
        user: String,
        password: String,
        cert_sha256: Option<String>,
    },
}

impl FirewallConfig {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DryRun => "dry-run",
            Self::Mikrotik { .. } => "mikrotik",
            Self::Openwrt { .. } => "openwrt",
        }
    }
}

/// The configuration without secrets, as the Core reports it back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub name: String,
    pub firewall: String,
}

pub const CONFIGURE_DOMAIN: &[u8] = b"guardian.configure.v1";

/// Bytes the owner signs to configure the Core. Struct field order is fixed,
/// so both sides produce the same JSON.
pub fn configure_message(config: &CoreConfig) -> Vec<u8> {
    let mut message = CONFIGURE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_json::to_vec(config).unwrap_or_default());
    message
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Who are you and in what state. Open to anyone.
    Hello,
    /// The one-time pairing offer, while unpaired. Open to anyone.
    PairOffer,
    /// Pair. The witness identity is taken from the TLS handshake.
    Pair {
        owner_public: String,
        epoch_public: String,
        signature: String,
    },
    /// Paired witness only, with the owner's signature.
    Configure {
        config: CoreConfig,
        signature: String,
    },
    /// Paired witness only.
    Status,
    Heads {
        since: Option<u64>,
    },
    Events {
        since: Option<u64>,
    },
    /// From a host daemon.
    Decide {
        call: ToolCall,
    },
    /// From a host daemon right after it connects: how to show it in the app.
    HostHello {
        hostname: String,
        os: String,
    },
    /// Paired witness only: the hosts the Core knows.
    Hosts,
    /// Paired witness only: ask one host (by identity, hex) to show itself.
    Identify {
        host: String,
    },
    /// From the Core to a host daemon: show an identification notice on
    /// this machine's screen (like HiveOS's identify for rigs in a room).
    IdentifySelf {
        core_name: String,
        fingerprint: String,
    },
}

/// A host as the Core reports it to the witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    /// Ed25519 identity of the host daemon, hex.
    pub id: String,
    /// Short hash of the identity, shown on both screens to match a machine.
    pub fingerprint: String,
    pub address: String,
    pub hostname: String,
    pub os: String,
    pub connected: bool,
    pub last_seen_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Hello {
        core_public: CorePublic,
        paired: bool,
        config: Option<ConfigSummary>,
    },
    Offer {
        core_public: CorePublic,
        nonce: String,
    },
    Paired {
        confirmation_code: String,
    },
    Configured {
        config: ConfigSummary,
    },
    Status {
        status: serde_json::Value,
    },
    Heads {
        heads: Vec<SignedHead>,
    },
    Events {
        events: Vec<serde_json::Value>,
    },
    Decision {
        decision: Decision,
    },
    Hosts {
        hosts: Vec<HostInfo>,
    },
    Ack,
    Error {
        message: String,
    },
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_tagged() {
        let json = serde_json::to_string(&Request::Heads { since: Some(3) }).unwrap();
        assert_eq!(json, r#"{"op":"heads","since":3}"#);
    }

    #[test]
    fn configure_message_is_stable_and_binds_the_config() {
        let a = CoreConfig {
            name: "lab".into(),
            firewall: FirewallConfig::DryRun,
        };
        let mut b = a.clone();
        assert_eq!(configure_message(&a), configure_message(&b));
        b.name = "other".into();
        assert_ne!(configure_message(&a), configure_message(&b));
    }
}
