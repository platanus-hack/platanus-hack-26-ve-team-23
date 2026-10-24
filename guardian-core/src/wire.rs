//! Messages between our edges over QUIC (ADR-0023). One request and one
//! response per stream, JSON-encoded inside length-prefixed frames.

use serde::{Deserialize, Serialize};

use crate::{
    keys::CorePublic,
    machine::{Mac, Nic},
    Decision, Severity, SignedHead, ToolCall,
};

/// The Core's configuration (ADR-0024, ADR-0027). Each configuration is one
/// link of a chain: it names its `version` (the previous one plus one) and
/// the hash of the previous configuration, and the signature covers both, so
/// an old configuration can never be replayed and history cannot fork.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConfig {
    pub name: String,
    pub firewall: FirewallConfig,
    /// 1 for the first configuration, previous + 1 for every change.
    #[serde(default)]
    pub version: u64,
    /// `config_hash` (hex) of the previous configuration; empty for version 1.
    #[serde(default)]
    pub prev: String,
    /// Enterprise edition (ADR-0027): P-256 public key (SEC1, hex) allowed to
    /// sign configurations the Core fetches remotely. Only the owner can set,
    /// change or remove it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_signer: Option<String>,
    /// The owner's attention thresholds (ADR-0033). Left out of the JSON
    /// while they are the defaults, so configurations signed before they
    /// existed keep their hash and signature.
    #[serde(default, skip_serializing_if = "Thresholds::is_default")]
    pub thresholds: Thresholds,
}

/// From which severity HAWK asks the owner and from which it denies
/// (ADR-0033). A critical finding always denies and quarantines, whatever
/// these say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    pub ask_from: Severity,
    pub deny_from: Severity,
}

impl Default for Thresholds {
    /// The table of ADR-0022: medium asks, high denies.
    fn default() -> Self {
        Self {
            ask_from: Severity::Medium,
            deny_from: Severity::High,
        }
    }
}

impl Thresholds {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The floors: a high finding at least asks, and asking starts at or
    /// below denying.
    pub fn is_valid(&self) -> bool {
        self.ask_from <= Severity::High && self.ask_from <= self.deny_from
    }
}

impl CoreConfig {
    /// Whether any router secret travels in this configuration. Remote
    /// (enterprise) configurations must not carry secrets in clear text.
    pub fn has_secrets(&self) -> bool {
        match &self.firewall {
            FirewallConfig::DryRun => false,
            FirewallConfig::Mikrotik { password, .. }
            | FirewallConfig::Openwrt { password, .. } => !password.is_empty(),
        }
    }
}

/// A configuration with its signature, as an enterprise pipeline publishes it
/// for the Core to fetch (ADR-0027).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedConfig {
    pub config: CoreConfig,
    /// ECDSA P-256 (DER, hex) over `configure_message(&config)`.
    pub signature: String,
}

pub const CONFIG_HASH_DOMAIN: &[u8] = b"guardian.config.v1";

/// Hash that links one configuration to the next (hex in `CoreConfig.prev`).
pub fn config_hash(config: &CoreConfig) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    Sha256::new()
        .chain_update(CONFIG_HASH_DOMAIN)
        .chain_update(serde_json::to_vec(config).unwrap_or_default())
        .finalize()
        .into()
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
    /// Position of the active configuration in the chain.
    #[serde(default)]
    pub version: u64,
    /// `config_hash` (hex) of the active configuration: the next one must name
    /// it as `prev`.
    #[serde(default)]
    pub hash: String,
    /// Whether remote (enterprise) configuration is authorised.
    #[serde(default)]
    pub enterprise: bool,
    /// The authorised enterprise signer (public key, hex), so the owner's app
    /// can keep it when it writes the next configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_signer: Option<String>,
    /// The active attention thresholds (ADR-0033), so the app can show them
    /// and keep them when it writes the next configuration.
    #[serde(default)]
    pub thresholds: Thresholds,
}

pub const CONFIGURE_DOMAIN: &[u8] = b"guardian.configure.v1";

/// Bytes the owner signs to configure the Core. Struct field order is fixed,
/// so both sides produce the same JSON.
pub fn configure_message(config: &CoreConfig) -> Vec<u8> {
    let mut message = CONFIGURE_DOMAIN.to_vec();
    message.extend_from_slice(&serde_json::to_vec(config).unwrap_or_default());
    message
}

pub const RELEASE_DOMAIN: &[u8] = b"guardian.release.v1";

/// Bytes the owner signs to release a host from quarantine: the host address
/// and a timestamp, so a release cannot be replayed or aimed at another host.
pub fn release_message(host: &str, timestamp_ms: u64) -> Vec<u8> {
    let mut message = RELEASE_DOMAIN.to_vec();
    message.extend_from_slice(host.as_bytes());
    message.extend_from_slice(&timestamp_ms.to_be_bytes());
    message
}

pub const OPEN_RECORD_DOMAIN: &[u8] = b"guardian.open-record.v1";

/// Bytes the owner signs to open a range of the sealed record (ADR-0007):
/// the range and a timestamp, so an opening cannot be replayed or widened.
pub fn open_record_message(from_seq: u64, to_seq: u64, timestamp_ms: u64) -> Vec<u8> {
    let mut message = OPEN_RECORD_DOMAIN.to_vec();
    message.extend_from_slice(&from_seq.to_be_bytes());
    message.extend_from_slice(&to_seq.to_be_bytes());
    message.extend_from_slice(&timestamp_ms.to_be_bytes());
    message
}

pub const ANSWER_DOMAIN: &[u8] = b"guardian.answer.v1";

/// Bytes the owner signs to answer an `ask`: the ask id and the decision.
/// The id is one-time and unpredictable, so a timestamp is unnecessary.
pub fn answer_message(id: &str, allow: bool) -> Vec<u8> {
    let mut message = ANSWER_DOMAIN.to_vec();
    message.extend_from_slice(id.as_bytes());
    message.push(u8::from(allow));
    message
}

pub const HEARTBEAT_DOMAIN: &[u8] = b"guardian.heartbeat.v1";

/// Bytes the daemon signs in a heartbeat (ADR-0021): the Core's nonce, a
/// monotonic counter, the digest of the calls the daemon observed since the
/// previous heartbeat, and its boot measurement (zeroes when there is no
/// TPM).
pub fn heartbeat_message(
    nonce: &[u8],
    counter: u64,
    digest: &[u8; 32],
    boot: &[u8; 32],
) -> Vec<u8> {
    let mut message = HEARTBEAT_DOMAIN.to_vec();
    message.extend_from_slice(nonce);
    message.extend_from_slice(&counter.to_be_bytes());
    message.extend_from_slice(digest);
    message.extend_from_slice(boot);
    message
}

/// An `ask` waiting for the owner (ADR-0022), as the Core lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAsk {
    pub id: String,
    pub session: String,
    pub tool: String,
    pub reason: String,
    pub host: String,
    pub created_at_ms: u64,
}

/// One event of the record as delivered to the witness: the chain metadata
/// and the sealed payload, still encrypted (ADR-0006). The witness decrypts
/// with its epoch key, never the Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEvent {
    pub seq: u64,
    pub timestamp_ms: u64,
    /// The `EventKind` discriminant (see `guardian_core::event::EventKind`).
    pub kind: u8,
    /// Hex of the sealed payload.
    pub payload: String,
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
    /// Paired witness only, with the owner's signature over
    /// `release_message(host, timestamp_ms)`, no more than 60 s old
    /// (ADR-0018). `host` is the address that was quarantined.
    Release {
        host: String,
        timestamp_ms: u64,
        signature: String,
    },
    /// Paired witness only, with the owner's signature over
    /// `open_record_message(from_seq, to_seq, timestamp_ms)` (ADR-0007).
    OpenRecord {
        from_seq: u64,
        to_seq: u64,
        timestamp_ms: u64,
        signature: String,
    },
    /// Paired witness only: the `ask`s waiting for the owner (ADR-0022).
    PendingAsks,
    /// Paired witness only, with the owner's signature over
    /// `answer_message(id, allow)` (ADR-0022).
    Answer {
        id: String,
        allow: bool,
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
    /// From a host daemon: a copy of one proxy request/response, recorded and
    /// cross-checked against the hook's decisions (ADR-0004).
    ProxyRecord {
        record: ProxyRecord,
    },
    /// From a host daemon right after it connects: how to show it in the
    /// app, and the identifiers that link it over time (ADR-0028). All of it
    /// is declared, so labels and links only.
    HostHello {
        hostname: String,
        os: String,
        /// `machine::hwid` for this Core; empty when unknown.
        #[serde(default)]
        hwid: String,
        #[serde(default)]
        nics: Vec<Nic>,
        /// The boot measurement (PCR digest), hex, or none without a TPM
        /// (ADR-0021).
        #[serde(default)]
        boot_digest: Option<String>,
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
    /// From the Core to a host daemon: answer this challenge with a signed
    /// heartbeat (ADR-0021).
    HeartbeatChallenge {
        nonce: String,
    },
    /// Paired witness only: the owner approves a host, bound to its daemon
    /// identity and HWID (ADR-0021, ADR-0029).
    ApproveHost {
        approval: HostApproval,
    },
    /// From the Core to an approved host daemon: the owner's approval and
    /// key, so the daemon pins this Core and this owner (ADR-0029).
    Enrolled {
        approval: HostApproval,
        owner_public: String,
    },
}

pub const APPROVE_DOMAIN: &[u8] = b"guardian.approve-host.v1";

/// The owner's approval of one host for one Core (ADR-0029). The signature
/// covers the Core, the host's daemon identity, its HWID and the time, so it
/// is worthless for another Core, another key, or a copy of the key on
/// another machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostApproval {
    /// Ed25519 transport identity of the Core, hex.
    pub core: String,
    /// Ed25519 identity of the host daemon, hex.
    pub host: String,
    /// The host's HWID for this Core; empty if it reported none.
    pub hwid: String,
    pub timestamp_ms: u64,
    /// ECDSA P-256 by the owner (DER, hex) over `approve_message`.
    pub signature: String,
}

/// Bytes the owner signs to approve a host.
pub fn approve_message(core: &[u8; 32], host: &[u8; 32], hwid: &str, timestamp_ms: u64) -> Vec<u8> {
    let mut message = APPROVE_DOMAIN.to_vec();
    message.extend_from_slice(core);
    message.extend_from_slice(host);
    message.extend_from_slice(&(hwid.len() as u64).to_be_bytes());
    message.extend_from_slice(hwid.as_bytes());
    message.extend_from_slice(&timestamp_ms.to_be_bytes());
    message
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
    /// Declared by the daemon, bound to its identity (ADR-0028).
    #[serde(default)]
    pub hwid: String,
    /// Observed by the Core in its neighbour table; none behind a router.
    #[serde(default)]
    pub mac: Option<Mac>,
    /// Declared by the daemon.
    #[serde(default)]
    pub nics: Vec<Nic>,
    /// Contained at the firewall, by identity, HWID or MAC.
    #[serde(default)]
    pub contained: bool,
    /// Approved by the owner with the HWID it reports (ADR-0021, ADR-0029).
    /// Unapproved hosts are shown as pending and their calls are denied.
    #[serde(default)]
    pub approved: bool,
    /// Why the Core does not trust this host's identifiers, if it does not:
    /// another identity reported the same HWID, or this identity reported a
    /// different one than it was approved with.
    #[serde(default)]
    pub conflict: Option<String>,
}

/// A tool call the model proposed, extracted by the proxy from a chat
/// response (ADR-0004). The `id` is the model's tool-call id, the same value
/// the agent hook sends as `ToolCall.call_id`, so the Core can match the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

/// One proxy exchange the host daemon relays to the Core for the sealed
/// record and the hook-proxy cross-check (ADR-0004). The request and response
/// are recorded as-is; `tool_calls` drive the cross-check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxyRecord {
    pub timestamp_ms: u64,
    /// The upstream path, for example `/v1/chat/completions`.
    pub path: String,
    /// The request body sent upstream (the prompt and tool definitions).
    pub request: serde_json::Value,
    /// The response body, if one arrived: the parsed JSON for non-streaming,
    /// or the raw server-sent-events text for a streaming answer.
    pub response: Option<serde_json::Value>,
    /// The tool calls the model proposed in the response, with their ids.
    pub tool_calls: Vec<ProposedToolCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Response {
    Hello {
        /// The head keys, once the owner's app activated the Core
        /// (ADR-0030); none while it is dormant.
        core_public: Option<CorePublic>,
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
    /// The sealed events of the requested range (ADR-0007).
    Record {
        events: Vec<RecordEvent>,
    },
    /// The `ask`s waiting for the owner (ADR-0022).
    Asks {
        asks: Vec<PendingAsk>,
    },
    Decision {
        decision: Decision,
    },
    /// A host daemon's answer to a heartbeat challenge (ADR-0021).
    Heartbeat {
        nonce: String,
        counter: u64,
        digest: String,
        signature: String,
        /// The boot measurement (PCR digest), hex, or none without a TPM.
        boot: Option<String>,
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
            version: 1,
            prev: String::new(),
            enterprise_signer: None,
            thresholds: Thresholds::default(),
        };
        let mut b = a.clone();
        assert_eq!(configure_message(&a), configure_message(&b));
        b.name = "other".into();
        assert_ne!(configure_message(&a), configure_message(&b));
    }

    #[test]
    fn default_thresholds_keep_the_signed_bytes_of_older_configurations() {
        let config = CoreConfig {
            name: "lab".into(),
            firewall: FirewallConfig::DryRun,
            version: 1,
            prev: String::new(),
            enterprise_signer: None,
            thresholds: Thresholds::default(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("thresholds"));
        // A configuration written before thresholds existed reads as default.
        let old: CoreConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(old.thresholds, Thresholds::default());

        let mut strict = config.clone();
        strict.thresholds = Thresholds {
            ask_from: Severity::Low,
            deny_from: Severity::Medium,
        };
        assert!(serde_json::to_string(&strict)
            .unwrap()
            .contains("\"ask_from\":\"low\""));
        assert_ne!(configure_message(&config), configure_message(&strict));
        assert_ne!(config_hash(&config), config_hash(&strict));
    }

    #[test]
    fn thresholds_keep_their_floors() {
        let t = |ask_from, deny_from| Thresholds {
            ask_from,
            deny_from,
        };
        assert!(Thresholds::default().is_valid());
        assert!(t(Severity::Low, Severity::Medium).is_valid());
        assert!(t(Severity::High, Severity::Critical).is_valid());
        // A high finding must at least ask.
        assert!(!t(Severity::Critical, Severity::Critical).is_valid());
        // Asking cannot start above denying.
        assert!(!t(Severity::High, Severity::Medium).is_valid());
    }

    #[test]
    fn release_and_open_messages_bind_their_fields() {
        let base = release_message("10.0.0.7", 5);
        assert_eq!(base, release_message("10.0.0.7", 5));
        assert_ne!(base, release_message("10.0.0.8", 5));
        assert_ne!(base, release_message("10.0.0.7", 6));

        let open = open_record_message(1, 5, 100);
        assert_eq!(open, open_record_message(1, 5, 100));
        assert_ne!(open, open_record_message(1, 6, 100));
        assert_ne!(open, open_record_message(1, 5, 101));
    }

    #[test]
    fn the_hash_binds_version_and_previous_link() {
        let first = CoreConfig {
            name: "lab".into(),
            firewall: FirewallConfig::DryRun,
            version: 1,
            prev: String::new(),
            enterprise_signer: None,
            thresholds: Thresholds::default(),
        };
        let mut second = first.clone();
        second.version = 2;
        second.prev = hex::encode(config_hash(&first));
        assert_ne!(config_hash(&first), config_hash(&second));
        assert_ne!(configure_message(&first), configure_message(&second));
    }

    #[test]
    fn the_approval_binds_core_host_hwid_and_time() {
        let base = approve_message(&[1; 32], &[2; 32], "ab", 10);
        assert_ne!(base, approve_message(&[3; 32], &[2; 32], "ab", 10));
        assert_ne!(base, approve_message(&[1; 32], &[3; 32], "ab", 10));
        assert_ne!(base, approve_message(&[1; 32], &[2; 32], "ac", 10));
        assert_ne!(base, approve_message(&[1; 32], &[2; 32], "ab", 11));
        // The length prefix keeps the HWID and the time from sliding.
        assert_ne!(
            approve_message(&[1; 32], &[2; 32], "", 10),
            approve_message(&[1; 32], &[2; 32], "0", 10)
        );
    }

    #[test]
    fn an_old_host_hello_without_identifiers_still_parses() {
        let old: Request =
            serde_json::from_str(r#"{"op":"host_hello","hostname":"rig","os":"linux"}"#).unwrap();
        match old {
            Request::HostHello {
                hwid,
                nics,
                boot_digest,
                ..
            } => {
                assert!(hwid.is_empty());
                assert!(nics.is_empty());
                assert!(boot_digest.is_none());
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn older_configurations_without_chain_fields_still_parse() {
        let old: CoreConfig =
            serde_json::from_str(r#"{"name":"lab","firewall":{"kind":"dry_run"}}"#).unwrap();
        assert_eq!(old.version, 0);
        assert!(old.prev.is_empty());
        assert!(!old.has_secrets());
    }
}
