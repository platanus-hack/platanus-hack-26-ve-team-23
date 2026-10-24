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

pub const ENROLL_DOMAIN: &[u8] = b"guardian.enroll.v1";

/// Bytes the owner signs to enrol a host daemon (ADR-0021): the host identity
/// and a timestamp, so an approval cannot be replayed or aimed at another
/// host.
pub fn enroll_message(host_id: &str, timestamp_ms: u64) -> Vec<u8> {
    let mut message = ENROLL_DOMAIN.to_vec();
    message.extend_from_slice(host_id.as_bytes());
    message.extend_from_slice(&timestamp_ms.to_be_bytes());
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
    /// Paired witness only, with the owner's signature over
    /// `enroll_message(host_id, timestamp_ms)` (ADR-0021). `host` is the hex
    /// identity of the host daemon to enrol.
    ApproveHost {
        host: String,
        timestamp_ms: u64,
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
    /// From a host daemon right after it connects: how to show it in the app.
    HostHello {
        hostname: String,
        os: String,
        /// The boot measurement (PCR digest), hex, or none without a TPM.
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
    /// Whether the owner has enrolled this host (ADR-0021). Unenrolled hosts
    /// are shown as pending and their decisions are denied.
    pub approved: bool,
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
        };
        let mut b = a.clone();
        assert_eq!(configure_message(&a), configure_message(&b));
        b.name = "other".into();
        assert_ne!(configure_message(&a), configure_message(&b));
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
}
