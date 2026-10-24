//! The Core's QUIC surface (ADR-0023). Every request arrives with the
//! authenticated identity of the peer (its Ed25519 key from the TLS
//! handshake) and its socket address.
//!
//! - Anyone may say hello, ask for the pairing offer, and pair.
//! - The record (status, events, heads) and configuration are served only to
//!   the witness identity bound at pairing; configuration also needs the
//!   owner's signature.
//! - Every path out of `decide` that is not an explicit `Allow` from the
//!   detector, recorded in the chain, is a denial (ADR-0003, ADR-0022). An
//!   unpaired Core denies everything (ADR-0017).

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
};

use detect::Detector;
use edge_net::quic::PeerId;
use guardian_core::{
    wire::{
        answer_message, enroll_message, open_record_message, release_message, ConfigSummary,
        CoreConfig, FirewallConfig, PendingAsk, ProxyRecord, RecordEvent, Request, Response,
    },
    Decision, EventKind, Severity, ToolCall,
};
use integrations::{sinks::Publisher, Firewall, SinkEvent};
use rand::RngCore;

use crate::{
    asks::Asks,
    core::{Core, CoreError, EventMeta, PairRequest},
    crosscheck::{CrossCheck, Match},
    heartbeat::Heartbeats,
    hosts::Hosts,
};

/// Called after pairing or configuration, so the network announcement
/// carries the new state (ADR-0024).
pub type Announcer = Arc<dyn Fn(&Core) + Send + Sync>;

#[derive(Clone)]
pub struct AppState {
    core: Arc<Core>,
    firewall: Arc<RwLock<Arc<dyn Firewall>>>,
    publisher: Publisher,
    detector: Arc<Mutex<Detector>>,
    announcer: Announcer,
    hosts: Arc<Hosts>,
    crosscheck: Arc<CrossCheck>,
    asks: Arc<Asks>,
    heartbeats: Arc<Heartbeats>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("core", &self.core)
            .finish_non_exhaustive()
    }
}

/// Builds the firewall adapter a configuration names. Errors fall back to
/// dry run so a bad router setting never stops the Core from deciding.
pub fn firewall_from_config(config: &FirewallConfig) -> Arc<dyn Firewall> {
    let built: Result<Arc<dyn Firewall>, integrations::FirewallError> = match config {
        FirewallConfig::DryRun => Ok(Arc::new(integrations::dry_run::DryRun::default())),
        FirewallConfig::Mikrotik {
            url,
            user,
            password,
            cert_sha256,
            list,
        } => integrations::mikrotik::MikroTik::new(
            url,
            user,
            password,
            cert_sha256
                .as_deref()
                .and_then(integrations::tls::parse_fingerprint),
            list.as_deref().unwrap_or("guardian_quarantine"),
        )
        .map(|f| Arc::new(f) as Arc<dyn Firewall>),
        FirewallConfig::Openwrt {
            url,
            user,
            password,
            cert_sha256,
        } => integrations::openwrt::OpenWrt::new(
            url,
            user,
            password,
            cert_sha256
                .as_deref()
                .and_then(integrations::tls::parse_fingerprint),
        )
        .map(|f| Arc::new(f) as Arc<dyn Firewall>),
    };
    built.unwrap_or_else(|err| {
        tracing::error!(%err, "firewall configuration rejected, using dry run");
        Arc::new(integrations::dry_run::DryRun::default())
    })
}

impl AppState {
    pub fn new(
        core: Core,
        detector: Detector,
        firewall: Arc<dyn Firewall>,
        publisher: Publisher,
        announcer: Announcer,
    ) -> Self {
        Self {
            core: Arc::new(core),
            firewall: Arc::new(RwLock::new(firewall)),
            publisher,
            detector: Arc::new(Mutex::new(detector)),
            announcer,
            hosts: Arc::new(Hosts::default()),
            crosscheck: Arc::new(CrossCheck::default()),
            asks: Arc::new(Asks::default()),
            heartbeats: Arc::new(Heartbeats::default()),
        }
    }

    #[cfg(test)]
    pub fn core(&self) -> &Core {
        &self.core
    }

    /// Every authenticated connection is offered here; the witness is not a
    /// host, so it is not registered.
    pub fn on_connect(&self, peer: PeerId, conn: quinn::Connection) {
        if !self.is_witness(&peer) {
            self.hosts.connected(peer, conn);
        }
    }

    fn firewall(&self) -> Arc<dyn Firewall> {
        match self.firewall.read() {
            Ok(fw) => Arc::clone(&fw),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    fn is_witness(&self, peer: &PeerId) -> bool {
        self.core.witness_id().is_some_and(|id| &id == peer)
    }

    /// Records one proxy exchange (sealed) and registers its proposed tool
    /// calls for the cross-check (ADR-0004).
    fn record_proxy(&self, host: IpAddr, record: ProxyRecord) {
        self.crosscheck
            .proposed(host, crate::core::now_ms(), &record.tool_calls);
        let meta = EventMeta {
            kind: "proxy",
            host: Some(host.to_string()),
            ..EventMeta::empty()
        };
        let content = serde_json::to_value(&record).unwrap_or_default();
        match self
            .core
            .record(EventKind::ProxyRequest, meta, &content, false)
        {
            Ok(meta) => self.publisher.send(SinkEvent {
                family: "proxy",
                seq: meta.seq,
                timestamp_ms: meta.timestamp_ms,
                key: host.to_string(),
                body: serde_json::to_value(&meta).unwrap_or_default(),
            }),
            Err(err) => tracing::warn!(%err, "could not record the proxy event"),
        }
    }

    /// Cross-checks a `decide` against the proposals. A `decide` whose call id
    /// was never proposed raises a high alert (ADR-0004).
    fn note_decide(&self, host: IpAddr, call_id: Option<&str>) {
        if call_id.is_none() {
            return;
        }
        if self.crosscheck.matched(call_id) == Match::Matched {
            return;
        }
        self.alert(
            host,
            Severity::High,
            "the hook decided a tool call the model never proposed",
            serde_json::json!({ "call_id": call_id }),
        );
    }

    /// Records an alert (sealed) and publishes it. Returns the metadata so a
    /// caller can chain containment onto a critical alert.
    fn alert(
        &self,
        host: IpAddr,
        severity: Severity,
        reason: &str,
        content: serde_json::Value,
    ) -> Option<EventMeta> {
        let meta = EventMeta {
            kind: "alert",
            severity: Some(severity),
            reason: Some(reason.to_owned()),
            host: Some(host.to_string()),
            ..EventMeta::empty()
        };
        match self.core.record(EventKind::Alert, meta, &content, true) {
            Ok(meta) => {
                self.publisher.send(SinkEvent {
                    family: "alerts",
                    seq: meta.seq,
                    timestamp_ms: meta.timestamp_ms,
                    key: host.to_string(),
                    body: serde_json::to_value(&meta).unwrap_or_default(),
                });
                Some(meta)
            }
            Err(err) => {
                tracing::warn!(%err, "could not record the alert");
                None
            }
        }
    }

    /// Evicts proposals that were never matched by a hook `decide`: each is a
    /// critical evasion alert and quarantines its host (ADR-0004, ADR-0018).
    pub async fn sweep_expired(&self) {
        let expired = self.crosscheck.expired(crate::core::now_ms());
        for proposal in expired {
            tracing::warn!(host = %proposal.host, tool = %proposal.name, "proposed tool call never reached the hook");
            let trigger = self.alert(
                proposal.host,
                Severity::Critical,
                "the model proposed a tool call that never reached the hook (evasion)",
                serde_json::json!({ "tool_call_id": proposal.id, "tool": proposal.name }),
            );
            if let Some(meta) = trigger {
                contain(self, Some(proposal.host), &meta).await;
            }
        }
    }

    /// Holds a `decide` that the policy asked about, waiting up to 60 s for
    /// the owner's answer (ADR-0022). No answer means deny.
    async fn hold_for_owner(
        &self,
        call: &ToolCall,
        peer: Option<IpAddr>,
        reason: &str,
    ) -> Decision {
        self.hold_for_owner_timeout(call, peer, reason, crate::asks::ASK_TIMEOUT)
            .await
    }

    async fn hold_for_owner_timeout(
        &self,
        call: &ToolCall,
        peer: Option<IpAddr>,
        reason: &str,
        timeout: std::time::Duration,
    ) -> Decision {
        let id = random_id();
        let meta = PendingAsk {
            id: id.clone(),
            session: call.session.clone(),
            tool: call.tool.clone(),
            reason: reason.to_owned(),
            host: peer.map_or_else(|| "unknown".into(), |ip| ip.to_string()),
            created_at_ms: crate::core::now_ms(),
        };
        let mut rx = self.asks.register(meta);
        match tokio::time::timeout(timeout, &mut rx).await {
            Ok(Ok(true)) => Decision::Allow,
            Ok(Ok(false)) => Decision::deny("denied by the owner"),
            _ => {
                self.asks.take(&id);
                Decision::deny("owner did not answer")
            }
        }
    }

    /// One heartbeat round (ADR-0021): challenge every enrolled, connected
    /// host, then quarantine the ones whose last heartbeat is stale.
    pub async fn heartbeat_round(&self) {
        let connections = self.hosts.connections();
        for (peer, conn) in connections {
            if !self.core.is_approved_host(&peer) {
                continue;
            }
            let nonce = random32();
            self.heartbeats.challenge(&peer, nonce);
            let req = Request::HeartbeatChallenge {
                nonce: hex::encode(nonce),
            };
            if let Ok(Response::Heartbeat {
                nonce,
                counter,
                digest,
                signature,
                boot,
            }) = edge_net::quic::request::<_, Response>(
                &conn,
                &req,
                std::time::Duration::from_secs(5),
            )
            .await
            {
                let nonce = hex::decode(&nonce).ok();
                let digest = hex::decode(&digest)
                    .ok()
                    .and_then(|d| <[u8; 32]>::try_from(d).ok());
                let boot = boot
                    .as_deref()
                    .and_then(|b| hex::decode(b).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .unwrap_or([0u8; 32]);
                let valid = nonce.zip(digest).is_some_and(|(nonce, digest)| {
                    self.heartbeats
                        .verify(&peer, &nonce, counter, &digest, &boot, &signature)
                        .is_ok()
                });
                if valid {
                    // The boot measurement must match what the host reported
                    // when it connected (ADR-0021): a changed boot is
                    // quarantined, like silence.
                    if self
                        .hosts
                        .boot_digest(&peer)
                        .is_some_and(|expected| expected != boot)
                    {
                        if let Some(ip) = self.hosts.address(&peer) {
                            tracing::warn!(host = %edge_net::quic::fingerprint(&peer), "boot measurement changed; quarantining");
                            let trigger = self.alert(
                                ip,
                                Severity::Critical,
                                "host boot measurement changed (attestation mismatch)",
                                serde_json::json!({ "host_id": hex::encode(peer) }),
                            );
                            if let Some(meta) = trigger {
                                contain(self, Some(ip), &meta).await;
                            }
                        }
                        continue;
                    }
                    self.hosts.seen(&peer);
                    tracing::debug!(host = %edge_net::quic::fingerprint(&peer), "heartbeat ok");
                }
            }
        }

        for peer in self.heartbeats.stale() {
            let Some(ip) = self.hosts.address(&peer) else {
                continue;
            };
            tracing::warn!(host = %edge_net::quic::fingerprint(&peer), "host heartbeat silent; quarantining");
            let trigger = self.alert(
                ip,
                Severity::Critical,
                "host daemon stopped answering its heartbeat (dead man's switch)",
                serde_json::json!({ "host_id": hex::encode(peer) }),
            );
            if let Some(meta) = trigger {
                contain(self, Some(ip), &meta).await;
            }
        }
    }
}

fn summary(config: &CoreConfig) -> ConfigSummary {
    ConfigSummary {
        name: config.name.clone(),
        firewall: config.firewall.kind().to_owned(),
    }
}

fn core_error(err: &CoreError) -> Response {
    Response::error(err.to_string())
}

/// An unpredictable, one-time id for an `ask`.
fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// A 32-byte nonce for a heartbeat challenge.
fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

pub async fn handle(state: AppState, peer: PeerId, addr: SocketAddr, req: Request) -> Response {
    match req {
        Request::Hello => Response::Hello {
            core_public: state.core.public().clone(),
            paired: state.core.is_paired(),
            config: state.core.config().as_ref().map(summary),
        },
        Request::PairOffer => match state.core.pair_offer() {
            Ok(offer) => Response::Offer {
                core_public: offer.core_public,
                nonce: offer.nonce,
            },
            Err(err) => core_error(&err),
        },
        Request::Pair {
            owner_public,
            epoch_public,
            signature,
        } => {
            let request = PairRequest {
                owner_public,
                epoch_public,
                signature,
            };
            match state.core.pair(&request, &peer) {
                Ok(code) => {
                    tracing::info!(%code, witness = %hex::encode(&peer[..8]), "paired; confirm this code on the phone");
                    (state.announcer)(&state.core);
                    Response::Paired {
                        confirmation_code: code,
                    }
                }
                Err(err) => core_error(&err),
            }
        }
        Request::Configure { config, signature } => {
            if !state.is_witness(&peer) {
                return Response::error("only the paired witness may configure this Core");
            }
            match state.core.set_config(&config, &signature) {
                Ok(()) => {
                    let firewall = firewall_from_config(&config.firewall);
                    tracing::info!(name = %config.name, firewall = firewall.name(), "configured by the owner");
                    if let Ok(mut slot) = state.firewall.write() {
                        *slot = firewall;
                    }
                    (state.announcer)(&state.core);
                    Response::Configured {
                        config: summary(&config),
                    }
                }
                Err(err) => core_error(&err),
            }
        }
        Request::Release {
            host,
            timestamp_ms,
            signature,
        } => {
            if !state.is_witness(&peer) {
                return Response::error("only the paired witness may release a quarantine");
            }
            release(&state, &host, timestamp_ms, &signature).await
        }
        Request::OpenRecord {
            from_seq,
            to_seq,
            timestamp_ms,
            signature,
        } => {
            if !state.is_witness(&peer) {
                return Response::error("only the paired witness may open the record");
            }
            open_record(&state, from_seq, to_seq, timestamp_ms, &signature)
        }
        Request::PendingAsks => {
            if !state.is_witness(&peer) {
                return Response::error("only the paired witness may list asks");
            }
            Response::Asks {
                asks: state.asks.pending(),
            }
        }
        Request::Answer {
            id,
            allow,
            signature,
        } => {
            if !state.is_witness(&peer) {
                return Response::error("only the paired witness may answer an ask");
            }
            answer(&state, &id, allow, &signature)
        }
        Request::ApproveHost {
            host,
            timestamp_ms,
            signature,
        } => {
            if !state.is_witness(&peer) {
                return Response::error("only the paired witness may enrol a host");
            }
            approve_host(&state, &host, timestamp_ms, &signature)
        }
        Request::Status
        | Request::Heads { .. }
        | Request::Events { .. }
        | Request::Hosts
        | Request::Identify { .. }
            if !state.is_witness(&peer) =>
        {
            Response::error("only the paired witness may read this Core")
        }
        Request::Status => match state.core.status() {
            Ok(status) => {
                let mut status = serde_json::to_value(status).unwrap_or_default();
                status["firewall"] = state.firewall().name().into();
                if let Some(config) = state.core.config() {
                    status["name"] = config.name.into();
                }
                Response::Status { status }
            }
            Err(err) => core_error(&err),
        },
        Request::Heads { since } => match state.core.heads_since(since) {
            Ok(heads) => Response::Heads { heads },
            Err(err) => core_error(&err),
        },
        Request::Events { since } => match state.core.events_since(since) {
            Ok(events) => Response::Events {
                events: events
                    .iter()
                    .filter_map(|e| serde_json::to_value(e).ok())
                    .collect(),
            },
            Err(err) => core_error(&err),
        },
        Request::Decide { call } => {
            state.hosts.seen(&peer);
            let call_id = call.call_id.clone();
            let decision = decide(&state, &call, &peer, Some(addr.ip())).await;
            state.note_decide(addr.ip(), call_id.as_deref());
            Response::Decision { decision }
        }
        Request::ProxyRecord { record } => {
            state.hosts.seen(&peer);
            state.record_proxy(addr.ip(), record);
            Response::Ack
        }
        Request::HostHello {
            hostname,
            os,
            boot_digest,
        } => {
            let boot = boot_digest
                .as_deref()
                .and_then(|b| hex::decode(b).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            state.hosts.hello(peer, &hostname, &os, boot);
            tracing::info!(host = %edge_net::quic::fingerprint(&peer), %hostname, %addr, "host connected");
            Response::Ack
        }
        Request::Hosts => {
            let mut hosts = state.hosts.list();
            for host in &mut hosts {
                host.approved = state.core.is_approved_host_hex(&host.id);
            }
            Response::Hosts { hosts }
        }
        Request::Identify { host } => {
            let Some(id) = hex::decode(&host)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            else {
                return Response::error("bad host id");
            };
            let name = state
                .core
                .config()
                .map(|c| c.name)
                .unwrap_or_else(|| "HAWK Core".into());
            match state.hosts.identify(&id, &name).await {
                Ok(()) => Response::Ack,
                Err(err) => Response::error(err),
            }
        }
        Request::IdentifySelf { .. } | Request::HeartbeatChallenge { .. } => {
            Response::error("not a host")
        }
    }
}

async fn decide(
    state: &AppState,
    call: &ToolCall,
    peer_id: &PeerId,
    peer: Option<IpAddr>,
) -> Decision {
    if !state.core.is_paired() {
        return Decision::deny("core not paired");
    }
    // Only enrolled hosts may decide (ADR-0021, ADR-0023).
    if !state.core.is_approved_host(peer_id) {
        return Decision::deny("host not enrolled");
    }
    let verdict = match state.detector.lock() {
        Ok(mut detector) => detector.decide(call),
        Err(_) => return Decision::deny("detector unavailable"),
    };
    let meta = match state.core.record_decision(call, &verdict) {
        Ok(meta) => meta,
        Err(err) => {
            tracing::error!(%err, "could not record decision, denying");
            return Decision::deny("record unavailable");
        }
    };
    tracing::info!(
        session = %call.session,
        tool = %call.tool,
        decision = ?verdict.decision,
        findings = verdict.findings.len(),
        contain = verdict.contain,
        "decided"
    );
    // The host to contain is the socket address of the authenticated QUIC
    // peer, never a value the client declares, so a host cannot get another
    // one quarantined.
    let host = peer.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    state.publisher.send(SinkEvent {
        family: "decisions",
        seq: meta.seq,
        timestamp_ms: meta.timestamp_ms,
        key: host,
        body: serde_json::to_value(&meta).unwrap_or_default(),
    });
    if verdict.contain {
        contain(state, peer, &meta).await;
    }
    match verdict.decision {
        Decision::Ask { reason } => state.hold_for_owner(call, peer, &reason).await,
        other => other,
    }
}

/// Quarantines the host on the network firewall and records the outcome.
async fn contain(state: &AppState, peer: Option<IpAddr>, trigger: &EventMeta) {
    let firewall = state.firewall();
    let reason = trigger
        .reason
        .clone()
        .unwrap_or_else(|| "critical finding".into());
    let (note, ok) = match peer {
        Some(ip) => match firewall.quarantine(ip, &reason).await {
            Ok(()) => ("contained", true),
            Err(err) => {
                tracing::error!(%err, %ip, "containment failed");
                ("containment_failed", false)
            }
        },
        None => ("containment_failed", false),
    };
    let meta = EventMeta {
        kind: "containment",
        host: peer.map(|p| p.to_string()),
        severity: Some(Severity::Critical),
        reason: Some(format!("{note}: {reason}")),
        ..EventMeta::empty()
    };
    let content = serde_json::json!({
        "firewall": firewall.name(),
        "host": peer.map(|p| p.to_string()),
        "ok": ok,
        "trigger_seq": trigger.seq,
    });
    match state
        .core
        .record(EventKind::Contained, meta, &content, true)
    {
        Ok(meta) => state.publisher.send(SinkEvent {
            family: "containment",
            seq: meta.seq,
            timestamp_ms: meta.timestamp_ms,
            key: peer.map_or_else(|| "unknown".into(), |p| p.to_string()),
            body: serde_json::to_value(&meta).unwrap_or_default(),
        }),
        Err(err) => tracing::error!(%err, "could not record containment"),
    }
}

/// An owner-signed request older than this is rejected (ADR-0018, ADR-0007).
const SIGNED_MAX_AGE_MS: u64 = 60_000;

/// Lifts a quarantine: the owner's signature covers the host address and the
/// timestamp, so a release cannot be replayed or aimed at another host.
async fn release(state: &AppState, host: &str, timestamp_ms: u64, signature: &str) -> Response {
    let message = release_message(host, timestamp_ms);
    if let Err(err) = state.core.verify_owner(&message, signature) {
        return core_error(&err);
    }
    let now = crate::core::now_ms();
    if now.saturating_sub(timestamp_ms) > SIGNED_MAX_AGE_MS
        || timestamp_ms.saturating_sub(now) > SIGNED_MAX_AGE_MS
    {
        return Response::error("release request too old");
    }
    let ip: IpAddr = match host.parse() {
        Ok(ip) => ip,
        Err(_) => return Response::error("bad host address"),
    };
    let firewall = state.firewall();
    if let Err(err) = firewall.release(ip).await {
        tracing::error!(%err, %ip, "release failed");
        return Response::error(err.to_string());
    }
    let meta = EventMeta {
        kind: "release",
        host: Some(host.to_owned()),
        ..EventMeta::empty()
    };
    let content = serde_json::json!({ "firewall": firewall.name(), "host": ip.to_string() });
    match state.core.record(EventKind::Released, meta, &content, true) {
        Ok(meta) => {
            state.publisher.send(SinkEvent {
                family: "containment",
                seq: meta.seq,
                timestamp_ms: meta.timestamp_ms,
                key: host.to_owned(),
                body: serde_json::to_value(&meta).unwrap_or_default(),
            });
            Response::Ack
        }
        Err(err) => core_error(&err),
    }
}

/// Opens a range of the sealed record for the witness: the owner's signature
/// covers the range and timestamp; the Core records the opening and hands the
/// events back still sealed (ADR-0007). The witness decrypts with its epoch
/// key.
fn open_record(
    state: &AppState,
    from_seq: u64,
    to_seq: u64,
    timestamp_ms: u64,
    signature: &str,
) -> Response {
    let message = open_record_message(from_seq, to_seq, timestamp_ms);
    if let Err(err) = state.core.verify_owner(&message, signature) {
        return core_error(&err);
    }
    let now = crate::core::now_ms();
    if now.saturating_sub(timestamp_ms) > SIGNED_MAX_AGE_MS
        || timestamp_ms.saturating_sub(now) > SIGNED_MAX_AGE_MS
    {
        return Response::error("open request too old");
    }
    if to_seq < from_seq {
        return Response::error("bad range");
    }
    let events = match state.core.events_range(from_seq, to_seq) {
        Ok(events) => events,
        Err(err) => return core_error(&err),
    };
    let meta = EventMeta {
        kind: "log_opened",
        ..EventMeta::empty()
    };
    let content = serde_json::json!({ "from_seq": from_seq, "to_seq": to_seq });
    if let Err(err) = state
        .core
        .record(EventKind::LogOpened, meta, &content, true)
    {
        return core_error(&err);
    }
    Response::Record {
        events: events
            .iter()
            .map(|e| RecordEvent {
                seq: e.seq,
                timestamp_ms: e.timestamp_ms,
                kind: e.kind as u8,
                payload: hex::encode(&e.payload),
            })
            .collect(),
    }
}

/// Resolves a pending `ask` with the owner's signed answer (ADR-0022).
fn answer(state: &AppState, id: &str, allow: bool, signature: &str) -> Response {
    let message = answer_message(id, allow);
    if let Err(err) = state.core.verify_owner(&message, signature) {
        return core_error(&err);
    }
    let Some(resolve) = state.asks.take(id) else {
        return Response::error("no such ask");
    };
    if resolve.send(allow).is_err() {
        return Response::error("the ask already resolved");
    }
    let meta = EventMeta {
        kind: "answer",
        decision: Some(if allow { "allow" } else { "deny" }),
        reason: Some("the owner answered the ask".into()),
        ..EventMeta::empty()
    };
    let content = serde_json::json!({ "ask_id": id, "allow": allow });
    match state
        .core
        .record(EventKind::Decision, meta, &content, false)
    {
        Ok(_) => Response::Ack,
        Err(err) => core_error(&err),
    }
}

/// Enrols a host daemon with the owner's signed approval (ADR-0021).
fn approve_host(state: &AppState, host: &str, timestamp_ms: u64, signature: &str) -> Response {
    let message = enroll_message(host, timestamp_ms);
    if let Err(err) = state.core.verify_owner(&message, signature) {
        return core_error(&err);
    }
    let now = crate::core::now_ms();
    if now.saturating_sub(timestamp_ms) > SIGNED_MAX_AGE_MS
        || timestamp_ms.saturating_sub(now) > SIGNED_MAX_AGE_MS
    {
        return Response::error("enrolment request too old");
    }
    if hex::decode(host)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .is_none()
    {
        return Response::error("bad host identity");
    }
    match state.core.approve_host(host) {
        Ok(()) => Response::Ack,
        Err(err) => core_error(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tests::{pair, TempDir, WITNESS};
    use detect::Rule;
    use guardian_core::{
        pairing::pair_message, seal, verify, wire::release_message, wire::ProposedToolCall, Event,
        Finding,
    };
    use integrations::dry_run::DryRun;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use rand::rngs::OsRng;

    const STRANGER: PeerId = [9u8; 32];

    fn addr() -> SocketAddr {
        "10.0.0.7:5000".parse().unwrap()
    }

    fn state_with(dir: &TempDir, detector: Detector, firewall: Arc<dyn Firewall>) -> AppState {
        let state = AppState::new(
            Core::open(&dir.0).unwrap(),
            detector,
            firewall,
            Publisher::none(),
            Arc::new(|_core: &Core| {}),
        );
        // Enrol the test peer so decide tests exercise the detector, not the
        // enrolment gate (ADR-0021).
        state.core().approve_host(&hex::encode(STRANGER)).unwrap();
        state
    }

    fn raw_state(dir: &TempDir) -> AppState {
        AppState::new(
            Core::open(&dir.0).unwrap(),
            Detector::new(),
            Arc::new(DryRun::default()),
            Publisher::none(),
            Arc::new(|_core: &Core| {}),
        )
    }

    fn bash(command: &str) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: "bash".into(),
            args: serde_json::json!({ "command": command }),
            cwd: "/w".into(),
            host: None,
            call_id: None,
        }
    }

    async fn decide_req(s: &AppState, call: ToolCall) -> Decision {
        match handle(s.clone(), STRANGER, addr(), Request::Decide { call }).await {
            Response::Decision { decision } => decision,
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn unpaired_core_denies_and_offers_pairing() {
        let dir = TempDir::new("api-unpaired");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        assert!(!decide_req(&s, bash("ls")).await.is_allow());
        assert!(matches!(
            handle(s.clone(), STRANGER, addr(), Request::PairOffer).await,
            Response::Offer { .. }
        ));
    }

    #[tokio::test]
    async fn only_the_paired_witness_reads_the_record() {
        let dir = TempDir::new("api-witness");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        pair(s.core());
        assert!(decide_req(&s, bash("ls")).await.is_allow());

        let stranger = handle(s.clone(), STRANGER, addr(), Request::Events { since: None }).await;
        assert!(matches!(stranger, Response::Error { .. }));

        match handle(s.clone(), WITNESS, addr(), Request::Events { since: None }).await {
            Response::Events { events } => assert_eq!(events.len(), 2),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            handle(s.clone(), STRANGER, addr(), Request::PairOffer).await,
            Response::Error { .. }
        ));
    }

    #[tokio::test]
    async fn configuration_needs_the_witness_and_the_owner_signature() {
        let dir = TempDir::new("api-config");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        pair(s.core());
        let config = CoreConfig {
            name: "lab".into(),
            firewall: FirewallConfig::DryRun,
        };
        let bad = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::Configure {
                config: config.clone(),
                signature: "00".into(),
            },
        )
        .await;
        assert!(matches!(bad, Response::Error { .. }));
        let stranger = handle(
            s.clone(),
            STRANGER,
            addr(),
            Request::Configure {
                config,
                signature: "00".into(),
            },
        )
        .await;
        assert!(matches!(stranger, Response::Error { .. }));
    }

    #[derive(Debug)]
    struct Critical;

    impl Rule for Critical {
        fn check(&self, call: &ToolCall) -> Option<Finding> {
            call.args["command"]
                .as_str()?
                .contains("CRITICAL")
                .then(|| Finding {
                    rule: "test.critical".into(),
                    severity: Severity::Critical,
                    reason: "test".into(),
                })
        }
    }

    #[derive(Debug)]
    struct Medium;

    impl Rule for Medium {
        fn check(&self, call: &ToolCall) -> Option<Finding> {
            call.args["command"]
                .as_str()?
                .contains("ASK")
                .then(|| Finding {
                    rule: "test.medium".into(),
                    severity: Severity::Medium,
                    reason: "test".into(),
                })
        }
    }

    #[tokio::test]
    async fn a_critical_finding_quarantines_the_quic_peer() {
        let dir = TempDir::new("api-contain");
        let firewall = Arc::new(DryRun::default());
        let s = state_with(
            &dir,
            Detector::with_rules(vec![Box::new(Critical)]),
            firewall.clone(),
        );
        pair(s.core());
        let peer = addr().ip();
        assert!(decide_req(&s, bash("ls")).await.is_allow());
        assert!(!firewall.is_quarantined(peer));
        assert!(!decide_req(&s, bash("CRITICAL")).await.is_allow());
        assert!(firewall.is_quarantined(peer));
    }

    #[tokio::test]
    async fn the_witness_lists_hosts_and_makes_one_identify_itself() {
        use edge_net::quic;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = TempDir::new("api-identify");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        pair(s.core());

        // The Core on a real QUIC endpoint.
        let core_key = s.core().keys().transport_key().clone();
        let identity = quic::TlsIdentity::from_signing_key(&core_key, "hawk-core").unwrap();
        let endpoint = quic::server(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let core_addr = endpoint.local_addr().unwrap();
        let (hook, served) = (s.clone(), s.clone());
        tokio::spawn(quic::serve_with(
            endpoint,
            move |peer, conn| hook.on_connect(peer, conn),
            move |peer, from, req| handle(served.clone(), peer, from, req),
        ));

        // A host daemon: connects, introduces itself, answers identification.
        let host_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let host_id = host_key.verifying_key().to_bytes();
        let client =
            quic::Client::new(quic::TlsIdentity::from_signing_key(&host_key, "hawk-host").unwrap())
                .unwrap();
        let (conn, core_id) = client
            .connect(core_addr, Some(identity.peer_id))
            .await
            .unwrap();
        let shown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shown);
        tokio::spawn(quic::serve_connection(
            conn.clone(),
            core_id,
            move |_p, _a, req: Request| {
                let flag = Arc::clone(&flag);
                async move {
                    if matches!(req, Request::IdentifySelf { .. }) {
                        flag.store(true, Ordering::SeqCst);
                    }
                    Response::Ack
                }
            },
        ));
        let hello = Request::HostHello {
            hostname: "rig-07".into(),
            os: "linux".into(),
            boot_digest: None,
        };
        let _: Response = quic::request(&conn, &hello, std::time::Duration::from_secs(5))
            .await
            .unwrap();

        let hosts = match handle(s.clone(), WITNESS, addr(), Request::Hosts).await {
            Response::Hosts { hosts } => hosts,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "rig-07");
        assert_eq!(hosts[0].fingerprint, quic::fingerprint(&host_id));
        assert!(hosts[0].connected);

        // A stranger cannot list or identify.
        assert!(matches!(
            handle(s.clone(), STRANGER, addr(), Request::Hosts).await,
            Response::Error { .. }
        ));

        let identify = Request::Identify {
            host: hex::encode(host_id),
        };
        assert!(matches!(
            handle(s.clone(), WITNESS, addr(), identify).await,
            Response::Ack
        ));
        assert!(shown.load(Ordering::SeqCst));
    }

    fn proposed(id: &str) -> ProposedToolCall {
        ProposedToolCall {
            id: id.to_owned(),
            name: "bash".into(),
            arguments: serde_json::json!({}),
        }
    }

    async fn alerts(s: &AppState) -> Vec<serde_json::Value> {
        match handle(s.clone(), WITNESS, addr(), Request::Events { since: None }).await {
            Response::Events { events } => events
                .into_iter()
                .filter(|e| e.get("kind").and_then(|k| k.as_str()) == Some("alert"))
                .collect(),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_decide_matching_its_proposal_raises_no_alert() {
        let dir = TempDir::new("cc-matched");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        pair(s.core());

        // The proxy saw the model propose tool call "c1".
        let record = ProxyRecord {
            timestamp_ms: 0,
            path: "/v1/chat/completions".into(),
            request: serde_json::json!({}),
            response: None,
            tool_calls: vec![proposed("c1")],
        };
        assert!(matches!(
            handle(s.clone(), STRANGER, addr(), Request::ProxyRecord { record }).await,
            Response::Ack
        ));

        // The hook then asks for the same call: no evasion alert.
        let mut call = bash("ls");
        call.call_id = Some("c1".into());
        assert!(decide_req(&s, call).await.is_allow());
        assert!(alerts(&s).await.is_empty());
    }

    #[tokio::test]
    async fn a_proposal_that_never_reaches_the_hook_quarantines() {
        let dir = TempDir::new("cc-evasion");
        let firewall = Arc::new(DryRun::default());
        let s = state_with(&dir, Detector::new(), firewall.clone());
        pair(s.core());
        let peer = addr().ip();

        // A proposal far in the past: the sweep evicts it at once.
        s.crosscheck.proposed(peer, 0, &[proposed("c1")]);
        s.sweep_expired().await;

        assert!(firewall.is_quarantined(peer));
        let alerts = alerts(&s).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["severity"], "critical");
    }

    #[tokio::test]
    async fn a_decide_without_a_proposal_raises_a_high_alert() {
        let dir = TempDir::new("cc-ghost");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        pair(s.core());

        let mut call = bash("ls");
        call.call_id = Some("ghost".into());
        assert!(decide_req(&s, call).await.is_allow());

        let alerts = alerts(&s).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0]["severity"], "high");
    }

    /// Pairs `core` and returns the owner signing key, so a test can sign a
    /// release request with the same key the Core stores.
    fn pair_owner(core: &Core) -> SigningKey {
        let owner = SigningKey::random(&mut OsRng);
        let offer = core.pair_offer().unwrap();
        let message = pair_message(
            &hex::decode(&offer.nonce).unwrap(),
            &offer.core_public.ed25519,
            &WITNESS,
        );
        let signature: Signature = owner.sign(&message);
        core.pair(
            &PairRequest {
                owner_public: hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes()),
                epoch_public: hex::encode(seal::epoch_public(&[7u8; 32])),
                signature: hex::encode(signature.to_der().as_bytes()),
            },
            &WITNESS,
        )
        .unwrap();
        owner
    }

    fn release_req(owner: &SigningKey, host: IpAddr, ts: u64) -> Request {
        let signature: Signature = owner.sign(&release_message(&host.to_string(), ts));
        Request::Release {
            host: host.to_string(),
            timestamp_ms: ts,
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }

    #[tokio::test]
    async fn releasing_requires_the_owner_signature() {
        let dir = TempDir::new("release-sig");
        let firewall = Arc::new(DryRun::default());
        let s = state_with(&dir, Detector::new(), firewall.clone());
        pair_owner(s.core());
        let host = addr().ip();
        firewall.quarantine(host, "test").await.unwrap();

        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::Release {
                host: host.to_string(),
                timestamp_ms: crate::core::now_ms(),
                signature: "00".into(),
            },
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
        assert!(firewall.is_quarantined(host));
    }

    #[tokio::test]
    async fn an_old_release_is_rejected() {
        let dir = TempDir::new("release-old");
        let firewall = Arc::new(DryRun::default());
        let s = state_with(&dir, Detector::new(), firewall.clone());
        let owner = pair_owner(s.core());
        let host = addr().ip();
        firewall.quarantine(host, "test").await.unwrap();

        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            release_req(&owner, host, crate::core::now_ms() - 120_000),
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
        assert!(firewall.is_quarantined(host));
    }

    #[tokio::test]
    async fn a_stranger_cannot_release() {
        let dir = TempDir::new("release-stranger");
        let firewall = Arc::new(DryRun::default());
        let s = state_with(&dir, Detector::new(), firewall.clone());
        let owner = pair_owner(s.core());
        let host = addr().ip();
        firewall.quarantine(host, "test").await.unwrap();

        let resp = handle(
            s.clone(),
            STRANGER,
            addr(),
            release_req(&owner, host, crate::core::now_ms()),
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
        assert!(firewall.is_quarantined(host));
    }

    #[tokio::test]
    async fn the_owner_releases_a_quarantined_host() {
        let dir = TempDir::new("release-ok");
        let firewall = Arc::new(DryRun::default());
        let s = state_with(&dir, Detector::new(), firewall.clone());
        let owner = pair_owner(s.core());
        let host = addr().ip();
        firewall.quarantine(host, "test").await.unwrap();

        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            release_req(&owner, host, crate::core::now_ms()),
        )
        .await;
        assert!(matches!(resp, Response::Ack));
        assert!(!firewall.is_quarantined(host));

        let released: Vec<_> =
            match handle(s.clone(), WITNESS, addr(), Request::Events { since: None }).await {
                Response::Events { events } => events
                    .into_iter()
                    .filter(|e| e.get("kind").and_then(|k| k.as_str()) == Some("release"))
                    .collect(),
                other => panic!("unexpected {other:?}"),
            };
        assert_eq!(released.len(), 1);
        assert_eq!(released[0]["host"], host.to_string());
    }

    #[tokio::test]
    async fn opening_the_record_requires_the_owner_signature() {
        let dir = TempDir::new("open-sig");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        pair_owner(s.core());
        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::OpenRecord {
                from_seq: 0,
                to_seq: 10,
                timestamp_ms: crate::core::now_ms(),
                signature: "00".into(),
            },
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
    }

    #[tokio::test]
    async fn the_owner_opens_the_sealed_record() {
        let dir = TempDir::new("open-ok");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        let owner = pair_owner(s.core());
        assert!(decide_req(&s, bash("ls")).await.is_allow());

        let heads = match handle(s.clone(), WITNESS, addr(), Request::Heads { since: None }).await {
            Response::Heads { heads } => heads,
            other => panic!("unexpected {other:?}"),
        };
        let last = heads.last().unwrap().clone();
        assert_eq!(last.seq, 0);

        let ts = crate::core::now_ms();
        let signature: Signature = owner.sign(&open_record_message(0, last.seq, ts));
        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::OpenRecord {
                from_seq: 0,
                to_seq: last.seq,
                timestamp_ms: ts,
                signature: hex::encode(signature.to_der().as_bytes()),
            },
        )
        .await;
        let events = match resp {
            Response::Record { events } => events,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(events.len(), 1);

        // The events are still sealed and rebuild to the signed head.
        let mut rebuilt = Vec::with_capacity(events.len());
        for e in &events {
            let kind = EventKind::from_u8(e.kind).unwrap();
            rebuilt.push(Event {
                seq: e.seq,
                timestamp_ms: e.timestamp_ms,
                kind,
                payload: hex::decode(&e.payload).unwrap(),
            });
        }
        assert_eq!(verify(&rebuilt, last.seq, &last.head), Ok(()));

        // The opening was recorded.
        let opened = match handle(s.clone(), WITNESS, addr(), Request::Events { since: None }).await
        {
            Response::Events { events } => events
                .into_iter()
                .any(|e| e.get("kind").and_then(|k| k.as_str()) == Some("log_opened")),
            other => panic!("unexpected {other:?}"),
        };
        assert!(opened);
    }

    async fn pending_id(s: &AppState) -> String {
        loop {
            if let Response::Asks { asks } =
                handle(s.clone(), WITNESS, addr(), Request::PendingAsks).await
            {
                if let Some(ask) = asks.first() {
                    return ask.id.clone();
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn the_owner_answers_an_ask_in_time() {
        let dir = TempDir::new("ask-ok");
        let s = state_with(
            &dir,
            Detector::with_rules(vec![Box::new(Medium)]),
            Arc::new(DryRun::default()),
        );
        let owner = pair_owner(s.core());

        let call = bash("ASK");
        let task = {
            let s = s.clone();
            tokio::spawn(async move {
                match handle(s.clone(), STRANGER, addr(), Request::Decide { call }).await {
                    Response::Decision { decision } => decision,
                    other => panic!("unexpected {other:?}"),
                }
            })
        };

        let id = pending_id(&s).await;
        let signature: Signature = owner.sign(&answer_message(&id, true));
        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::Answer {
                id,
                allow: true,
                signature: hex::encode(signature.to_der().as_bytes()),
            },
        )
        .await;
        assert!(matches!(resp, Response::Ack));
        assert!(task.await.unwrap().is_allow());
    }

    #[tokio::test]
    async fn an_unanswered_ask_is_denied() {
        let dir = TempDir::new("ask-timeout");
        let s = state_with(&dir, Detector::new(), Arc::new(DryRun::default()));
        let decision = s
            .hold_for_owner_timeout(
                &bash("ASK"),
                None,
                "reason",
                std::time::Duration::from_millis(20),
            )
            .await;
        assert!(matches!(decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn answering_requires_the_owner_signature() {
        let dir = TempDir::new("ask-sig");
        let s = state_with(
            &dir,
            Detector::with_rules(vec![Box::new(Medium)]),
            Arc::new(DryRun::default()),
        );
        pair_owner(s.core());

        let call = bash("ASK");
        let task = {
            let s = s.clone();
            tokio::spawn(async move {
                match handle(s.clone(), STRANGER, addr(), Request::Decide { call }).await {
                    Response::Decision { decision } => decision,
                    other => panic!("unexpected {other:?}"),
                }
            })
        };

        let id = pending_id(&s).await;
        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::Answer {
                id,
                allow: true,
                signature: "00".into(),
            },
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
        // The invalid answer did not resolve the ask.
        assert_eq!(s.asks.pending().len(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn an_unenrolled_host_is_denied() {
        let dir = TempDir::new("enroll-deny");
        let s = raw_state(&dir);
        pair(s.core());
        assert!(matches!(
            decide_req(&s, bash("ls")).await,
            Decision::Deny { .. }
        ));
    }

    #[tokio::test]
    async fn the_owner_enrols_a_host_and_it_can_decide() {
        let dir = TempDir::new("enroll-ok");
        let s = raw_state(&dir);
        let owner = pair_owner(s.core());
        let host = hex::encode(STRANGER);
        assert!(matches!(
            decide_req(&s, bash("ls")).await,
            Decision::Deny { .. }
        ));

        let ts = crate::core::now_ms();
        let signature: Signature = owner.sign(&enroll_message(&host, ts));
        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::ApproveHost {
                host: host.clone(),
                timestamp_ms: ts,
                signature: hex::encode(signature.to_der().as_bytes()),
            },
        )
        .await;
        assert!(matches!(resp, Response::Ack));
        assert!(decide_req(&s, bash("ls")).await.is_allow());
    }

    #[tokio::test]
    async fn enrolling_requires_the_owner_signature() {
        let dir = TempDir::new("enroll-sig");
        let s = raw_state(&dir);
        pair_owner(s.core());
        let resp = handle(
            s.clone(),
            WITNESS,
            addr(),
            Request::ApproveHost {
                host: hex::encode(STRANGER),
                timestamp_ms: crate::core::now_ms(),
                signature: "00".into(),
            },
        )
        .await;
        assert!(matches!(resp, Response::Error { .. }));
        assert!(matches!(
            decide_req(&s, bash("ls")).await,
            Decision::Deny { .. }
        ));
    }
}
