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
    wire::{ConfigSummary, CoreConfig, FirewallConfig, Request, Response},
    Decision, EventKind, Severity, ToolCall,
};
use integrations::{sinks::Publisher, Firewall, SinkEvent};

use crate::{
    core::{Core, CoreError, EventMeta, PairRequest},
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
            Response::Decision {
                decision: decide(&state, &call, Some(addr.ip())).await,
            }
        }
        Request::HostHello { hostname, os } => {
            state.hosts.hello(peer, &hostname, &os);
            tracing::info!(host = %edge_net::quic::fingerprint(&peer), %hostname, %addr, "host connected");
            Response::Ack
        }
        Request::Hosts => Response::Hosts {
            hosts: state.hosts.list(),
        },
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
        Request::IdentifySelf { .. } => Response::error("not a host"),
    }
}

async fn decide(state: &AppState, call: &ToolCall, peer: Option<IpAddr>) -> Decision {
    if !state.core.is_paired() {
        return Decision::deny("core not paired");
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
    verdict.decision
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::tests::{pair, TempDir, WITNESS};
    use detect::Rule;
    use guardian_core::Finding;
    use integrations::dry_run::DryRun;

    const STRANGER: PeerId = [9u8; 32];

    fn addr() -> SocketAddr {
        "10.0.0.7:5000".parse().unwrap()
    }

    fn state_with(dir: &TempDir, detector: Detector, firewall: Arc<dyn Firewall>) -> AppState {
        AppState::new(
            Core::open(&dir.0).unwrap(),
            detector,
            firewall,
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
}
