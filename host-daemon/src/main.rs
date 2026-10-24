//! Host daemon (ADR-0015). Listens on loopback (`HOST_DAEMON_ADDR`, default
//! `127.0.0.1:7070`) for the agent hooks of this machine and relays each
//! request to the Core over QUIC with mutual TLS (ADR-0023).
//!
//! Loopback HTTP is the only HTTP left: OpenCode cannot speak QUIC, and
//! nothing on that socket leaves the machine.
//!
//! Finding the Core (ADR-0024): `GUARDIAN_CORE` (`ip:port`) when set,
//! otherwise the first active Core discovered on the network. The Core's
//! identity is pinned: `GUARDIAN_CORE_ID` when set, otherwise the first one
//! this daemon talks to, stored in `core.pin`.
//!
//! It never decides: it returns the Core's answer, and denies when the Core
//! cannot be found or reached, or the answer is unusable.

#![forbid(unsafe_code)]

mod heartbeat;
mod notice;
mod tpm;

use heartbeat::Heartbeat;

use std::{
    error::Error as StdError,
    fs,
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use edge_net::{
    discovery,
    http::{boxed, json, read_json, text, BoxBody},
    quic::{self, PeerId},
};
use guardian_core::{
    wire::{ProxyRecord, Request as Wire, Response as WireResponse},
    Decision, ToolCall,
};
use hyper::{Method, Request, Response, StatusCode};
use llm_proxy::{Proxy, ProxyConfig, RecordSink};
use quinn::Connection;
use rand::rngs::OsRng;
use tokio::{net::TcpListener, sync::Mutex};
use tracing_subscriber::EnvFilter;

const MAX_BODY_BYTES: usize = 256 * 1024;
/// Longer than the owner's 60 s to answer an `ask` (ADR-0022).
const DECIDE_TIMEOUT: Duration = Duration::from_secs(65);
const DISCOVERY_WAIT: Duration = Duration::from_secs(2);

/// How to find the Core.
#[derive(Debug, Clone)]
enum Locator {
    Fixed(SocketAddr),
    Discover,
    /// For tests: no Core at all.
    #[cfg(test)]
    None,
}

struct Link {
    client: quic::Client,
    locator: Locator,
    pin_file: Option<PathBuf>,
    pinned: Mutex<Option<PeerId>>,
    conn: Mutex<Option<Connection>>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("locator", &self.locator)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
struct Relay {
    link: Arc<Link>,
    heartbeat: Arc<Heartbeat>,
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// This machine's name, for the app. A label only: the identity is the key.
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    hex::decode(text.trim()).ok()?.try_into().ok()
}

/// The daemon's Ed25519 identity, kept in the data directory (to be sealed by
/// the TPM, ADR-0021).
fn load_or_create_key(dir: &Path) -> std::io::Result<SigningKey> {
    fs::create_dir_all(dir)?;
    let path = dir.join("host.key");
    if let Some(seed) = fs::read_to_string(&path).ok().as_deref().and_then(hex32) {
        return Ok(SigningKey::from_bytes(&seed));
    }
    let key = SigningKey::generate(&mut OsRng);
    write_private(&path, hex::encode(key.to_bytes()).as_bytes())?;
    Ok(key)
}

impl Relay {
    fn new(
        key: &SigningKey,
        locator: Locator,
        pin: Option<PeerId>,
        pin_file: Option<PathBuf>,
        counter_file: Option<PathBuf>,
        boot: Option<[u8; 32]>,
    ) -> Result<Self, String> {
        let identity = quic::TlsIdentity::from_signing_key(key, "hawk-host")?;
        let pinned = pin.or_else(|| {
            pin_file
                .as_deref()
                .and_then(|p| fs::read_to_string(p).ok())
                .as_deref()
                .and_then(hex32)
        });
        Ok(Self {
            link: Arc::new(Link {
                client: quic::Client::new(identity)?,
                locator,
                pin_file,
                pinned: Mutex::new(pinned),
                conn: Mutex::new(None),
            }),
            heartbeat: Arc::new(Heartbeat::new(key.clone(), counter_file, boot)),
        })
    }

    /// Where the Core is right now.
    async fn find(&self, pinned: Option<PeerId>) -> Result<SocketAddr, String> {
        match &self.link.locator {
            Locator::Fixed(addr) => Ok(*addr),
            #[cfg(test)]
            Locator::None => Err("no core configured".into()),
            Locator::Discover => {
                let found = tokio::task::spawn_blocking(|| discovery::browse(DISCOVERY_WAIT))
                    .await
                    .map_err(|e| e.to_string())??;
                found
                    .into_iter()
                    .filter(|f| f.txt.get("state").map(String::as_str) == Some("active"))
                    .find(|f| match pinned {
                        Some(pin) => f.txt.get("id").and_then(|id| hex32(id)) == Some(pin),
                        None => true,
                    })
                    .and_then(|f| f.addrs.first().copied())
                    .ok_or_else(|| "no active core found on the network".to_owned())
            }
        }
    }

    async fn connection(&self) -> Result<Connection, String> {
        let mut slot = self.link.conn.lock().await;
        if let Some(conn) = slot.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        let pinned = *self.link.pinned.lock().await;
        let addr = self.find(pinned).await?;
        let (conn, id) = self.link.client.connect(addr, pinned).await?;
        if pinned.is_none() {
            // Trust on first use, until host enrolment exists (ADR-0021).
            tracing::warn!(core = %hex::encode(&id[..8]), "pinning this core");
            *self.link.pinned.lock().await = Some(id);
            if let Some(path) = &self.link.pin_file {
                let _ = write_private(path, hex::encode(id).as_bytes());
            }
        }
        self.introduce(&conn, id).await;
        *slot = Some(conn.clone());
        Ok(conn)
    }

    /// Tells the Core how to show this host, and answers what the Core asks
    /// on this connection (the identification signal).
    async fn introduce(&self, conn: &Connection, core: PeerId) {
        let hello = Wire::HostHello {
            hostname: hostname(),
            os: std::env::consts::OS.to_owned(),
            boot_digest: self.heartbeat.boot().map(hex::encode),
        };
        if let Err(err) =
            quic::request::<_, WireResponse>(conn, &hello, Duration::from_secs(5)).await
        {
            tracing::warn!(%err, "core did not take the host hello");
        }
        let heartbeat = Arc::clone(&self.heartbeat);
        tokio::spawn(quic::serve_connection(
            conn.clone(),
            core,
            move |_peer, _addr, req: Wire| {
                let heartbeat = Arc::clone(&heartbeat);
                async move {
                    match req {
                        Wire::IdentifySelf {
                            core_name,
                            fingerprint,
                        } => {
                            let text = notice::message(&core_name, &fingerprint, &hostname());
                            let shown = tokio::task::spawn_blocking(move || notice::show(&text))
                                .await
                                .unwrap_or(false);
                            if !shown {
                                tracing::warn!(
                                    "no desktop notifier accepted the notice; it is in the log"
                                );
                            }
                            WireResponse::Ack
                        }
                        Wire::HeartbeatChallenge { nonce } => {
                            let nonce = hex::decode(&nonce).unwrap_or_default();
                            let (counter, digest, signature, boot) = heartbeat.beat(&nonce);
                            WireResponse::Heartbeat {
                                nonce: hex::encode(nonce),
                                counter,
                                digest: hex::encode(digest),
                                signature,
                                boot: boot.map(hex::encode),
                            }
                        }
                        _ => WireResponse::error("a host daemon only answers identification"),
                    }
                }
            },
        ));
    }

    async fn decide(&self, call: &ToolCall) -> Decision {
        // The heartbeat carries the hash of what this daemon observed, so the
        // Core can compare it with the hook and proxy reports (ADR-0021).
        self.heartbeat.note_call(call.digest());
        // One retry with a fresh connection if the cached one went stale.
        for attempt in 0..2 {
            let conn = match self.connection().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(%err, "core unavailable, denying");
                    return Decision::deny("core unreachable");
                }
            };
            let req = Wire::Decide { call: call.clone() };
            match quic::request::<_, WireResponse>(&conn, &req, DECIDE_TIMEOUT).await {
                Ok(WireResponse::Decision { decision }) => return decision,
                Ok(other) => {
                    tracing::warn!(?other, "unexpected answer from the core, denying");
                    return Decision::deny("unexpected answer from the core");
                }
                Err(err) if attempt == 0 => {
                    tracing::debug!(%err, "retrying with a new connection");
                    *self.link.conn.lock().await = None;
                }
                Err(err) => {
                    tracing::warn!(%err, "core call failed, denying");
                }
            }
        }
        Decision::deny("core unreachable")
    }

    /// A `RecordSink` the proxy calls after each response: relays the copy to
    /// the Core over QUIC. Fire-and-forget so a slow Core never blocks the
    /// agent's answer; failures are logged and the Core records nothing.
    fn proxy_sink(&self) -> RecordSink {
        let relay = self.clone();
        Arc::new(move |record| {
            let relay = relay.clone();
            tokio::spawn(async move {
                if let Err(err) = relay.send_proxy_record(record).await {
                    tracing::warn!(%err, "could not relay the proxy record to the core");
                }
            });
        })
    }

    async fn send_proxy_record(&self, record: ProxyRecord) -> Result<(), String> {
        let conn = self.connection().await?;
        match quic::request::<_, WireResponse>(
            &conn,
            &Wire::ProxyRecord { record },
            Duration::from_secs(5),
        )
        .await?
        {
            WireResponse::Ack => Ok(()),
            other => Err(format!("unexpected answer from the core: {other:?}")),
        }
    }
}

async fn handle<B>(relay: Relay, proxy: Arc<Proxy>, req: Request<B>) -> Response<BoxBody>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    match (method, path.as_str()) {
        (Method::GET, "/health") => boxed(text(StatusCode::OK, "ok")),
        (Method::POST, "/decide") => {
            let decision = match read_json::<ToolCall, _>(req, MAX_BODY_BYTES).await {
                Ok(call) => {
                    let decision = relay.decide(&call).await;
                    tracing::info!(session = %call.session, tool = %call.tool, ?decision, "relayed");
                    decision
                }
                Err(_) => Decision::deny("malformed tool call"),
            };
            boxed(json(StatusCode::OK, &decision))
        }
        _ if Proxy::accepts(&path) => match proxy.forward(req, relay.proxy_sink()).await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(%err, "proxy forwarding failed");
                boxed(text(StatusCode::BAD_GATEWAY, "bad gateway"))
            }
        },
        _ => boxed(text(StatusCode::NOT_FOUND, "not found")),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let addr: SocketAddr = std::env::var("HOST_DAEMON_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7070".into())
        .parse()?;
    if !addr.ip().is_loopback() {
        return Err("HOST_DAEMON_ADDR must be a loopback address".into());
    }
    let dir = PathBuf::from(
        std::env::var("HOST_DAEMON_DATA_DIR").unwrap_or_else(|_| "host-daemon-data".into()),
    );
    let key = load_or_create_key(&dir)?;
    let locator = match std::env::var("GUARDIAN_CORE") {
        Ok(core) => Locator::Fixed(core.parse()?),
        Err(_) => Locator::Discover,
    };
    let pin = std::env::var("GUARDIAN_CORE_ID")
        .ok()
        .as_deref()
        .and_then(hex32);
    let boot = tpm::boot_digest();
    if boot.is_some() {
        tracing::info!("TPM boot measurement available");
    }
    let relay = Relay::new(
        &key,
        locator,
        pin,
        Some(dir.join("core.pin")),
        Some(dir.join("heartbeat.counter")),
        boot,
    )?;
    let upstream = std::env::var("OLLAMA_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
    let proxy = Arc::new(Proxy::new(
        ProxyConfig {
            upstream: upstream.clone(),
        },
        Duration::from_secs(5),
    ));
    tracing::warn!(
        fingerprint = %quic::fingerprint(&key.verifying_key().to_bytes()),
        hostname = %hostname(),
        "host identity"
    );

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, %upstream, "host daemon listening on loopback");
    edge_net::http::serve(listener, move |req| {
        handle(relay.clone(), proxy.clone(), req)
    })
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    const CALL: &[u8] = br#"{"session":"s","tool":"bash","args":{"command":"ls"},"cwd":"/w"}"#;

    /// A proxy that never talks to a real upstream: only `/decide` is used.
    fn dummy_proxy() -> Arc<Proxy> {
        Arc::new(Proxy::new(
            ProxyConfig {
                upstream: "http://127.0.0.1:1".into(),
            },
            Duration::from_secs(1),
        ))
    }

    async fn ask(relay: Relay, body: &'static [u8]) -> Decision {
        let req = Request::post("/decide")
            .body(Full::new(Bytes::from_static(body)))
            .unwrap();
        let bytes = handle(relay, dummy_proxy(), req)
            .await
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A stand-in Core over QUIC that answers every decision with `answer`.
    async fn fake_core(answer: Decision) -> (SocketAddr, PeerId) {
        let key = SigningKey::generate(&mut OsRng);
        let identity = quic::TlsIdentity::from_signing_key(&key, "hawk-core").unwrap();
        let endpoint = quic::server(&identity, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(quic::serve(endpoint, move |_peer, _addr, req: Wire| {
            let decision = answer.clone();
            async move {
                match req {
                    Wire::HostHello { .. } => WireResponse::Ack,
                    _ => WireResponse::Decision { decision },
                }
            }
        }));
        (addr, identity.peer_id)
    }

    fn relay(locator: Locator, pin: Option<PeerId>) -> Relay {
        Relay::new(
            &SigningKey::generate(&mut OsRng),
            locator,
            pin,
            None,
            None,
            None,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn returns_the_core_answer_over_quic() {
        let (addr, id) = fake_core(Decision::Allow).await;
        assert!(ask(relay(Locator::Fixed(addr), Some(id)), CALL)
            .await
            .is_allow());
    }

    #[tokio::test]
    async fn refuses_a_core_with_another_identity() {
        let (addr, _) = fake_core(Decision::Allow).await;
        assert!(!ask(relay(Locator::Fixed(addr), Some([5u8; 32])), CALL)
            .await
            .is_allow());
    }

    #[tokio::test]
    async fn denies_without_a_core() {
        assert!(!ask(relay(Locator::None, None), CALL).await.is_allow());
    }

    #[tokio::test]
    async fn denies_malformed_calls() {
        let (addr, id) = fake_core(Decision::Allow).await;
        assert!(!ask(relay(Locator::Fixed(addr), Some(id)), b"{nope")
            .await
            .is_allow());
    }
}
