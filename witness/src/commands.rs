//! Commands the web view may call. All logic lives here: the web view only
//! shows results, and no key material ever crosses into it (ADR-0013).
//!
//! The app talks to its Core only over QUIC with mutual TLS (ADR-0023): the
//! app has its own device identity, the Core's identity is pinned at pairing,
//! and the owner's signature binds that pair (ADR-0017). Cores are found on
//! the network by mDNS (ADR-0024); where multicast does not reach (another
//! VLAN, an emulator) the owner may type the address, and the fingerprint
//! and the six-digit code still decide.
//!
//! Keys live in the app's data directory for the desktop build and the demo:
//! `device.key` (Ed25519, transport identity), `owner.key` (P-256, owner
//! signatures), `epoch.key` (X25519, opens the record). On Android they move
//! into the Keystore (see PENDIENTES.md).

use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use edge_net::{
    discovery,
    quic::{self, PeerId},
};
use guardian_core::{
    pairing::{confirmation_code, pair_message},
    seal, verify,
    wire::{
        answer_message, approve_message, configure_message, open_record_message, release_message,
        CoreConfig, FirewallConfig, HostApproval, HostInfo, PendingAsk, RecordEvent, Request,
        Response, Thresholds,
    },
    CorePublic, Event, EventKind, SignedHead,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use quinn::Connection;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use tokio::sync::Mutex;

const CALL_TIMEOUT: Duration = Duration::from_secs(10);
const DISCOVERY_WAIT: Duration = Duration::from_millis(2500);
/// Heads shown in the dashboard, newest last.
const HEADS_SHOWN: usize = 50;

/// The live QUIC connection to the paired Core, reused across commands.
#[derive(Default)]
pub struct Link {
    conn: Mutex<Option<Connection>>,
}

/// The Core this app is paired with, as remembered between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Remembered {
    id: String,
    last_addr: Option<String>,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CoreRef {
    id: String,
    fingerprint: String,
    name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AppInfo {
    version: &'static str,
    core: Option<CoreRef>,
    device_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct Discovered {
    id: String,
    fingerprint: String,
    name: String,
    state: String,
    address: String,
}

#[derive(Debug, Serialize)]
pub struct PairResult {
    /// Must match the code the Core prints in its log.
    confirmation_code: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct HeadView {
    seq: u64,
    timestamp_ms: u64,
    head: String,
    valid: bool,
}

#[derive(Debug, Serialize)]
pub struct Dashboard {
    reachable: bool,
    error: Option<String>,
    paired_here: bool,
    /// True when reachable: the TLS handshake refuses any other Core key.
    identity_matches: Option<bool>,
    status: Option<serde_json::Value>,
    events: Vec<serde_json::Value>,
    hosts: Vec<HostInfo>,
    asks: Vec<PendingAsk>,
    heads_total: usize,
    heads_invalid: usize,
    heads: Vec<HeadView>,
}

// Files ----------------------------------------------------------------------

fn data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
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

fn read_hex32(path: &Path) -> Option<[u8; 32]> {
    hex::decode(fs::read_to_string(path).ok()?.trim())
        .ok()?
        .try_into()
        .ok()
}

/// A 32-byte secret stored as hex, created on first use.
fn secret32(dir: &Path, file: &str) -> Result<[u8; 32], String> {
    let path = dir.join(file);
    if let Some(secret) = read_hex32(&path) {
        return Ok(secret);
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    write_private(&path, hex::encode(secret).as_bytes()).map_err(|e| e.to_string())?;
    Ok(secret)
}

fn device_key(dir: &Path) -> Result<ed25519_dalek::SigningKey, String> {
    Ok(ed25519_dalek::SigningKey::from_bytes(&secret32(
        dir,
        "device.key",
    )?))
}

fn owner_key(dir: &Path) -> Result<SigningKey, String> {
    SigningKey::from_slice(&secret32(dir, "owner.key")?)
        .map_err(|_| "owner.key is corrupt".to_owned())
}

fn pinned(dir: &Path) -> Option<CorePublic> {
    serde_json::from_slice(&fs::read(dir.join("pinned.json")).ok()?).ok()
}

fn remembered(dir: &Path) -> Option<Remembered> {
    serde_json::from_slice(&fs::read(dir.join("core.json")).ok()?).ok()
}

fn remember(dir: &Path, core: &Remembered) -> Result<(), String> {
    fs::write(
        dir.join("core.json"),
        serde_json::to_vec(core).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn parse_id(hex_id: &str) -> Result<PeerId, String> {
    hex::decode(hex_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "bad core id".to_owned())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn kind_name(kind: u8) -> String {
    EventKind::from_u8(kind)
        .map(|k| format!("{k:?}"))
        .unwrap_or_else(|| format!("kind {kind}"))
}

// Network --------------------------------------------------------------------

async fn browse() -> Result<Vec<discovery::Found>, String> {
    tokio::task::spawn_blocking(|| discovery::browse(DISCOVERY_WAIT))
        .await
        .map_err(|e| e.to_string())?
}

fn client(dir: &Path) -> Result<quic::Client, String> {
    quic::Client::new(quic::TlsIdentity::from_signing_key(
        &device_key(dir)?,
        "hawk-witness",
    )?)
}

/// Connects to the remembered Core: its last address first, then wherever
/// discovery finds that same identity.
async fn connect(dir: &Path, link: &Link) -> Result<Connection, String> {
    let mut slot = link.conn.lock().await;
    if let Some(conn) = slot.as_ref() {
        if conn.close_reason().is_none() {
            return Ok(conn.clone());
        }
    }
    let mut core = remembered(dir).ok_or("this app is not paired with a Core")?;
    let id = parse_id(&core.id)?;
    let client = client(dir)?;

    if let Some(addr) = core
        .last_addr
        .as_deref()
        .and_then(|a| a.parse::<SocketAddr>().ok())
    {
        if let Ok((conn, _)) = client.connect(addr, Some(id)).await {
            *slot = Some(conn.clone());
            return Ok(conn);
        }
    }
    let found = browse().await?;
    let addr = found
        .iter()
        .find(|f| f.txt.get("id").map(String::as_str) == Some(core.id.as_str()))
        .and_then(|f| f.addrs.first().copied())
        .ok_or("the paired Core is not on this network")?;
    let (conn, _) = client.connect(addr, Some(id)).await?;
    core.last_addr = Some(addr.to_string());
    let _ = remember(dir, &core);
    *slot = Some(conn.clone());
    Ok(conn)
}

async fn call(conn: &Connection, req: &Request) -> Result<Response, String> {
    match quic::request::<_, Response>(conn, req, CALL_TIMEOUT).await? {
        Response::Error { message } => Err(message),
        other => Ok(other),
    }
}

// Commands -------------------------------------------------------------------

#[tauri::command]
pub fn app_info(app: tauri::AppHandle) -> Result<AppInfo, String> {
    let dir = data_dir(&app)?;
    let core = match (remembered(&dir), pinned(&dir)) {
        (Some(core), Some(_)) => {
            let id = parse_id(&core.id)?;
            Some(CoreRef {
                fingerprint: quic::fingerprint(&id),
                id: core.id,
                name: core.name,
            })
        }
        _ => None,
    };
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        core,
        device_fingerprint: quic::fingerprint(&device_key(&dir)?.verifying_key().to_bytes()),
    })
}

/// Cores announcing themselves on the local network.
#[tauri::command]
pub async fn discover() -> Result<Vec<Discovered>, String> {
    let mut out: Vec<Discovered> = browse()
        .await?
        .into_iter()
        .filter_map(|f| {
            let id = f.txt.get("id")?.clone();
            let peer = parse_id(&id).ok()?;
            Some(Discovered {
                fingerprint: quic::fingerprint(&peer),
                name: f
                    .txt
                    .get("name")
                    .cloned()
                    .filter(|n| !n.is_empty())
                    .unwrap_or(f.instance),
                state: f.txt.get("state").cloned().unwrap_or_default(),
                address: f.addrs.first().map(ToString::to_string).unwrap_or_default(),
                id,
            })
        })
        .collect();
    out.sort_by(|a, b| a.state.cmp(&b.state).reverse().then(a.name.cmp(&b.name)));
    Ok(out)
}

/// A Core at an address the owner typed, for networks where discovery does
/// not reach (ADR-0024 v1.1). Nothing is trusted yet: the owner still
/// compares the fingerprint, and pairing pins the key the handshake proved.
#[tauri::command]
pub async fn probe_core(app: tauri::AppHandle, address: String) -> Result<Discovered, String> {
    let dir = data_dir(&app)?;
    let addr = parse_address(&address)?;
    let (conn, id) = client(&dir)?.connect(addr, None).await?;
    // The identity is the key the handshake proved; head keys come only at
    // activation (ADR-0030).
    let (paired, config) = match call(&conn, &Request::Hello).await? {
        Response::Hello { paired, config, .. } => (paired, config),
        other => return Err(format!("unexpected answer: {other:?}")),
    };
    conn.close(0u32.into(), b"probe");
    Ok(Discovered {
        fingerprint: quic::fingerprint(&id),
        name: config.map(|c| c.name).unwrap_or_else(|| "HAWK Core".into()),
        state: if paired { "active" } else { "unpaired" }.into(),
        address: addr.to_string(),
        id: hex::encode(id),
    })
}

/// `ip:port`, or an IP alone with the Core's default port.
fn parse_address(text: &str) -> Result<SocketAddr, String> {
    let text = text.trim();
    text.parse::<SocketAddr>()
        .or_else(|_| {
            text.parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, CORE_PORT))
        })
        .map_err(|_| "type an address like 192.168.88.20 or 192.168.88.20:7443".into())
}

/// The Core's QUIC port when the owner types only an address.
const CORE_PORT: u16 = 7443;

/// Pairs this app with an unpaired Core (ADR-0017). The handshake proves the
/// Core holds the key it announced; the owner's signature covers the Core's
/// identity, the offer nonce and this app's device identity.
#[tauri::command]
pub async fn pair_core(
    app: tauri::AppHandle,
    link: State<'_, Link>,
    id: String,
    address: String,
) -> Result<PairResult, String> {
    let dir = data_dir(&app)?;
    if pinned(&dir).is_some() {
        return Err("this app is already paired with a Core".into());
    }
    let core_id = parse_id(&id)?;
    let addr: SocketAddr = address.parse().map_err(|_| "bad address")?;
    let device = device_key(&dir)?;
    let (conn, _) = client(&dir)?.connect(addr, Some(core_id)).await?;

    let (core_public, nonce) = match call(&conn, &Request::PairOffer).await? {
        Response::Offer { core_public, nonce } => (core_public, nonce),
        other => return Err(format!("unexpected answer: {other:?}")),
    };
    // The head keys the Core generated for this activation (ADR-0030): the
    // owner's signature covers them, and the app pins them for the heads.
    if core_public.ed25519.len() != 32 || core_public.ml_dsa_65.len() != 1952 {
        return Err("the Core offered malformed head keys".into());
    }
    let nonce = hex::decode(&nonce).map_err(|_| "the Core sent a bad nonce")?;
    let owner = owner_key(&dir)?;
    let epoch = secret32(&dir, "epoch.key")?;
    let owner_public = owner.verifying_key().to_encoded_point(true);
    let device_id = device.verifying_key().to_bytes();
    let signature: Signature =
        owner.sign(&pair_message(&nonce, &core_id, &core_public, &device_id));

    let request = Request::Pair {
        owner_public: hex::encode(owner_public.as_bytes()),
        epoch_public: hex::encode(seal::epoch_public(&epoch)),
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    let code = match call(&conn, &request).await? {
        Response::Paired { confirmation_code } => confirmation_code,
        other => return Err(format!("unexpected answer: {other:?}")),
    };
    let expected = confirmation_code(&core_id, &core_public, owner_public.as_bytes());
    if code != expected {
        return Err("confirmation codes differ: someone may be in the middle".into());
    }
    fs::write(
        dir.join("pinned.json"),
        serde_json::to_vec(&core_public).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    remember(
        &dir,
        &Remembered {
            id,
            last_addr: Some(address),
            name: None,
        },
    )?;
    *link.conn.lock().await = Some(conn);
    Ok(PairResult {
        confirmation_code: expected,
        fingerprint: quic::fingerprint(&core_id),
    })
}

/// Names the Core, sets its firewall and the attention thresholds, signed by
/// the owner (ADR-0024, ADR-0033). Without thresholds the active ones stay.
#[tauri::command]
pub async fn configure_core(
    app: tauri::AppHandle,
    link: State<'_, Link>,
    name: String,
    firewall: FirewallConfig,
    thresholds: Option<Thresholds>,
) -> Result<String, String> {
    let dir = data_dir(&app)?;
    let conn = connect(&dir, &link).await?;
    // The next link of the configuration chain (ADR-0027): the active
    // version plus one, naming the active configuration's hash, and keeping
    // the enterprise signer the owner authorised, if any.
    let active = match call(&conn, &Request::Hello).await? {
        Response::Hello { config, .. } => config,
        other => return Err(format!("unexpected answer: {other:?}")),
    };
    let thresholds = thresholds
        .or_else(|| active.as_ref().map(|c| c.thresholds))
        .unwrap_or_default();
    let config = CoreConfig {
        name: name.trim().chars().take(48).collect(),
        firewall,
        version: active.as_ref().map_or(1, |c| c.version + 1),
        prev: active.as_ref().map(|c| c.hash.clone()).unwrap_or_default(),
        enterprise_signer: active.and_then(|c| c.enterprise_signer),
        thresholds,
    };
    if config.name.is_empty() {
        return Err("give the Core a name".into());
    }
    if !config.thresholds.is_valid() {
        return Err(
            "a high finding must at least ask, and asking cannot start above denying".into(),
        );
    }
    let signature: Signature = owner_key(&dir)?.sign(&configure_message(&config));
    let request = Request::Configure {
        config,
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    match call(&conn, &request).await? {
        Response::Configured { config: summary } => {
            if let Some(mut core) = remembered(&dir) {
                core.name = Some(summary.name.clone());
                let _ = remember(&dir, &core);
            }
            Ok(summary.name)
        }
        other => Err(format!("unexpected answer: {other:?}")),
    }
}

/// Asks one host to show its identification notice on its screen.
#[tauri::command]
pub async fn identify_host(
    app: tauri::AppHandle,
    link: State<'_, Link>,
    host: String,
) -> Result<(), String> {
    let dir = data_dir(&app)?;
    let conn = connect(&dir, &link).await?;
    match call(&conn, &Request::Identify { host }).await? {
        Response::Ack => Ok(()),
        other => Err(format!("unexpected answer: {other:?}")),
    }
}

/// Approves a host for this Core with the owner's signature over the Core,
/// the host's daemon identity, the HWID it reports and the time (ADR-0029).
/// The Core then decides for it, and the host pins this Core and owner.
#[tauri::command]
pub async fn approve_host(
    app: tauri::AppHandle,
    link: State<'_, Link>,
    host: String,
    hwid: String,
) -> Result<(), String> {
    let dir = data_dir(&app)?;
    if pinned(&dir).is_none() {
        return Err("this app is not paired with a Core".into());
    }
    // The Core's transport identity, the one the daemons pin.
    let core = parse_id(
        &remembered(&dir)
            .ok_or("this app is not paired with a Core")?
            .id,
    )?;
    let host_id = parse_id(&host)?;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let signature: Signature =
        owner_key(&dir)?.sign(&approve_message(&core, &host_id, &hwid, timestamp_ms));
    let approval = HostApproval {
        core: hex::encode(core),
        host,
        hwid,
        timestamp_ms,
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    let conn = connect(&dir, &link).await?;
    match call(&conn, &Request::ApproveHost { approval }).await? {
        Response::Ack => Ok(()),
        other => Err(format!("unexpected answer: {other:?}")),
    }
}

/// Lifts a host's quarantine with the owner's signature (ADR-0018). `host` is
/// the address that was quarantined, shown in the dashboard.
#[tauri::command]
pub async fn release_host(
    app: tauri::AppHandle,
    link: State<'_, Link>,
    host: String,
) -> Result<(), String> {
    let dir = data_dir(&app)?;
    let conn = connect(&dir, &link).await?;
    let timestamp_ms = now_ms();
    let message = release_message(&host, timestamp_ms);
    let signature: Signature = owner_key(&dir)?.sign(&message);
    let request = Request::Release {
        host,
        timestamp_ms,
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    match call(&conn, &request).await? {
        Response::Ack => Ok(()),
        other => Err(format!("unexpected answer: {other:?}")),
    }
}

/// Answers a pending `ask` (ADR-0022), signed by the owner.
#[tauri::command]
pub async fn answer_ask(
    app: tauri::AppHandle,
    link: State<'_, Link>,
    id: String,
    allow: bool,
) -> Result<(), String> {
    let dir = data_dir(&app)?;
    let conn = connect(&dir, &link).await?;
    let message = answer_message(&id, allow);
    let signature: Signature = owner_key(&dir)?.sign(&message);
    let request = Request::Answer {
        id,
        allow,
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    match call(&conn, &request).await? {
        Response::Ack => Ok(()),
        other => Err(format!("unexpected answer: {other:?}")),
    }
}

/// A decrypted event of the record (ADR-0007).
#[derive(Debug, Serialize)]
pub struct RecordEntryView {
    seq: u64,
    timestamp_ms: u64,
    kind: String,
    content: Option<serde_json::Value>,
}

/// The opened record: whether the chain verified, and the decrypted events.
#[derive(Debug, Serialize)]
pub struct RecordView {
    verified: bool,
    events: Vec<RecordEntryView>,
}

/// Opens the sealed record: the owner's signature covers the range; the app
/// verifies the chain against the last signed head and decrypts each payload
/// with the epoch key (ADR-0006, ADR-0007).
#[tauri::command]
pub async fn open_record(
    app: tauri::AppHandle,
    link: State<'_, Link>,
) -> Result<RecordView, String> {
    let dir = data_dir(&app)?;
    let conn = connect(&dir, &link).await?;

    let heads: Vec<SignedHead> = match call(&conn, &Request::Heads { since: None }).await? {
        Response::Heads { heads } => heads,
        other => return Err(format!("unexpected answer: {other:?}")),
    };
    let last = heads
        .last()
        .cloned()
        .ok_or("the Core has no signed heads yet")?;

    let timestamp_ms = now_ms();
    let message = open_record_message(0, last.seq, timestamp_ms);
    let signature: Signature = owner_key(&dir)?.sign(&message);
    let request = Request::OpenRecord {
        from_seq: 0,
        to_seq: last.seq,
        timestamp_ms,
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    let records: Vec<RecordEvent> = match call(&conn, &request).await? {
        Response::Record { events } => events,
        other => return Err(format!("unexpected answer: {other:?}")),
    };

    // Rebuild the events and verify the chain against the last signed head.
    let mut events = Vec::with_capacity(records.len());
    for record in &records {
        let kind = EventKind::from_u8(record.kind)
            .ok_or_else(|| format!("unknown event kind {}", record.kind))?;
        events.push(Event {
            seq: record.seq,
            timestamp_ms: record.timestamp_ms,
            kind,
            payload: hex::decode(&record.payload).map_err(|_| "bad payload hex")?,
        });
    }
    let verified = verify(&events, last.seq, &last.head).is_ok();

    // Decrypt each payload with the epoch key.
    let epoch = secret32(&dir, "epoch.key")?;
    let entries = records
        .into_iter()
        .map(|record| {
            let payload = hex::decode(&record.payload).unwrap_or_default();
            let content = seal::open(&epoch, &payload)
                .ok()
                .and_then(|plain| serde_json::from_slice(&plain).ok());
            RecordEntryView {
                seq: record.seq,
                timestamp_ms: record.timestamp_ms,
                kind: kind_name(record.kind),
                content,
            }
        })
        .collect();

    Ok(RecordView {
        verified,
        events: entries,
    })
}

/// Forgets the paired Core on this device, to run the wizard again. The
/// keys stay; the Core keeps its pairing until it is reset.
#[tauri::command]
pub async fn forget_core(app: tauri::AppHandle, link: State<'_, Link>) -> Result<(), String> {
    let dir = data_dir(&app)?;
    *link.conn.lock().await = None;
    for file in ["pinned.json", "core.json"] {
        let _ = fs::remove_file(dir.join(file));
    }
    Ok(())
}

/// Everything the dashboard shows, with the signed heads verified against the
/// identity pinned at pairing.
#[tauri::command]
pub async fn dashboard(app: tauri::AppHandle, link: State<'_, Link>) -> Result<Dashboard, String> {
    let dir = data_dir(&app)?;
    let pin = pinned(&dir);
    let unreachable = |error: String| Dashboard {
        reachable: false,
        error: Some(error),
        paired_here: pin.is_some(),
        identity_matches: None,
        status: None,
        events: Vec::new(),
        hosts: Vec::new(),
        asks: Vec::new(),
        heads_total: 0,
        heads_invalid: 0,
        heads: Vec::new(),
    };
    let conn = match connect(&dir, &link).await {
        Ok(conn) => conn,
        Err(err) => return Ok(unreachable(err)),
    };
    let status = match call(&conn, &Request::Status).await {
        Ok(Response::Status { status }) => status,
        Ok(other) => return Ok(unreachable(format!("unexpected answer: {other:?}"))),
        Err(err) => {
            *link.conn.lock().await = None;
            return Ok(unreachable(err));
        }
    };
    let events = match call(&conn, &Request::Events { since: None }).await {
        Ok(Response::Events { events }) => events,
        _ => Vec::new(),
    };
    let hosts = match call(&conn, &Request::Hosts).await {
        Ok(Response::Hosts { hosts }) => hosts,
        _ => Vec::new(),
    };
    let asks = match call(&conn, &Request::PendingAsks).await {
        Ok(Response::Asks { asks }) => asks,
        _ => Vec::new(),
    };
    let heads: Vec<SignedHead> = match call(&conn, &Request::Heads { since: None }).await {
        Ok(Response::Heads { heads }) => heads,
        _ => Vec::new(),
    };

    // Heads are checked against the pinned key, never against what the Core
    // claims now.
    let views: Vec<HeadView> = heads
        .iter()
        .map(|h| HeadView {
            seq: h.seq,
            timestamp_ms: h.timestamp_ms,
            head: hex::encode(h.head),
            valid: pin.as_ref().is_some_and(|p| h.verify(p).is_ok()),
        })
        .collect();
    let invalid = views.iter().filter(|h| !h.valid).count();
    let skip = views.len().saturating_sub(HEADS_SHOWN);

    Ok(Dashboard {
        reachable: true,
        error: None,
        paired_here: pin.is_some(),
        identity_matches: Some(true),
        status: Some(status),
        events,
        hosts,
        asks,
        heads_total: views.len(),
        heads_invalid: invalid,
        heads: views.into_iter().skip(skip).collect(),
    })
}
