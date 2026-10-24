//! The Core: the Guardian daemon on the Raspberry Pi.
//!
//! Serves QUIC with mutual TLS on `GUARDIAN_ADDR` (UDP, default
//! `0.0.0.0:7443`), announces itself on the local network (ADR-0024) and
//! keeps its state in `GUARDIAN_DATA_DIR` (default `./guardian-data`).
//! There is no HTTP endpoint (ADR-0023).
//!
//! `guardian probe [ADDR]` connects to a Core as a throwaway client and
//! prints its hello: used by the smoke test and to check a Core from a shell.

#![forbid(unsafe_code)]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use edge_net::{discovery, quic};
use guardian_core::wire::{Request, Response};
use tracing_subscriber::EnvFilter;

mod api;
mod core;
mod hosts;

const DEFAULT_ADDR: &str = "0.0.0.0:7443";

fn announce(core: &core::Core, port: u16) -> Option<discovery::Announcement> {
    let id = &core.public().ed25519;
    let state = if core.is_paired() {
        "active"
    } else {
        "unpaired"
    };
    let name = core.config().map(|c| c.name).unwrap_or_default();
    let instance = format!("hawk-{}", hex::encode(&id[..6]));
    match discovery::announce(
        &instance,
        port,
        &[
            ("id", hex::encode(id)),
            ("state", state.into()),
            ("name", name),
            ("v", "1".into()),
        ],
    ) {
        Ok(handle) => Some(handle),
        Err(err) => {
            tracing::warn!(%err, "mDNS announcement failed; the app can still connect by address");
            None
        }
    }
}

// The probe's purpose is to print for the operator.
#[allow(clippy::print_stdout)]
async fn probe(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = addr.parse()?;
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let client = quic::Client::new(quic::TlsIdentity::from_signing_key(&key, "hawk-probe")?)?;
    let (conn, id) = client.connect(addr, None).await?;
    let hello: Response = quic::request(&conn, &Request::Hello, Duration::from_secs(5)).await?;
    println!("core {} at {addr}", quic::fingerprint(&id));
    println!("{}", serde_json::to_string_pretty(&hello)?);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("probe") {
        let addr = args.get(2).map_or("127.0.0.1:7443", String::as_str);
        return probe(addr).await;
    }

    let addr: SocketAddr = std::env::var("GUARDIAN_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.into())
        .parse()?;
    let data_dir = std::env::var("GUARDIAN_DATA_DIR").unwrap_or_else(|_| "guardian-data".into());
    let core = core::Core::open(&data_dir)?;
    let identity = quic::TlsIdentity::from_signing_key(core.keys().transport_key(), "hawk-core")?;

    // The fingerprint the owner compares in the activation wizard.
    tracing::warn!(fingerprint = %quic::fingerprint(&identity.peer_id), "core identity");
    if !core.is_paired() {
        tracing::warn!("core NOT paired: every decision is denied until the app activates it");
    }

    let firewall = match core.config() {
        Some(config) => api::firewall_from_config(&config.firewall),
        None => Arc::from(integrations::firewall_from_env()),
    };
    tracing::info!(firewall = firewall.name(), "firewall adapter");
    let publisher =
        integrations::sinks::Publisher::start(integrations::sinks::sinks_from_env().await);

    let endpoint = quic::server(&identity, addr)?;
    let port = endpoint.local_addr()?.port();
    let announcement = Arc::new(Mutex::new(announce(&core, port)));
    let announcer: api::Announcer = {
        let announcement = Arc::clone(&announcement);
        Arc::new(move |core: &core::Core| {
            if let Ok(mut slot) = announcement.lock() {
                // Drop the old record before registering the new state.
                slot.take();
                *slot = announce(core, port);
            }
        })
    };

    let state = api::AppState::new(
        core,
        detect::Detector::new(),
        firewall,
        publisher,
        announcer,
    );
    tracing::info!(%addr, "core listening (QUIC)");
    let hook = state.clone();
    quic::serve_with(
        endpoint,
        move |peer, conn| hook.on_connect(peer, conn),
        move |peer, from, req| api::handle(state.clone(), peer, from, req),
    )
    .await;
    Ok(())
}
