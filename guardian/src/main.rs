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
mod asks;
mod core;
mod crosscheck;
mod enrolment;
mod heartbeat;
mod hosts;
mod neighbors;

const DEFAULT_ADDR: &str = "0.0.0.0:7443";

fn announce(core: &core::Core, port: u16) -> Option<discovery::Announcement> {
    let id = core.id();
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

/// Creates the enterprise signer's key pair (ADR-0027). The private key goes
/// to the pipeline's secret store; the public key goes into a configuration
/// the owner signs from the app.
#[allow(clippy::print_stdout)] // The command's purpose is to print for the operator.
fn config_keygen() -> Result<(), Box<dyn std::error::Error>> {
    let key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let output = serde_json::json!({
        "private_key": hex::encode(key.to_bytes()),
        "public_key": hex::encode(key.verifying_key().to_encoded_point(true).as_bytes()),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Signs `config.json` (a `CoreConfig` with the next `version` and `prev`)
/// with the enterprise signer's key and prints the `SignedConfig` to publish.
#[allow(clippy::print_stdout)] // The command's purpose is to print the signed document.
fn config_sign(key_file: &str, config_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    use p256::ecdsa::{signature::Signer as _, Signature};
    let key_hex = std::fs::read_to_string(key_file)?;
    let key = p256::ecdsa::SigningKey::from_slice(&hex::decode(key_hex.trim())?)?;
    let config: guardian_core::wire::CoreConfig =
        serde_json::from_slice(&std::fs::read(config_file)?)?;
    if config.has_secrets() {
        return Err("a remote configuration must not carry router secrets".into());
    }
    let signature: Signature = key.sign(&guardian_core::wire::configure_message(&config));
    let signed = guardian_core::wire::SignedConfig {
        config,
        signature: hex::encode(signature.to_der().as_bytes()),
    };
    println!("{}", serde_json::to_string_pretty(&signed)?);
    Ok(())
}

// The probe's purpose is to print for the operator.
#[allow(clippy::print_stdout)]
async fn probe(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = tokio::net::lookup_host(addr)
        .await?
        .next()
        .ok_or("could not resolve the core address")?;
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
    match args.get(1).map(String::as_str) {
        Some("config-keygen") => return config_keygen(),
        Some("config-sign") => {
            let (Some(key), Some(file)) = (args.get(2), args.get(3)) else {
                return Err("usage: guardian config-sign <private-key-file> <config.json>".into());
            };
            return config_sign(key, file);
        }
        _ => {}
    }
    if args.get(1).map(String::as_str) == Some("probe") {
        let addr = args.get(2).map_or("127.0.0.1:7443", String::as_str);
        return probe(addr).await;
    }

    let addr: SocketAddr = std::env::var("GUARDIAN_ADDR")
        .unwrap_or_else(|_| DEFAULT_ADDR.into())
        .parse()?;
    let data_dir = std::env::var("GUARDIAN_DATA_DIR").unwrap_or_else(|_| "guardian-data".into());
    let core = core::Core::open(&data_dir)?;
    let identity = quic::TlsIdentity::from_signing_key(core.transport_key(), "hawk-core")?;

    // The fingerprint the owner compares in the activation wizard.
    tracing::warn!(fingerprint = %quic::fingerprint(&identity.peer_id), "core identity");
    if !core.is_paired() {
        tracing::warn!("core NOT paired: every decision is denied until the app activates it");
    }

    // Off-site archive of every signed batch (ADR-0026), when configured.
    if let Some(config) = integrations::archive::ArchiveConfig::from_env() {
        match integrations::archive::Archiver::start(&config) {
            Ok(archiver) => {
                tracing::info!(bucket = %config.bucket, endpoint = %config.endpoint, "archiving batches off-site");
                core.set_archiver(archiver);
            }
            Err(err) => tracing::error!(%err, "archive disabled"),
        }
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

    // Rules always run. The familiarity stage (ADR-0036) is opt-in: it
    // default-denies unfamiliar shell commands, so it stays off unless the
    // owner turns it on (the demo Core and the installer set HAWK_CLASSIFIER).
    let mut rules = detect::catalogue::builtin();
    if std::env::var("HAWK_CLASSIFIER").is_ok_and(|v| v == "1" || v == "familiarity") {
        tracing::info!("familiarity classifier stage enabled (ADR-0036)");
        rules.push(Box::new(detect::Familiarity::builtin()));
    }
    let state = api::AppState::new(
        core,
        detect::Detector::with_rules(rules),
        firewall,
        publisher,
        announcer,
    );
    // Evict proposals that were never matched by a hook decide (ADR-0004).
    let sweeper = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            sweeper.sweep_expired().await;
        }
    });
    // Challenge hosts and quarantine the silent ones (ADR-0021).
    let beater = state.clone();
    tokio::spawn(async move {
        loop {
            beater.heartbeat_round().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    tracing::info!(%addr, "core listening (QUIC)");
    // Enterprise edition (ADR-0027): configuration published remotely and
    // signed by the enterprise signer the owner authorised. Off by default:
    // the Core runs fully offline.
    if let Some(settings) = integrations::remote_config::RemoteConfigSettings::from_env() {
        match integrations::remote_config::RemoteConfig::new(&settings) {
            Ok(remote) => {
                tracing::info!(key = %settings.key, every_secs = settings.poll_secs, "remote configuration enabled");
                tokio::spawn(api::poll_remote_config(
                    state.clone(),
                    remote,
                    settings.poll_secs,
                ));
            }
            Err(err) => tracing::error!(%err, "remote configuration disabled"),
        }
    }

    let hook = state.clone();
    quic::serve_with(
        endpoint,
        move |peer, conn| hook.on_connect(peer, conn),
        move |peer, from, req| api::handle(state.clone(), peer, from, req),
    )
    .await;
    Ok(())
}
