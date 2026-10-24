//! The Core: the Guardian daemon on the Raspberry Pi. Listens on
//! `GUARDIAN_ADDR` (default `0.0.0.0:8080`) and keeps its state in
//! `GUARDIAN_DATA_DIR` (default `./guardian-data`).

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

mod api;
mod core;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let addr: SocketAddr = std::env::var("GUARDIAN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let data_dir = std::env::var("GUARDIAN_DATA_DIR").unwrap_or_else(|_| "guardian-data".into());

    let core = core::Core::open(&data_dir)?;
    tracing::info!(
        ed25519 = %hex::encode(&core.public().ed25519),
        "core identity (Ed25519 + ML-DSA-65)"
    );
    if core.is_paired() {
        tracing::info!(%data_dir, "core paired and active");
    } else {
        let offer = core.pair_offer()?;
        tracing::warn!(
            nonce = %offer.nonce,
            "core NOT paired: every decision is denied until a phone pairs via GET/POST /pair"
        );
    }

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "guardian listening");
    let firewall = integrations::firewall_from_env();
    tracing::info!(firewall = firewall.name(), "firewall adapter");
    let publisher =
        integrations::sinks::Publisher::start(integrations::sinks::sinks_from_env().await);
    let state = api::AppState::new(core, detect::Detector::new(), firewall, publisher);
    edge_net::http::serve(listener, move |req| api::handle(state.clone(), req)).await;
    Ok(())
}
