//! The Core: the Guardian daemon on the Raspberry Pi. Listens on
//! `GUARDIAN_ADDR` (default `0.0.0.0:8080`).

#![forbid(unsafe_code)]

use std::net::SocketAddr;

use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

mod api;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let addr: SocketAddr = std::env::var("GUARDIAN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "guardian listening");
    let state = api::AppState::default();
    edge_net::http::serve(listener, move |req| api::handle(state.clone(), req)).await;
    Ok(())
}
