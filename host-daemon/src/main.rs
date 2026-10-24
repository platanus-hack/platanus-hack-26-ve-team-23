//! Host daemon (ADR-0015). Listens on `HOST_DAEMON_ADDR` (default
//! `127.0.0.1:7070`) for the agent hooks of this machine.
//!
//! It never decides. Until forwarding to the Core is implemented, every
//! request is answered with deny, as it would be if the Core were down.

#![forbid(unsafe_code)]

use std::{error::Error as StdError, net::SocketAddr};

use bytes::Bytes;
use edge_net::http::{json, read_json, text, Body};
use guardian_core::{Decision, ToolCall};
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const MAX_BODY_BYTES: usize = 256 * 1024;

async fn handle<B>(req: Request<B>) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => text(StatusCode::OK, "ok"),
        (&Method::POST, "/decide") => {
            let decision = match read_json::<ToolCall, _>(req, MAX_BODY_BYTES).await {
                Ok(call) => {
                    tracing::info!(session = %call.session, tool = %call.tool, "no core configured, denying");
                    Decision::deny("core unreachable")
                }
                Err(_) => Decision::deny("malformed tool call"),
            };
            json(StatusCode::OK, &decision)
        }
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // Loopback by default: only processes on this machine reach the daemon.
    let addr: SocketAddr = std::env::var("HOST_DAEMON_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7070".into())
        .parse()?;

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "host daemon listening");
    edge_net::http::serve(listener, handle).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    #[tokio::test]
    async fn denies_without_a_core() {
        let response = handle(
            Request::post("/decide")
                .body(Full::new(Bytes::from_static(
                    br#"{"session":"s","tool":"bash","args":{},"cwd":"/w"}"#,
                )))
                .unwrap(),
        )
        .await;
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let decision: Decision = serde_json::from_slice(&bytes).unwrap();
        assert!(!decision.is_allow());
    }
}
