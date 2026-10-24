//! Host daemon (ADR-0015). Listens on `HOST_DAEMON_ADDR` (default
//! `127.0.0.1:7070`) for the agent hooks of this machine and relays each
//! request to the Core at `GUARDIAN_URL`.
//!
//! It never decides: it returns the Core's answer, and denies when there is
//! no Core configured, the Core does not answer, or the answer is unusable.

#![forbid(unsafe_code)]

use std::{error::Error as StdError, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use edge_net::http::{json, post_json, read_json, text, Body, Client};
use guardian_core::{Decision, ToolCall};
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_ANSWER_BYTES: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Longer than the owner's 60 s to answer an `ask` (ADR-0022).
const DECIDE_TIMEOUT: Duration = Duration::from_secs(65);

#[derive(Debug, Clone)]
struct Relay {
    core: Option<Arc<CoreLink>>,
}

#[derive(Debug)]
struct CoreLink {
    client: Client,
    decide_url: String,
}

impl Relay {
    fn new(guardian_url: Option<String>) -> Self {
        let core = guardian_url.map(|url| {
            Arc::new(CoreLink {
                client: edge_net::http::client(CONNECT_TIMEOUT),
                decide_url: format!("{}/decide", url.trim_end_matches('/')),
            })
        });
        Self { core }
    }

    async fn decide(&self, call: &ToolCall) -> Decision {
        let Some(core) = &self.core else {
            return Decision::deny("no core configured");
        };
        match post_json::<_, Decision>(
            &core.client,
            &core.decide_url,
            call,
            DECIDE_TIMEOUT,
            MAX_ANSWER_BYTES,
        )
        .await
        {
            Ok(decision) => decision,
            Err(err) => {
                tracing::warn!(?err, "core call failed, denying");
                Decision::deny("core unreachable")
            }
        }
    }
}

async fn handle<B>(relay: Relay, req: Request<B>) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => text(StatusCode::OK, "ok"),
        (&Method::POST, "/decide") => {
            let decision = match read_json::<ToolCall, _>(req, MAX_BODY_BYTES).await {
                Ok(call) => {
                    let decision = relay.decide(&call).await;
                    tracing::info!(session = %call.session, tool = %call.tool, ?decision, "relayed");
                    decision
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
    let relay = Relay::new(std::env::var("GUARDIAN_URL").ok());
    if relay.core.is_none() {
        tracing::warn!("GUARDIAN_URL not set: every request will be denied");
    }

    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "host daemon listening");
    edge_net::http::serve(listener, move |req| handle(relay.clone(), req)).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    const CALL: &[u8] = br#"{"session":"s","tool":"bash","args":{"command":"ls"},"cwd":"/w"}"#;

    async fn ask(relay: Relay, body: &'static [u8]) -> Decision {
        let req = Request::post("/decide")
            .body(Full::new(Bytes::from_static(body)))
            .unwrap();
        let bytes = handle(relay, req)
            .await
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A stand-in Core on a free port that answers every call with `answer`.
    async fn fake_core(answer: Decision) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(edge_net::http::serve(listener, move |_req| {
            let answer = answer.clone();
            async move { json(StatusCode::OK, &answer) }
        }));
        url
    }

    #[tokio::test]
    async fn returns_the_core_answer() {
        let relay = Relay::new(Some(fake_core(Decision::Allow).await));
        assert!(ask(relay, CALL).await.is_allow());
    }

    #[tokio::test]
    async fn denies_without_a_core() {
        assert!(!ask(Relay::new(None), CALL).await.is_allow());
    }

    #[tokio::test]
    async fn denies_when_the_core_is_down() {
        // Bind and drop to get a port nobody listens on.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let relay = Relay::new(Some(format!("http://127.0.0.1:{port}")));
        assert!(!ask(relay, CALL).await.is_allow());
    }

    #[tokio::test]
    async fn denies_malformed_calls() {
        let relay = Relay::new(Some(fake_core(Decision::Allow).await));
        assert!(!ask(relay, b"{nope").await.is_allow());
    }
}
