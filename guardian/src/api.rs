//! HTTP surface for the host daemons (ADR-0015).
//!
//! Every path out of `/decide` that is not an explicit `Allow` from the
//! detector is a denial: a malformed body, an oversized body or a poisoned
//! lock all end in `deny` (fail closed, ADR-0003).

use std::{
    error::Error as StdError,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use detect::Detector;
use edge_net::http::{json, read_json, text, Body};
use guardian_core::{Decision, ToolCall};
use hyper::{Method, Request, Response, StatusCode};

/// Largest request a daemon may send. Checked before parsing.
const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Default)]
pub struct AppState {
    detector: Arc<Mutex<Detector>>,
}

pub async fn handle<B>(state: AppState, req: Request<B>) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => text(StatusCode::OK, "ok"),
        (&Method::POST, "/decide") => {
            let decision = match read_json::<ToolCall, _>(req, MAX_BODY_BYTES).await {
                Ok(call) => decide(&state, &call),
                Err(_) => Decision::deny("malformed tool call"),
            };
            json(StatusCode::OK, &decision)
        }
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

fn decide(state: &AppState, call: &ToolCall) -> Decision {
    let decision = match state.detector.lock() {
        Ok(mut detector) => detector.decide(call),
        Err(_) => Decision::deny("detector unavailable"),
    };
    tracing::info!(session = %call.session, tool = %call.tool, ?decision, "decided");
    decision
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    async fn call(req: Request<Full<Bytes>>) -> Response<Body> {
        handle(AppState::default(), req).await
    }

    async fn post_decide(body: &'static str) -> Decision {
        let response = call(
            Request::post("/decide")
                .body(Full::new(Bytes::from_static(body.as_bytes())))
                .unwrap(),
        )
        .await;
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_answers() {
        let response = call(Request::get("/health").body(Full::default()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_path_is_not_found() {
        let response = call(Request::get("/nope").body(Full::default()).unwrap()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn malformed_call_is_denied() {
        assert!(!post_decide("{not json").await.is_allow());
    }

    #[tokio::test]
    async fn valid_call_gets_a_decision() {
        let decision =
            post_decide(r#"{"session":"s","tool":"bash","args":{"command":"ls"},"cwd":"/w"}"#)
                .await;
        assert!(matches!(decision, Decision::Deny { .. }));
    }
}
