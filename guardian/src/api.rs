//! HTTP surface of the Core: the decision endpoint for host daemons, pairing
//! for the phone, and read-only views for the witness dashboard.
//!
//! Every path out of `/decide` that is not an explicit `Allow` from the
//! detector, recorded in the chain, is a denial (fail closed, ADR-0003,
//! ADR-0022). An unpaired Core denies everything (ADR-0017).

use std::{
    error::Error as StdError,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use detect::Detector;
use edge_net::http::{json, read_json, text, Body};
use guardian_core::{Decision, ToolCall};
use hyper::{Method, Request, Response, StatusCode};
use integrations::{sinks::Publisher, Firewall, SinkEvent};

use crate::core::{Core, CoreError, PairRequest};

/// Largest request accepted. Checked before parsing.
const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct AppState {
    core: Arc<Core>,
    firewall: Arc<dyn Firewall>,
    publisher: Publisher,
    detector: Arc<Mutex<Detector>>,
}

impl AppState {
    pub fn new(
        core: Core,
        detector: Detector,
        firewall: Box<dyn Firewall>,
        publisher: Publisher,
    ) -> Self {
        Self {
            core: Arc::new(core),
            firewall: Arc::from(firewall),
            publisher,
            detector: Arc::new(Mutex::new(detector)),
        }
    }
}

/// `since=N` from the query string, if present and numeric.
fn since(query: Option<&str>) -> Option<u64> {
    query?
        .split('&')
        .find_map(|pair| pair.strip_prefix("since="))
        .and_then(|v| v.parse().ok())
}

fn core_error(err: &CoreError) -> Response<Body> {
    let status = match err {
        CoreError::AlreadyPaired => StatusCode::CONFLICT,
        CoreError::BadPairing(_) => StatusCode::BAD_REQUEST,
        CoreError::NotPaired => StatusCode::PRECONDITION_FAILED,
        CoreError::Io(_) | CoreError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json(status, &serde_json::json!({ "error": err.to_string() }))
}

pub async fn handle<B>(state: AppState, req: Request<B>) -> Response<Body>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let query = req.uri().query().map(str::to_owned);
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => text(StatusCode::OK, "ok"),
        (&Method::POST, "/decide") => {
            let peer = edge_net::http::peer(&req).map(|p| p.ip());
            let decision = match read_json::<ToolCall, _>(req, MAX_BODY_BYTES).await {
                Ok(call) => decide(&state, &call, peer).await,
                Err(_) => Decision::deny("malformed tool call"),
            };
            json(StatusCode::OK, &decision)
        }
        (&Method::GET, "/pair") => match state.core.pair_offer() {
            Ok(offer) => json(StatusCode::OK, &offer),
            Err(err) => core_error(&err),
        },
        (&Method::POST, "/pair") => match read_json::<PairRequest, _>(req, MAX_BODY_BYTES).await {
            Ok(request) => match state.core.pair(&request) {
                Ok(code) => {
                    tracing::info!(%code, "paired; confirm this code on the phone");
                    json(
                        StatusCode::OK,
                        &serde_json::json!({ "confirmation_code": code }),
                    )
                }
                Err(err) => core_error(&err),
            },
            Err(_) => text(StatusCode::BAD_REQUEST, "malformed pairing request"),
        },
        (&Method::GET, "/identity") => json(StatusCode::OK, state.core.public()),
        (&Method::GET, "/status") => match state.core.status() {
            Ok(status) => json(StatusCode::OK, &status),
            Err(err) => core_error(&err),
        },
        (&Method::GET, "/heads") => match state.core.heads_since(since(query.as_deref())) {
            Ok(heads) => json(StatusCode::OK, &heads),
            Err(err) => core_error(&err),
        },
        (&Method::GET, "/events") => match state.core.events_since(since(query.as_deref())) {
            Ok(events) => json(StatusCode::OK, &events),
            Err(err) => core_error(&err),
        },
        _ => text(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn decide(state: &AppState, call: &ToolCall, peer: Option<std::net::IpAddr>) -> Decision {
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
    // The host to contain is the TCP peer of this request (never a value the
    // client declares), so a host cannot get another one quarantined.
    let host = peer.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
    state.publisher.send(SinkEvent {
        family: "decisions",
        seq: meta.seq,
        timestamp_ms: meta.timestamp_ms,
        key: host.clone(),
        body: serde_json::to_value(&meta).unwrap_or_default(),
    });
    if verdict.contain {
        contain(state, peer, &meta).await;
    }
    verdict.decision
}

/// Quarantines the host on the network firewall and records the outcome.
/// A failed cut raises an alert event; the decision itself stays a denial.
async fn contain(
    state: &AppState,
    peer: Option<std::net::IpAddr>,
    trigger: &crate::core::EventMeta,
) {
    let reason = trigger
        .reason
        .clone()
        .unwrap_or_else(|| "critical finding".into());
    let (kind_note, ok) = match peer {
        Some(ip) => match state.firewall.quarantine(ip, &reason).await {
            Ok(()) => ("contained", true),
            Err(err) => {
                tracing::error!(%err, %ip, "containment failed");
                ("containment_failed", false)
            }
        },
        None => ("containment_failed", false),
    };
    let meta = crate::core::EventMeta {
        kind: "containment",
        host: peer.map(|p| p.to_string()),
        severity: Some(guardian_core::Severity::Critical),
        reason: Some(format!("{kind_note}: {reason}")),
        ..crate::core::EventMeta::empty()
    };
    let content = serde_json::json!({
        "firewall": state.firewall.name(),
        "host": peer.map(|p| p.to_string()),
        "ok": ok,
        "trigger_seq": trigger.seq,
    });
    match state
        .core
        .record(guardian_core::EventKind::Contained, meta, &content, true)
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
    use crate::core::tests::{pair, TempDir};
    use http_body_util::{BodyExt, Full};

    const CALL: &str = r#"{"session":"s","tool":"bash","args":{"command":"ls"},"cwd":"/w"}"#;

    fn state(dir: &TempDir) -> AppState {
        AppState::new(
            Core::open(&dir.0).unwrap(),
            Detector::new(),
            Box::new(integrations::dry_run::DryRun::default()),
            Publisher::none(),
        )
    }

    async fn send(state: &AppState, req: Request<Full<Bytes>>) -> (StatusCode, Bytes) {
        let response = handle(state.clone(), req).await;
        let status = response.status();
        (
            status,
            response.into_body().collect().await.unwrap().to_bytes(),
        )
    }

    async fn decide_json(state: &AppState, body: &'static str) -> Decision {
        let req = Request::post("/decide")
            .body(Full::new(Bytes::from_static(body.as_bytes())))
            .unwrap();
        serde_json::from_slice(&send(state, req).await.1).unwrap()
    }

    #[tokio::test]
    async fn health_and_unknown_paths() {
        let dir = TempDir::new("api-health");
        let s = state(&dir);
        let get = |p: &'static str| Request::get(p).body(Full::default()).unwrap();
        assert_eq!(send(&s, get("/health")).await.0, StatusCode::OK);
        assert_eq!(send(&s, get("/nope")).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unpaired_core_denies_and_offers_pairing() {
        let dir = TempDir::new("api-unpaired");
        let s = state(&dir);
        assert!(!decide_json(&s, CALL).await.is_allow());
        let (status, _) = send(&s, Request::get("/pair").body(Full::default()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn paired_core_allows_records_and_stops_offering() {
        let dir = TempDir::new("api-paired");
        let s = state(&dir);
        pair(&s.core);
        assert!(decide_json(&s, CALL).await.is_allow());
        assert!(!decide_json(&s, "{not json").await.is_allow());

        let (status, _) = send(&s, Request::get("/pair").body(Full::default()).unwrap()).await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (_, body) = send(
            &s,
            Request::get("/events?since=0")
                .body(Full::default())
                .unwrap(),
        )
        .await;
        let events: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(events.as_array().unwrap().len(), 1);
        assert_eq!(events[0]["decision"], "allow");
    }

    #[test]
    fn since_parses_the_query() {
        assert_eq!(since(Some("since=7")), Some(7));
        assert_eq!(since(Some("a=1&since=3")), Some(3));
        assert_eq!(since(Some("since=x")), None);
        assert_eq!(since(None), None);
    }

    use detect::Rule;
    use guardian_core::{Finding, Severity};
    use integrations::{dry_run::DryRun, BoxFuture, FirewallError};

    #[derive(Debug)]
    struct Critical;

    impl Rule for Critical {
        fn check(&self, call: &ToolCall) -> Option<Finding> {
            call.args["command"]
                .as_str()?
                .contains("EXFIL")
                .then(|| Finding {
                    rule: "test.critical".into(),
                    severity: Severity::Critical,
                    reason: "test".into(),
                })
        }
    }

    /// Shares one `DryRun` between the test and the state.
    #[derive(Debug)]
    struct Shared(Arc<DryRun>);

    impl Firewall for Shared {
        fn name(&self) -> &'static str {
            "shared-dry-run"
        }
        fn quarantine<'a>(
            &'a self,
            host: std::net::IpAddr,
            reason: &'a str,
        ) -> BoxFuture<'a, Result<(), FirewallError>> {
            self.0.quarantine(host, reason)
        }
        fn release(&self, host: std::net::IpAddr) -> BoxFuture<'_, Result<(), FirewallError>> {
            self.0.release(host)
        }
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

    #[tokio::test]
    async fn a_critical_finding_denies_and_quarantines_the_peer() {
        let dir = TempDir::new("api-contain");
        let firewall = Arc::new(DryRun::default());
        let s = AppState::new(
            Core::open(&dir.0).unwrap(),
            Detector::with_rules(vec![Box::new(Critical)]),
            Box::new(Shared(Arc::clone(&firewall))),
            Publisher::none(),
        );
        pair(&s.core);
        let peer: std::net::IpAddr = "10.0.0.7".parse().unwrap();

        assert!(decide(&s, &bash("ls"), Some(peer)).await.is_allow());
        assert!(!firewall.is_quarantined(peer));

        let decision = decide(&s, &bash("EXFIL"), Some(peer)).await;
        assert!(!decision.is_allow());
        assert!(firewall.is_quarantined(peer));

        let kinds: Vec<_> = s
            .core
            .events_since(None)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert!(kinds.contains(&"containment"));
    }
}
