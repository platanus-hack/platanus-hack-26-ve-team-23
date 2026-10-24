//! OpenAI-compatible proxy between the agent and Ollama (ADR-0004). It
//! forwards each request upstream, streams the answer back unchanged, and
//! hands the caller a `ProxyRecord` (request, response and the tool calls the
//! model proposed) to relay to the Core for the cross-check.
//!
//! The proxy never changes the model's answer: it records, the hook enforces
//! (ADR-0004). A request that fails to parse is still forwarded and still
//! recorded; nothing is dropped because it could not be understood.

#![forbid(unsafe_code)]

pub mod extract;

use std::{
    error::Error as StdError,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use edge_net::http::{BoxBody, Client};
use futures_util::stream;
use guardian_core::wire::ProxyRecord;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    body::{Body as HttpBody, Frame, Incoming},
    header, Request, Response,
};
use serde_json::Value;

/// Largest request or response body the proxy buffers (prompts and tool
/// definitions are large; a cap still bounds memory).
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Where the proxy forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Base URL of Ollama on the PC, for example `http://127.0.0.1:11434`.
    pub upstream: String,
}

/// Called once the response has been sent downstream, with the record to
/// relay to the Core. Must not block: it spawns the send.
pub type RecordSink = Arc<dyn Fn(ProxyRecord) + Send + Sync>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A buffered body over bytes, boxed so it matches the streaming body type.
fn buffered(bytes: Bytes) -> BoxBody {
    BoxBody::new(
        Full::new(bytes).map_err(|err| -> Box<dyn StdError + Send + Sync> { match err {} }),
    )
}

/// An OpenAI-compatible forwarder. The inner client is pooled and `Clone`, so
/// one instance serves every connection.
#[derive(Debug, Clone)]
pub struct Proxy {
    client: Client,
    upstream: String,
}

impl Proxy {
    pub fn new(config: ProxyConfig, connect_timeout: Duration) -> Self {
        Self {
            client: edge_net::http::client(connect_timeout),
            upstream: config.upstream.trim_end_matches('/').to_owned(),
        }
    }

    /// Whether this request should be forwarded upstream (ADR-0004).
    pub fn accepts(path: &str) -> bool {
        path.starts_with("/v1/") || path.starts_with("/api/")
    }

    /// Chat-completion paths, whose response proposes tool calls.
    fn extracts(path: &str) -> bool {
        path == "/v1/chat/completions" || path == "/api/chat"
    }

    /// Forwards `req` upstream and returns the answer. When the whole response
    /// has been consumed downstream, `sink` is called with the `ProxyRecord`.
    pub async fn forward<B>(
        &self,
        req: Request<B>,
        sink: RecordSink,
    ) -> Result<Response<BoxBody>, String>
    where
        B: HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        let path = req.uri().path().to_owned();
        let query = req
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        let request_bytes = read_body(req.into_body()).await?;
        let request = parse_json(&request_bytes);
        let streaming = request
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let upstream = self.upstream_request(&path, &query, &request_bytes)?;
        let upstream_response = self
            .client
            .request(upstream)
            .await
            .map_err(|e| format!("upstream: {e}"))?;

        let status = upstream_response.status();
        let headers = upstream_response.headers().clone();
        let body = upstream_response.into_body();

        // Non-streaming: buffer the answer, extract, forward it complete.
        if !streaming {
            let bytes = read_body(body).await?;
            let tool_calls = if Self::extracts(&path) {
                extract::tool_calls_from_response(&parse_json(&bytes))
            } else {
                Vec::new()
            };
            let response = response_value(&path, &bytes);
            sink(ProxyRecord {
                timestamp_ms: now_ms(),
                path,
                request,
                response: Some(response),
                tool_calls,
            });
            let mut response = Response::new(buffered(bytes));
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            return Ok(response);
        }

        // Streaming chat completion: tee the SSE body downstream while a copy
        // is accumulated; the record is emitted when the stream ends.
        let buffer = Arc::new(Mutex::new(Vec::<u8>::new()));
        let state = Tee {
            body,
            buffer: Arc::clone(&buffer),
            path,
            request,
            sink,
        };
        let teed = stream::unfold(state, |mut state| async move {
            match state.body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        state
                            .buffer
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .extend_from_slice(data);
                    }
                    Some((
                        Ok::<Frame<Bytes>, Box<dyn StdError + Send + Sync>>(frame),
                        state,
                    ))
                }
                Some(Err(err)) => Some((
                    Err::<Frame<Bytes>, Box<dyn StdError + Send + Sync>>(Box::new(err)),
                    state,
                )),
                None => {
                    finalize(&state.buffer, &state.path, &state.request, &state.sink);
                    None
                }
            }
        });

        let mut response = Response::new(BoxBody::new(StreamBody::new(teed)));
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }

    fn upstream_request(
        &self,
        path: &str,
        query: &str,
        body: &[u8],
    ) -> Result<Request<Full<Bytes>>, String> {
        let url = format!("{}{path}{query}", self.upstream);
        Request::post(&url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| format!("request: {e}"))
    }
}

struct Tee {
    body: Incoming,
    buffer: Arc<Mutex<Vec<u8>>>,
    path: String,
    request: Value,
    sink: RecordSink,
}

fn finalize(buffer: &Mutex<Vec<u8>>, path: &str, request: &Value, sink: &RecordSink) {
    let bytes = buffer.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let tool_calls = extract::tool_calls_from_sse(&text);
    sink(ProxyRecord {
        timestamp_ms: now_ms(),
        path: path.to_owned(),
        request: request.clone(),
        response: Some(Value::String(text)),
        tool_calls,
    });
}

/// The response as it is recorded: parsed JSON for chat responses, the raw
/// text otherwise.
fn response_value(path: &str, bytes: &[u8]) -> Value {
    if Proxy::extracts(path) {
        parse_json(bytes)
    } else {
        Value::String(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Reads a body up to `MAX_BODY_BYTES`.
async fn read_body<B>(body: B) -> Result<Bytes, String>
where
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    http_body_util::Limited::new(body, MAX_BODY_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|e| format!("body: {e}"))
}

fn parse_json(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

pub use extract::{tool_calls_from_response, tool_calls_from_sse};

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    /// A tiny upstream that answers a fixed body, recording what it received.
    async fn upstream(response_body: &'static [u8], seen: Arc<Mutex<Vec<u8>>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let seen = Arc::clone(&seen);
                        async move {
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            seen.lock().unwrap().extend_from_slice(&body);
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                response_body,
                            ))))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    fn sink_recorder() -> (RecordSink, Arc<Mutex<Vec<ProxyRecord>>>) {
        let records = Arc::new(Mutex::new(Vec::new()));
        let sink: RecordSink = {
            let records = Arc::clone(&records);
            Arc::new(move |record| records.lock().unwrap().push(record))
        };
        (sink, records)
    }

    fn chat_request(body: &str) -> Request<Full<Bytes>> {
        Request::post("/v1/chat/completions")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_owned())))
            .unwrap()
    }

    #[tokio::test]
    async fn forwards_and_extracts_non_streaming_tool_calls() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let upstream = upstream(
            br#"{"choices":[{"message":{"tool_calls":[{"id":"call_1","function":{"name":"bash","arguments":"{\"command\":\"ls\"}"}}]}}]}"#,
            Arc::clone(&seen),
        )
        .await;
        let proxy = Proxy::new(ProxyConfig { upstream }, Duration::from_secs(5));
        let (sink, records) = sink_recorder();

        let response = proxy
            .forward(chat_request(r#"{"model":"qwen","messages":[]}"#), sink)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("call_1"));

        let seen = seen.lock().unwrap();
        assert_eq!(&*seen, br#"{"model":"qwen","messages":[]}"#);

        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].path, "/v1/chat/completions");
        assert_eq!(records[0].tool_calls.len(), 1);
        assert_eq!(records[0].tool_calls[0].id, "call_1");
    }

    #[tokio::test]
    async fn streams_sse_and_extracts_accumulated_tool_calls() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"function\":{\"name\":\"bash\",\"arguments\":\"\"}}]}}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"command\\\":\\\"ls\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: [DONE]\n",
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let upstream = upstream(sse.as_bytes(), Arc::clone(&seen)).await;
        let proxy = Proxy::new(ProxyConfig { upstream }, Duration::from_secs(5));
        let (sink, records) = sink_recorder();

        let response = proxy
            .forward(
                chat_request(r#"{"model":"qwen","messages":[],"stream":true}"#),
                sink,
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("finish_reason"));

        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tool_calls.len(), 1);
        assert_eq!(records[0].tool_calls[0].id, "call_9");
        assert_eq!(records[0].tool_calls[0].arguments["command"], "ls");
    }
}
