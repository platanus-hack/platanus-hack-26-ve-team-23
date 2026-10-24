//! A minimal HTTP/1.1 server on hyper and tokio: our accept loop, one task
//! per connection, a header read timeout, and capped JSON bodies.

use std::{convert::Infallible, error::Error as StdError, future::Future, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{header, server::conn::http1, service::service_fn, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{de::DeserializeOwned, Serialize};
use tokio::net::TcpListener;

/// Response body used by every handler.
pub type Body = Full<Bytes>;

/// A client that does not send its headers within this time is dropped.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Accepts connections forever, serving each on its own task. Accept errors
/// (for example, out of file descriptors) are logged and retried after a
/// short pause instead of stopping the server.
pub async fn serve<H, F>(listener: TcpListener, handler: H)
where
    H: Fn(Request<hyper::body::Incoming>) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Response<Body>> + Send + 'static,
{
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                tracing::warn!(%err, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let response = handler(req);
                async move { Ok::<_, Infallible>(response.await) }
            });
            let result = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await;
            if let Err(err) = result {
                tracing::debug!(%peer, %err, "connection ended with an error");
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// Larger than the cap, or the connection failed while reading.
    Unreadable,
    /// Not valid JSON for the expected type.
    Malformed,
}

/// Reads at most `max_bytes` of the body, then parses it as JSON.
pub async fn read_json<T, B>(req: Request<B>, max_bytes: usize) -> Result<T, BodyError>
where
    T: DeserializeOwned,
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    let bytes = Limited::new(req.into_body(), max_bytes)
        .collect()
        .await
        .map_err(|_| BodyError::Unreadable)?
        .to_bytes();
    serde_json::from_slice(&bytes).map_err(|_| BodyError::Malformed)
}

pub fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(bytes) => response(status, "application/json", Bytes::from(bytes)),
        Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "serialisation failed"),
    }
}

pub fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    response(status, "text/plain", Bytes::from_static(body.as_bytes()))
}

fn response(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Body> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(body: &'static [u8]) -> Request<Full<Bytes>> {
        Request::post("/")
            .body(Full::new(Bytes::from_static(body)))
            .unwrap()
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_before_parsing() {
        let result: Result<serde_json::Value, _> = read_json(request(b"[1,2,3,4,5]"), 4).await;
        assert_eq!(result, Err(BodyError::Unreadable));
    }

    #[tokio::test]
    async fn malformed_json_is_reported() {
        let result: Result<serde_json::Value, _> = read_json(request(b"{nope"), 1024).await;
        assert_eq!(result, Err(BodyError::Malformed));
    }

    #[tokio::test]
    async fn valid_json_is_parsed() {
        let value: serde_json::Value = read_json(request(b"{\"a\":1}"), 1024).await.unwrap();
        assert_eq!(value["a"], 1);
    }
}
