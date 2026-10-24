//! One JSON request to a device: bounded in time and in response size.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{header, Method, Request};

use crate::tls::HttpsClient;

const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    Unreachable(String),
    Status(u16, String),
    Body(String),
}

pub async fn call_json(
    client: &HttpsClient,
    method: Method,
    url: &str,
    authorization: Option<&str>,
    body: Option<&serde_json::Value>,
    timeout: Duration,
) -> Result<serde_json::Value, CallError> {
    let bytes = match body {
        Some(value) => serde_json::to_vec(value).map_err(|e| CallError::Body(e.to_string()))?,
        None => Vec::new(),
    };
    let mut builder = Request::builder()
        .method(method)
        .uri(url)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(auth) = authorization {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let request = builder
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|e| CallError::Body(e.to_string()))?;

    let call = async {
        let response = client
            .request(request)
            .await
            .map_err(|e| CallError::Unreachable(e.to_string()))?;
        let status = response.status();
        let body = Limited::new(response.into_body(), MAX_RESPONSE)
            .collect()
            .await
            .map_err(|e| CallError::Body(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(CallError::Status(
                status.as_u16(),
                String::from_utf8_lossy(&body).chars().take(200).collect(),
            ));
        }
        if body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        serde_json::from_slice(&body).map_err(|e| CallError::Body(e.to_string()))
    };
    tokio::time::timeout(timeout, call)
        .await
        .map_err(|_| CallError::Unreachable("timeout".into()))?
}
