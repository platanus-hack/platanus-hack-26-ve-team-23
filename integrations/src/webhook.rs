//! Webhook sink: POSTs each batch as a JSON array (ADR-0020). For HTTPS
//! endpoints with a public certificate, put a reverse proxy or set
//! `GUARDIAN_WEBHOOK_CERT_SHA256` to pin the endpoint's certificate.

use std::time::Duration;

use hyper::Method;

use crate::{
    client::call_json,
    tls::{parse_fingerprint, pinned_client, HttpsClient},
    BoxFuture, EventSink, SinkEvent,
};

pub struct Webhook {
    client: HttpsClient,
    url: String,
}

impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

impl Webhook {
    pub fn new(url: &str) -> Self {
        let pin = std::env::var("GUARDIAN_WEBHOOK_CERT_SHA256")
            .ok()
            .and_then(|t| parse_fingerprint(&t))
            .unwrap_or([0; 32]);
        Self {
            client: pinned_client(pin, Duration::from_secs(2)),
            url: url.to_owned(),
        }
    }
}

impl EventSink for Webhook {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn publish<'a>(&'a self, events: &'a [SinkEvent]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let body = serde_json::to_value(events).map_err(|e| e.to_string())?;
            call_json(
                &self.client,
                Method::POST,
                &self.url,
                None,
                Some(&body),
                Duration::from_secs(5),
            )
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
        })
    }
}
