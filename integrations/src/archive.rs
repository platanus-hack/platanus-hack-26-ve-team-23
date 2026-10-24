//! Off-site archive of sealed batches in S3 with Object Lock (ADR-0026).
//!
//! After each signed head the Core hands over the batch (its encoded events,
//! payloads sealed to the owner) and the head. They are uploaded in the
//! background; the bucket's Object Lock in compliance mode keeps anyone,
//! the account root included, from deleting or overwriting them during the
//! retention period. The same code talks to AWS or to LocalStack.
//!
//! Requests are signed (SigV4) by `rusty-s3`; `Content-MD5`, which S3
//! requires for objects in a locked bucket, is part of the signature.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{header, Request};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use md5::{Digest as _, Md5};
use rusty_s3::{actions::S3Action as _, Bucket, Credentials, UrlStyle};
use tokio::sync::mpsc;

const QUEUE: usize = 256;
const ATTEMPTS: u32 = 4;
const PRESIGN_FOR: Duration = Duration::from_secs(300);
const TIMEOUT: Duration = Duration::from_secs(30);

/// One batch between two signed heads, as the Core hands it over.
#[derive(Debug, Clone)]
pub struct ArchiveBatch {
    pub first_seq: u64,
    pub seq: u64,
    /// The batch's events, each `Event::encode`d, concatenated.
    pub events: Vec<u8>,
    /// The signed head v2, as JSON.
    pub head_json: Vec<u8>,
}

impl ArchiveBatch {
    pub fn batch_key(&self, prefix: &str) -> String {
        format!(
            "{prefix}/batches/{:020}-{:020}.bin",
            self.first_seq, self.seq
        )
    }

    pub fn head_key(&self, prefix: &str) -> String {
        format!("{prefix}/heads/{:020}.json", self.seq)
    }
}

#[derive(Debug, Clone)]
pub struct ArchiveConfig {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub prefix: String,
    pub access_key: String,
    pub secret_key: String,
}

impl ArchiveConfig {
    /// `ARCHIVE_ENDPOINT`, `ARCHIVE_REGION`, `ARCHIVE_BUCKET`, `ARCHIVE_PREFIX`,
    /// `ARCHIVE_ACCESS_KEY`, `ARCHIVE_SECRET_KEY`. `None` when the archive is
    /// not configured (no `ARCHIVE_BUCKET`).
    pub fn from_env() -> Option<Self> {
        let get = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let bucket = get("ARCHIVE_BUCKET")?;
        Some(Self {
            endpoint: get("ARCHIVE_ENDPOINT").unwrap_or_else(|| "https://s3.amazonaws.com".into()),
            region: get("ARCHIVE_REGION").unwrap_or_else(|| "us-east-1".into()),
            bucket,
            prefix: get("ARCHIVE_PREFIX").unwrap_or_else(|| "core".into()),
            access_key: get("ARCHIVE_ACCESS_KEY").unwrap_or_default(),
            secret_key: get("ARCHIVE_SECRET_KEY").unwrap_or_default(),
        })
    }
}

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// HTTPS with the public CA roots (AWS), plain HTTP for a local emulator.
fn client() -> HttpsClient {
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    http.enforce_http(false);
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
}

pub(crate) struct Store {
    bucket: Bucket,
    credentials: Credentials,
    prefix: String,
    http: HttpsClient,
}

impl Store {
    pub(crate) fn new(config: &ArchiveConfig) -> Result<Self, String> {
        let endpoint = config
            .endpoint
            .parse()
            .map_err(|e| format!("ARCHIVE_ENDPOINT: {e}"))?;
        // Path style works on AWS and on LocalStack without DNS tricks.
        let bucket = Bucket::new(
            endpoint,
            UrlStyle::Path,
            config.bucket.clone(),
            config.region.clone(),
        )
        .map_err(|e| format!("bucket: {e}"))?;
        Ok(Self {
            bucket,
            credentials: Credentials::new(config.access_key.clone(), config.secret_key.clone()),
            prefix: config.prefix.trim_matches('/').to_owned(),
            http: client(),
        })
    }

    /// Reads `key` (under no prefix). `Ok(None)` when it does not exist.
    pub(crate) async fn get(&self, key: &str, max_bytes: usize) -> Result<Option<Vec<u8>>, String> {
        let action = rusty_s3::actions::GetObject::new(&self.bucket, Some(&self.credentials), key);
        let url = action.sign(PRESIGN_FOR);
        let request = Request::get(url.as_str())
            .body(Full::new(Bytes::new()))
            .map_err(|e| e.to_string())?;
        let call = async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status();
            if status == hyper::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let body = Limited::new(response.into_body(), max_bytes)
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            if !status.is_success() {
                return Err(format!(
                    "{status}: {}",
                    String::from_utf8_lossy(&body)
                        .chars()
                        .take(300)
                        .collect::<String>()
                ));
            }
            Ok(Some(body.to_vec()))
        };
        tokio::time::timeout(TIMEOUT, call)
            .await
            .map_err(|_| "timed out".to_owned())?
    }

    pub(crate) async fn put(&self, key: &str, body: &[u8]) -> Result<(), String> {
        let md5 = base64::engine::general_purpose::STANDARD.encode(Md5::digest(body));
        let mut action =
            rusty_s3::actions::PutObject::new(&self.bucket, Some(&self.credentials), key);
        action.headers_mut().insert("content-md5", md5.clone());
        let url = action.sign(PRESIGN_FOR);
        let request = Request::put(url.as_str())
            .header("content-md5", md5)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| e.to_string())?;
        let call = async {
            let response = self
                .http
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status();
            if status.is_success() {
                return Ok(());
            }
            let text = Limited::new(response.into_body(), 4096)
                .collect()
                .await
                .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
                .unwrap_or_default();
            Err(format!(
                "{status}: {}",
                text.chars().take(300).collect::<String>()
            ))
        };
        tokio::time::timeout(TIMEOUT, call)
            .await
            .map_err(|_| "timed out".to_owned())?
    }

    async fn archive(&self, batch: &ArchiveBatch) -> Result<(), String> {
        // The batch first: a head in the archive always has its batch.
        self.put(&batch.batch_key(&self.prefix), &batch.events)
            .await?;
        self.put(&batch.head_key(&self.prefix), &batch.head_json)
            .await
    }
}

/// Hands batches to the background uploader. `submit` never blocks.
#[derive(Debug, Clone)]
pub struct Archiver {
    tx: mpsc::Sender<ArchiveBatch>,
    dropped: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}

impl Archiver {
    /// Starts the uploader. Must be called inside a tokio runtime.
    pub fn start(config: &ArchiveConfig) -> Result<Self, String> {
        let store = Store::new(config)?;
        let (tx, mut rx) = mpsc::channel::<ArchiveBatch>(QUEUE);
        let failed = Arc::new(AtomicU64::new(0));
        let failed_task = Arc::clone(&failed);
        tokio::spawn(async move {
            while let Some(batch) = rx.recv().await {
                let mut attempt = 0;
                loop {
                    attempt += 1;
                    match store.archive(&batch).await {
                        Ok(()) => {
                            tracing::debug!(
                                first = batch.first_seq,
                                last = batch.seq,
                                "batch archived"
                            );
                            break;
                        }
                        Err(err) if attempt < ATTEMPTS => {
                            tracing::warn!(%err, attempt, "archive upload failed, retrying");
                            tokio::time::sleep(Duration::from_secs(2u64.pow(attempt))).await;
                        }
                        Err(err) => {
                            failed_task.fetch_add(1, Ordering::Relaxed);
                            tracing::error!(%err, first = batch.first_seq, last = batch.seq, "batch NOT archived; it stays on the Core");
                            break;
                        }
                    }
                }
            }
        });
        Ok(Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            failed,
        })
    }

    pub fn submit(&self, batch: ArchiveBatch) {
        if self.tx.try_send(batch).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            tracing::error!("archive queue full; batch kept only on the Core");
        }
    }

    /// Batches that could not be queued or uploaded.
    pub fn missed(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed) + self.failed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_by_sequence() {
        let batch = ArchiveBatch {
            first_seq: 7,
            seq: 16,
            events: Vec::new(),
            head_json: Vec::new(),
        };
        assert_eq!(
            batch.batch_key("core"),
            "core/batches/00000000000000000007-00000000000000000016.bin"
        );
        assert_eq!(
            batch.head_key("core"),
            "core/heads/00000000000000000016.json"
        );
    }

    #[tokio::test]
    async fn uploads_sign_the_md5_header() {
        // A stand-in for S3 that records what it receives.
        use std::sync::Mutex;
        type Seen = Arc<Mutex<Vec<(String, String, Option<String>)>>>;
        let seen: Seen = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let service =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let log = Arc::clone(&log);
                            async move {
                                let path = req.uri().path().to_owned();
                                let query = req.uri().query().unwrap_or_default().to_owned();
                                let md5 = req
                                    .headers()
                                    .get("content-md5")
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned);
                                log.lock().unwrap().push((path, query, md5));
                                Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                                    Bytes::new(),
                                )))
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        let config = ArchiveConfig {
            endpoint: format!("http://{addr}"),
            region: "us-east-1".into(),
            bucket: "hawk-archive".into(),
            prefix: "core".into(),
            access_key: "test".into(),
            secret_key: "test".into(),
        };
        let store = Store::new(&config).unwrap();
        let batch = ArchiveBatch {
            first_seq: 0,
            seq: 9,
            events: b"events".to_vec(),
            head_json: b"{}".to_vec(),
        };
        store.archive(&batch).await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].0,
            "/hawk-archive/core/batches/00000000000000000000-00000000000000000009.bin"
        );
        assert_eq!(
            seen[1].0,
            "/hawk-archive/core/heads/00000000000000000009.json"
        );
        for (_, query, md5) in seen.iter() {
            assert!(query.contains("X-Amz-Signature="));
            assert!(
                query.contains("content-md5"),
                "md5 must be a signed header: {query}"
            );
            assert!(md5.is_some());
        }
    }
}
