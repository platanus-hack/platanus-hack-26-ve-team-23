//! Kafka sink with the pure-Rust `rskafka` client (ADR-0020): one topic per
//! event family (`<prefix>.decisions`, `.alerts`, `.containment`, `.heads`),
//! partition 0, keyed by host. Topics must exist (or broker auto-creation be
//! enabled).

use std::collections::{BTreeMap, HashMap};

use rskafka::{
    chrono::{TimeZone, Utc},
    client::{
        partition::{Compression, PartitionClient, UnknownTopicHandling},
        Client, ClientBuilder,
    },
    record::Record,
};
use tokio::sync::Mutex;

use crate::{BoxFuture, EventSink, SinkEvent};

pub struct Kafka {
    client: Client,
    prefix: String,
    partitions: Mutex<HashMap<&'static str, PartitionClient>>,
}

impl std::fmt::Debug for Kafka {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kafka")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl Kafka {
    /// `brokers` is a comma-separated list of `host:port`.
    pub async fn connect(brokers: &str, prefix: &str) -> Result<Self, String> {
        let brokers = brokers.split(',').map(|b| b.trim().to_owned()).collect();
        let client = ClientBuilder::new(brokers)
            .build()
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            client,
            prefix: prefix.to_owned(),
            partitions: Mutex::new(HashMap::new()),
        })
    }

    fn record(event: &SinkEvent) -> Result<Record, String> {
        Ok(Record {
            key: Some(event.key.as_bytes().to_vec()),
            value: Some(serde_json::to_vec(event).map_err(|e| e.to_string())?),
            headers: BTreeMap::new(),
            timestamp: Utc
                .timestamp_millis_opt(i64::try_from(event.timestamp_ms).unwrap_or(0))
                .single()
                .unwrap_or_default(),
        })
    }
}

impl EventSink for Kafka {
    fn name(&self) -> &'static str {
        "kafka"
    }

    fn publish<'a>(&'a self, events: &'a [SinkEvent]) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let mut by_family: BTreeMap<&'static str, Vec<Record>> = BTreeMap::new();
            for event in events {
                by_family
                    .entry(event.family)
                    .or_default()
                    .push(Self::record(event)?);
            }
            let mut partitions = self.partitions.lock().await;
            for (family, records) in by_family {
                if !partitions.contains_key(family) {
                    let topic = format!("{}.{family}", self.prefix);
                    let client = self
                        .client
                        .partition_client(topic, 0, UnknownTopicHandling::Retry)
                        .await
                        .map_err(|e| e.to_string())?;
                    partitions.insert(family, client);
                }
                if let Some(partition) = partitions.get(family) {
                    partition
                        .produce(records, Compression::NoCompression)
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
            Ok(())
        })
    }
}
