//! Asynchronous publishing to every configured sink (ADR-0020).
//!
//! `Publisher::send` never waits: events go into a bounded queue, and a
//! background task delivers them in small batches. When the queue is full
//! the event is dropped and counted; the record on the Core stays complete,
//! so nothing is lost from the evidence, only from the live feed.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::sync::mpsc;

use crate::{EventSink, SinkEvent};

const QUEUE: usize = 4096;
const BATCH: usize = 100;
const RETRY_DELAY: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct Publisher {
    tx: Option<mpsc::Sender<SinkEvent>>,
    dropped: Arc<AtomicU64>,
}

impl Publisher {
    /// A publisher that discards everything; used when no sink is configured.
    pub fn none() -> Self {
        Self {
            tx: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Starts the delivery task. Must be called inside a tokio runtime.
    pub fn start(sinks: Vec<Box<dyn EventSink>>) -> Self {
        if sinks.is_empty() {
            return Self::none();
        }
        let (tx, mut rx) = mpsc::channel::<SinkEvent>(QUEUE);
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(BATCH);
            while rx.recv_many(&mut batch, BATCH).await > 0 {
                for sink in &sinks {
                    // One retry, then the batch is given up for this sink.
                    if let Err(err) = sink.publish(&batch).await {
                        tracing::warn!(sink = sink.name(), %err, "publish failed, retrying");
                        tokio::time::sleep(RETRY_DELAY).await;
                        if let Err(err) = sink.publish(&batch).await {
                            tracing::error!(sink = sink.name(), %err, events = batch.len(), "batch dropped");
                        }
                    }
                }
                batch.clear();
            }
        });
        Self {
            tx: Some(tx),
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn send(&self, event: SinkEvent) {
        if let Some(tx) = &self.tx {
            if tx.try_send(event).is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Builds the sinks named in the environment: `KAFKA_BROKERS` and
/// `GUARDIAN_WEBHOOK_URL`.
pub async fn sinks_from_env() -> Vec<Box<dyn EventSink>> {
    #[allow(unused_mut)]
    let mut sinks: Vec<Box<dyn EventSink>> = Vec::new();
    #[cfg(feature = "kafka")]
    if let Ok(brokers) = std::env::var("KAFKA_BROKERS") {
        let prefix = std::env::var("KAFKA_TOPIC_PREFIX").unwrap_or_else(|_| "guardian".into());
        match crate::kafka::Kafka::connect(&brokers, &prefix).await {
            Ok(kafka) => sinks.push(Box::new(kafka)),
            Err(err) => tracing::error!(%err, "kafka sink disabled"),
        }
    }
    #[cfg(feature = "webhook")]
    if let Ok(url) = std::env::var("GUARDIAN_WEBHOOK_URL") {
        sinks.push(Box::new(crate::webhook::Webhook::new(&url)));
    }
    sinks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxFuture;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Collect(Arc<Mutex<Vec<u64>>>);

    impl EventSink for Collect {
        fn name(&self) -> &'static str {
            "collect"
        }
        fn publish<'a>(&'a self, events: &'a [SinkEvent]) -> BoxFuture<'a, Result<(), String>> {
            Box::pin(async move {
                self.0.lock().unwrap().extend(events.iter().map(|e| e.seq));
                Ok(())
            })
        }
    }

    fn event(seq: u64) -> SinkEvent {
        SinkEvent {
            family: "decisions",
            seq,
            timestamp_ms: 0,
            key: "host".into(),
            body: serde_json::json!({}),
        }
    }

    #[tokio::test]
    async fn events_reach_the_sink_in_order() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let publisher = Publisher::start(vec![Box::new(Collect(Arc::clone(&seen)))]);
        for seq in 0..5 {
            publisher.send(event(seq));
        }
        for _ in 0..50 {
            if seen.lock().unwrap().len() == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(*seen.lock().unwrap(), vec![0, 1, 2, 3, 4]);
        assert_eq!(publisher.dropped(), 0);
    }

    #[test]
    fn no_sink_discards_silently() {
        let publisher = Publisher::none();
        publisher.send(event(1));
        assert_eq!(publisher.dropped(), 0);
    }
}
