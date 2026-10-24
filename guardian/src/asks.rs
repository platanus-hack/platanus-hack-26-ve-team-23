//! Pending `ask` decisions (ADR-0022). A medium finding makes the policy ask
//! the owner; the Core holds the `decide` answer for up to 60 s while the
//! owner answers from the app. Each ask is one-shot and resolved by an
//! `Answer` carrying the owner's signature.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use guardian_core::wire::PendingAsk;
use tokio::sync::oneshot;

/// How long the owner has to answer before the ask is denied (ADR-0022).
pub const ASK_TIMEOUT: Duration = Duration::from_secs(60);

struct Entry {
    meta: PendingAsk,
    resolve: oneshot::Sender<bool>,
}

#[derive(Default)]
pub struct Asks {
    inner: Mutex<HashMap<String, Entry>>,
}

impl std::fmt::Debug for Asks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Asks").finish_non_exhaustive()
    }
}

impl Asks {
    /// Registers an ask and returns the receiver the owner's answer resolves:
    /// `Ok(true)` for allow, `Ok(false)` for deny.
    pub fn register(&self, meta: PendingAsk) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.insert(meta.id.clone(), Entry { meta, resolve: tx });
        rx
    }

    /// The asks waiting for the owner, oldest first.
    pub fn pending(&self) -> Vec<PendingAsk> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut asks: Vec<PendingAsk> = inner.values().map(|e| e.meta.clone()).collect();
        asks.sort_by_key(|a| a.created_at_ms);
        asks
    }

    /// Takes the resolver of an ask by id. `None` if there is no such ask
    /// (wrong id, already answered, or it timed out).
    pub fn take(&self, id: &str) -> Option<oneshot::Sender<bool>> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner.remove(id).map(|e| e.resolve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(id: &str) -> PendingAsk {
        PendingAsk {
            id: id.to_owned(),
            session: "s".into(),
            tool: "bash".into(),
            reason: "r".into(),
            host: "10.0.0.7".into(),
            created_at_ms: 0,
        }
    }

    #[tokio::test]
    async fn an_answer_resolves_the_waiting_ask() {
        let asks = Asks::default();
        let rx = asks.register(ask("a1"));
        assert_eq!(asks.pending().len(), 1);

        let sender = asks.take("a1").unwrap();
        sender.send(true).unwrap();
        assert_eq!(rx.await, Ok(true));
        assert!(asks.take("a1").is_none());
    }

    #[tokio::test]
    async fn an_unknown_ask_is_not_resolvable() {
        let asks = Asks::default();
        assert!(asks.take("nope").is_none());
    }
}
