//! Records containment decisions without touching any device. The default
//! when no router is configured, and what the tests use.

use std::{collections::BTreeSet, net::IpAddr, sync::Mutex};

use crate::{BoxFuture, Firewall, FirewallError};

#[derive(Debug, Default)]
pub struct DryRun {
    quarantined: Mutex<BTreeSet<IpAddr>>,
}

impl DryRun {
    pub fn is_quarantined(&self, host: IpAddr) -> bool {
        self.quarantined
            .lock()
            .map(|set| set.contains(&host))
            .unwrap_or(false)
    }
}

impl Firewall for DryRun {
    fn name(&self) -> &'static str {
        "dry-run"
    }

    fn quarantine<'a>(
        &'a self,
        host: IpAddr,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>> {
        Box::pin(async move {
            tracing::warn!(%host, reason, "DRY RUN: host would be quarantined");
            self.quarantined
                .lock()
                .map_err(|_| FirewallError::Rejected("lock poisoned".into()))?
                .insert(host);
            Ok(())
        })
    }

    fn release(&self, host: IpAddr) -> BoxFuture<'_, Result<(), FirewallError>> {
        Box::pin(async move {
            tracing::warn!(%host, "DRY RUN: host would be released");
            self.quarantined
                .lock()
                .map_err(|_| FirewallError::Rejected("lock poisoned".into()))?
                .remove(&host);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quarantine_and_release_are_idempotent() {
        let fw = DryRun::default();
        let host: IpAddr = "10.0.0.5".parse().unwrap();
        fw.quarantine(host, "test").await.unwrap();
        fw.quarantine(host, "test").await.unwrap();
        assert!(fw.is_quarantined(host));
        fw.release(host).await.unwrap();
        fw.release(host).await.unwrap();
        assert!(!fw.is_quarantined(host));
    }
}
