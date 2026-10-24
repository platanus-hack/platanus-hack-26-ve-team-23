//! Records containment decisions without touching any device. The default
//! when no router is configured, and what the tests use.

use std::{collections::BTreeSet, net::IpAddr, sync::Mutex};

use guardian_core::machine::Mac;

use crate::{BoxFuture, Firewall, FirewallError};

#[derive(Debug, Default)]
pub struct DryRun {
    quarantined: Mutex<BTreeSet<IpAddr>>,
    macs: Mutex<BTreeSet<Mac>>,
}

impl DryRun {
    pub fn is_quarantined(&self, host: IpAddr) -> bool {
        self.quarantined
            .lock()
            .map(|set| set.contains(&host))
            .unwrap_or(false)
    }

    pub fn is_mac_quarantined(&self, mac: Mac) -> bool {
        self.macs
            .lock()
            .map(|set| set.contains(&mac))
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

    fn quarantine_mac<'a>(
        &'a self,
        mac: Mac,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>> {
        Box::pin(async move {
            tracing::warn!(%mac, reason, "DRY RUN: MAC would be quarantined");
            self.macs
                .lock()
                .map_err(|_| FirewallError::Rejected("lock poisoned".into()))?
                .insert(mac);
            Ok(())
        })
    }

    fn release_mac(&self, mac: Mac) -> BoxFuture<'_, Result<(), FirewallError>> {
        Box::pin(async move {
            tracing::warn!(%mac, "DRY RUN: MAC would be released");
            self.macs
                .lock()
                .map_err(|_| FirewallError::Rejected("lock poisoned".into()))?
                .remove(&mac);
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

    #[tokio::test]
    async fn macs_are_quarantined_and_released_on_their_own() {
        let fw = DryRun::default();
        let mac = Mac::parse("52:54:00:12:34:56").unwrap();
        fw.quarantine_mac(mac, "test").await.unwrap();
        fw.quarantine_mac(mac, "test").await.unwrap();
        assert!(fw.is_mac_quarantined(mac));
        assert!(!fw.is_quarantined("10.0.0.5".parse().unwrap()));
        fw.release_mac(mac).await.unwrap();
        assert!(!fw.is_mac_quarantined(mac));
    }
}
