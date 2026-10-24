//! MikroTik RouterOS 7 through its REST API (ADR-0018).
//!
//! The Core adds the host to an address list; a firewall rule the owner
//! installs once (`docs/LAB.md`) drops traffic from that list except towards
//! the Core. The router account needs only the `rest-api`, `read` and
//! `write` policies.
//!
//! MAC containment (ADR-0028): RouterOS has no MAC address lists, so the Core
//! adds one mangle rule per MAC with `add-src-to-address-list` into the same
//! quarantine list. Any address that interface uses lands in the list on its
//! first packet, and the existing drop rule applies.
//!
//! Configuration:
//!
//! | Variable | Example |
//! |---|---|
//! | `MIKROTIK_URL` | `https://192.168.88.1` |
//! | `MIKROTIK_USER`, `MIKROTIK_PASSWORD` | account of the Core |
//! | `MIKROTIK_CERT_SHA256` | fingerprint of the router certificate (required for HTTPS) |
//! | `MIKROTIK_LIST` | address list name, default `guardian_quarantine` |

use std::{net::IpAddr, time::Duration};

use base64::Engine as _;
use guardian_core::machine::Mac;
use hyper::Method;

use crate::{
    client::{call_json, CallError},
    env,
    tls::{parse_fingerprint, pinned_client, HttpsClient},
    BoxFuture, Firewall, FirewallError,
};

const TIMEOUT: Duration = Duration::from_secs(5);

pub struct MikroTik {
    client: HttpsClient,
    base: String,
    authorization: String,
    list: String,
}

impl std::fmt::Debug for MikroTik {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MikroTik")
            .field("base", &self.base)
            .field("list", &self.list)
            .finish_non_exhaustive()
    }
}

fn map(err: CallError) -> FirewallError {
    match err {
        CallError::Unreachable(why) => FirewallError::Unreachable(why),
        CallError::Status(code, body) => FirewallError::Rejected(format!("{code}: {body}")),
        CallError::Body(why) => FirewallError::Rejected(why),
    }
}

impl MikroTik {
    pub fn new(
        base: &str,
        user: &str,
        password: &str,
        fingerprint: Option<[u8; 32]>,
        list: &str,
    ) -> Result<Self, FirewallError> {
        let base = base.trim_end_matches('/').to_owned();
        let fingerprint = match (base.starts_with("https://"), fingerprint) {
            (true, Some(fp)) => fp,
            (true, None) => {
                return Err(FirewallError::Config(
                    "MIKROTIK_CERT_SHA256 is required for HTTPS".into(),
                ))
            }
            // Plain HTTP (lab only): the pin is never used.
            (false, fp) => fp.unwrap_or([0; 32]),
        };
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        Ok(Self {
            client: pinned_client(fingerprint, Duration::from_secs(2)),
            base,
            authorization: format!("Basic {credentials}"),
            list: list.to_owned(),
        })
    }

    pub fn from_env() -> Result<Self, FirewallError> {
        let fingerprint = std::env::var("MIKROTIK_CERT_SHA256")
            .ok()
            .map(|t| {
                parse_fingerprint(&t)
                    .ok_or_else(|| FirewallError::Config("bad MIKROTIK_CERT_SHA256".into()))
            })
            .transpose()?;
        Self::new(
            &env("MIKROTIK_URL")?,
            &env("MIKROTIK_USER")?,
            &env("MIKROTIK_PASSWORD")?,
            fingerprint,
            &std::env::var("MIKROTIK_LIST").unwrap_or_else(|_| "guardian_quarantine".into()),
        )
    }

    fn url(&self, path: &str) -> String {
        format!("{}/rest/ip/firewall/address-list{path}", self.base)
    }

    fn mangle_url(&self, path: &str) -> String {
        format!("{}/rest/ip/firewall/mangle{path}", self.base)
    }

    /// The mangle rule that puts every address of `mac` in the list.
    fn mac_rule(&self, mac: Mac, reason: &str) -> serde_json::Value {
        serde_json::json!({
            "chain": "prerouting",
            "src-mac-address": mac.upper(),
            "action": "add-src-to-address-list",
            "address-list": self.list,
            "address-list-timeout": "none-dynamic",
            "comment": format!("guardian: {reason}"),
        })
    }

    async fn get(&self, url: &str) -> Result<serde_json::Value, FirewallError> {
        call_json(
            &self.client,
            Method::GET,
            url,
            Some(&self.authorization),
            None,
            TIMEOUT,
        )
        .await
        .map_err(map)
    }

    async fn delete(&self, url: &str) -> Result<(), FirewallError> {
        call_json(
            &self.client,
            Method::DELETE,
            url,
            Some(&self.authorization),
            None,
            TIMEOUT,
        )
        .await
        .map(|_| ())
        .map_err(map)
    }

    /// Ids of our mangle rules for `mac`.
    async fn mac_rules(&self, mac: Mac) -> Result<Vec<String>, FirewallError> {
        let url = self.mangle_url(&format!(
            "?src-mac-address={}&address-list={}",
            mac.upper(),
            self.list
        ));
        Ok(ids(&self.get(&url).await?))
    }

    /// Addresses the router has seen for `mac` in its ARP table.
    async fn addresses_of(&self, mac: Mac) -> Result<Vec<IpAddr>, FirewallError> {
        let url = format!("{}/rest/ip/arp?mac-address={}", self.base, mac.upper());
        Ok(self
            .get(&url)
            .await?
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| i.get("address")?.as_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Ids of the entries for `host` in the quarantine list.
    async fn entries(&self, host: IpAddr) -> Result<Vec<String>, FirewallError> {
        let url = self.url(&format!("?list={}&address={host}", self.list));
        let found = call_json(
            &self.client,
            Method::GET,
            &url,
            Some(&self.authorization),
            None,
            TIMEOUT,
        )
        .await
        .map_err(map)?;
        Ok(ids(&found))
    }
}

/// The `.id` of every item RouterOS returned.
fn ids(found: &serde_json::Value) -> Vec<String> {
    found
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.get(".id")?.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl Firewall for MikroTik {
    fn name(&self) -> &'static str {
        "mikrotik"
    }

    fn quarantine<'a>(
        &'a self,
        host: IpAddr,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>> {
        Box::pin(async move {
            if !self.entries(host).await?.is_empty() {
                return Ok(());
            }
            let body = serde_json::json!({
                "list": self.list,
                "address": host.to_string(),
                "comment": format!("guardian: {reason}"),
            });
            call_json(
                &self.client,
                Method::PUT,
                &self.url(""),
                Some(&self.authorization),
                Some(&body),
                TIMEOUT,
            )
            .await
            .map(|_| ())
            .map_err(map)
        })
    }

    fn release(&self, host: IpAddr) -> BoxFuture<'_, Result<(), FirewallError>> {
        Box::pin(async move {
            for id in self.entries(host).await? {
                self.delete(&self.url(&format!("/{id}"))).await?;
            }
            Ok(())
        })
    }

    fn quarantine_mac<'a>(
        &'a self,
        mac: Mac,
        reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>> {
        Box::pin(async move {
            if !self.mac_rules(mac).await?.is_empty() {
                return Ok(());
            }
            call_json(
                &self.client,
                Method::PUT,
                &self.mangle_url(""),
                Some(&self.authorization),
                Some(&self.mac_rule(mac, reason)),
                TIMEOUT,
            )
            .await
            .map(|_| ())
            .map_err(map)
        })
    }

    /// Removes the mangle rule, then the list entries of every address the
    /// router saw for that MAC.
    fn release_mac(&self, mac: Mac) -> BoxFuture<'_, Result<(), FirewallError>> {
        Box::pin(async move {
            for id in self.mac_rules(mac).await? {
                self.delete(&self.mangle_url(&format!("/{id}"))).await?;
            }
            for address in self.addresses_of(mac).await? {
                for id in self.entries(address).await? {
                    self.delete(&self.url(&format!("/{id}"))).await?;
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_requires_a_pin() {
        let err = MikroTik::new("https://router", "u", "p", None, "q").unwrap_err();
        assert!(matches!(err, FirewallError::Config(_)));
        assert!(MikroTik::new("https://router", "u", "p", Some([1; 32]), "q").is_ok());
    }

    #[test]
    fn the_mac_rule_feeds_the_quarantine_list() {
        let fw = MikroTik::new("http://10.0.0.1", "core", "secret", None, "q").unwrap();
        let mac = Mac::parse("52:54:00:ab:cd:ef").unwrap();
        let rule = fw.mac_rule(mac, "critical finding");
        assert_eq!(rule["src-mac-address"], "52:54:00:AB:CD:EF");
        assert_eq!(rule["action"], "add-src-to-address-list");
        assert_eq!(rule["address-list"], "q");
        assert_eq!(rule["chain"], "prerouting");
        assert_eq!(
            fw.mangle_url("/*1"),
            "http://10.0.0.1/rest/ip/firewall/mangle/*1"
        );
    }

    #[test]
    fn ids_are_read_from_router_answers() {
        let found = serde_json::json!([{ ".id": "*1" }, { "other": 1 }, { ".id": "*A" }]);
        assert_eq!(ids(&found), vec!["*1", "*A"]);
        assert!(ids(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn urls_and_auth() {
        let fw = MikroTik::new("http://10.0.0.1/", "core", "secret", None, "q").unwrap();
        assert_eq!(fw.url(""), "http://10.0.0.1/rest/ip/firewall/address-list");
        assert_eq!(fw.authorization, "Basic Y29yZTpzZWNyZXQ=");
    }
}
