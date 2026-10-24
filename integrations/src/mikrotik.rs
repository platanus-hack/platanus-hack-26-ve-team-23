//! MikroTik RouterOS 7 through its REST API (ADR-0018).
//!
//! The Core adds the host to an address list; a firewall rule the owner
//! installs once (see `docs/lab/mikrotik-setup.rsc`) drops traffic from that
//! list except towards the Core. The router account needs only the `rest-api`,
//! `read` and `write` policies.
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
        Ok(found
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| i.get(".id")?.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }
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
                let url = self.url(&format!("/{id}"));
                call_json(
                    &self.client,
                    Method::DELETE,
                    &url,
                    Some(&self.authorization),
                    None,
                    TIMEOUT,
                )
                .await
                .map_err(map)?;
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
    fn urls_and_auth() {
        let fw = MikroTik::new("http://10.0.0.1/", "core", "secret", None, "q").unwrap();
        assert_eq!(fw.url(""), "http://10.0.0.1/rest/ip/firewall/address-list");
        assert_eq!(fw.authorization, "Basic Y29yZTpzZWNyZXQ=");
    }
}
