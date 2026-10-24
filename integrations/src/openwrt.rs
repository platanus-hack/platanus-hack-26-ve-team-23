//! OpenWrt (22.03+, fw4/nftables) through ubus JSON-RPC (ADR-0018).
//!
//! The Core logs in to rpcd and calls the `guardian` object provided by our
//! rpcd plugin (`integrations/openwrt/`), which only adds, removes and lists
//! entries of two nftables sets: IPv4 addresses and MACs (ADR-0028). The
//! rpcd ACL grants the Core's user those methods and nothing else.
//!
//! Configuration:
//!
//! | Variable | Example |
//! |---|---|
//! | `OPENWRT_URL` | `https://192.168.1.1` (the `/ubus` endpoint is appended) |
//! | `OPENWRT_USER`, `OPENWRT_PASSWORD` | rpcd login of the Core |
//! | `OPENWRT_CERT_SHA256` | fingerprint of the router certificate (required for HTTPS) |

use std::{net::IpAddr, sync::Mutex, time::Duration};

use guardian_core::machine::Mac;
use hyper::Method;

use crate::{
    client::{call_json, CallError},
    env,
    tls::{parse_fingerprint, pinned_client, HttpsClient},
    BoxFuture, Firewall, FirewallError,
};

const TIMEOUT: Duration = Duration::from_secs(5);
/// rpcd's anonymous session id, used only for `session login`.
const NO_SESSION: &str = "00000000000000000000000000000000";

pub struct OpenWrt {
    client: HttpsClient,
    url: String,
    user: String,
    password: String,
    session: Mutex<Option<String>>,
}

impl std::fmt::Debug for OpenWrt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenWrt")
            .field("url", &self.url)
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

/// ubus answers `{"result": [status, data]}`; status 0 is success.
fn ubus_result(answer: &serde_json::Value) -> Result<serde_json::Value, FirewallError> {
    let result = answer
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| FirewallError::Rejected(format!("unexpected ubus answer: {answer}")))?;
    match result.first().and_then(|s| s.as_u64()) {
        Some(0) => Ok(result.get(1).cloned().unwrap_or(serde_json::Value::Null)),
        Some(6) => Err(FirewallError::Rejected("ubus: permission denied".into())),
        other => Err(FirewallError::Rejected(format!("ubus status {other:?}"))),
    }
}

impl OpenWrt {
    pub fn new(
        base: &str,
        user: &str,
        password: &str,
        fingerprint: Option<[u8; 32]>,
    ) -> Result<Self, FirewallError> {
        let base = base.trim_end_matches('/');
        let fingerprint = match (base.starts_with("https://"), fingerprint) {
            (true, Some(fp)) => fp,
            (true, None) => {
                return Err(FirewallError::Config(
                    "OPENWRT_CERT_SHA256 is required for HTTPS".into(),
                ))
            }
            (false, fp) => fp.unwrap_or([0; 32]),
        };
        Ok(Self {
            client: pinned_client(fingerprint, Duration::from_secs(2)),
            url: format!("{base}/ubus"),
            user: user.to_owned(),
            password: password.to_owned(),
            session: Mutex::new(None),
        })
    }

    pub fn from_env() -> Result<Self, FirewallError> {
        let fingerprint = std::env::var("OPENWRT_CERT_SHA256")
            .ok()
            .map(|t| {
                parse_fingerprint(&t)
                    .ok_or_else(|| FirewallError::Config("bad OPENWRT_CERT_SHA256".into()))
            })
            .transpose()?;
        Self::new(
            &env("OPENWRT_URL")?,
            &env("OPENWRT_USER")?,
            &env("OPENWRT_PASSWORD")?,
            fingerprint,
        )
    }

    async fn rpc(
        &self,
        session: &str,
        object: &str,
        method: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, FirewallError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [session, object, method, args],
        });
        let answer = call_json(
            &self.client,
            Method::POST,
            &self.url,
            None,
            Some(&body),
            TIMEOUT,
        )
        .await
        .map_err(map)?;
        ubus_result(&answer)
    }

    async fn login(&self) -> Result<String, FirewallError> {
        let data = self
            .rpc(
                NO_SESSION,
                "session",
                "login",
                serde_json::json!({
                    "username": self.user,
                    "password": self.password,
                }),
            )
            .await?;
        let session = data
            .get("ubus_rpc_session")
            .and_then(|s| s.as_str())
            .ok_or_else(|| FirewallError::Rejected("login returned no session".into()))?
            .to_owned();
        if let Ok(mut slot) = self.session.lock() {
            *slot = Some(session.clone());
        }
        Ok(session)
    }

    /// Calls a method of our plugin, logging in again once if the session
    /// expired. The plugin answers `{"ok": false}` for input it refuses.
    async fn guardian(&self, method: &str, args: serde_json::Value) -> Result<(), FirewallError> {
        let cached = self.session.lock().ok().and_then(|s| s.clone());
        let session = match cached {
            Some(s) => s,
            None => self.login().await?,
        };
        let data = match self.rpc(&session, "guardian", method, args.clone()).await {
            Ok(data) => data,
            Err(FirewallError::Rejected(_)) => {
                let session = self.login().await?;
                self.rpc(&session, "guardian", method, args).await?
            }
            Err(err) => return Err(err),
        };
        plugin_answer(&data)
    }
}

/// The plugin's own verdict inside a successful ubus call.
fn plugin_answer(data: &serde_json::Value) -> Result<(), FirewallError> {
    match data.get("ok").and_then(serde_json::Value::as_bool) {
        Some(false) => Err(FirewallError::Rejected(format!(
            "guardian plugin: {}",
            data.get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("refused")
        ))),
        _ => Ok(()),
    }
}

impl Firewall for OpenWrt {
    fn name(&self) -> &'static str {
        "openwrt"
    }

    fn quarantine<'a>(
        &'a self,
        host: IpAddr,
        _reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>> {
        Box::pin(self.guardian("add", serde_json::json!({ "address": host.to_string() })))
    }

    fn release(&self, host: IpAddr) -> BoxFuture<'_, Result<(), FirewallError>> {
        Box::pin(self.guardian("remove", serde_json::json!({ "address": host.to_string() })))
    }

    fn quarantine_mac<'a>(
        &'a self,
        mac: Mac,
        _reason: &'a str,
    ) -> BoxFuture<'a, Result<(), FirewallError>> {
        Box::pin(self.guardian("add_mac", serde_json::json!({ "mac": mac.to_string() })))
    }

    fn release_mac(&self, mac: Mac) -> BoxFuture<'_, Result<(), FirewallError>> {
        Box::pin(self.guardian("remove_mac", serde_json::json!({ "mac": mac.to_string() })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubus_results_are_interpreted() {
        let ok = serde_json::json!({ "result": [0, { "ubus_rpc_session": "abc" }] });
        assert_eq!(ubus_result(&ok).unwrap()["ubus_rpc_session"], "abc");
        let denied = serde_json::json!({ "result": [6] });
        assert!(matches!(
            ubus_result(&denied),
            Err(FirewallError::Rejected(_))
        ));
        assert!(ubus_result(&serde_json::json!({ "error": {} })).is_err());
    }

    #[test]
    fn the_plugin_refusal_is_an_error() {
        assert!(plugin_answer(&serde_json::json!({ "ok": true })).is_ok());
        assert!(plugin_answer(&serde_json::Value::Null).is_ok());
        let refused = plugin_answer(&serde_json::json!({ "ok": false, "message": "invalid mac" }));
        assert!(matches!(refused, Err(FirewallError::Rejected(m)) if m.contains("invalid mac")));
    }

    #[test]
    fn https_requires_a_pin() {
        assert!(OpenWrt::new("https://router", "u", "p", None).is_err());
        assert_eq!(
            OpenWrt::new("http://10.0.0.1/", "u", "p", None)
                .unwrap()
                .url,
            "http://10.0.0.1/ubus"
        );
    }
}
