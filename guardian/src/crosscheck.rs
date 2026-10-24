//! Hook-proxy cross-check (ADR-0004): every tool call the model proposes
//! through the proxy must be matched, within a short window, by a hook
//! `decide` for the same call id. A proposed call that never reaches the hook
//! means the hook was disabled or bypassed (evasion); a `decide` the model
//! never proposed means something is executing on its own.
//!
//! The call id is the model's tool-call id from the proxy, which the agent
//! hook sends back as `ToolCall.call_id` (OpenCode's `input.callID`, the
//! `tool_use_id` of Claude Code and Codex).
//!
//! A `decide` is only compared with proposals on hosts whose agents use the
//! proxy (ADR-0034): an agent that talks to its model directly has no
//! proposals to match, and must not raise an alert on every call.

use std::{collections::HashMap, net::IpAddr, sync::Mutex, time::Duration};

use guardian_core::wire::ProposedToolCall;

/// How long a proposal stays open before it counts as evasion (ADR-0022).
pub const WINDOW: Duration = Duration::from_secs(5);

/// How long after its last proxy record a host still counts as proxied.
pub const PROXIED_FOR: Duration = Duration::from_secs(10 * 60);

/// A proposed tool call that has not yet been matched by a `decide`.
#[derive(Debug, Clone)]
pub struct Proposed {
    pub id: String,
    pub name: String,
    pub host: IpAddr,
    pub at_ms: u64,
}

/// Result of matching a `decide` (by call id) against the proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    /// A proposal with that id existed and was consumed: no evasion.
    Matched,
    /// No proposal with that id: the hook asked for a call the model never
    /// proposed.
    NoProposal,
}

#[derive(Debug, Default)]
pub struct CrossCheck {
    proposals: Mutex<HashMap<String, Proposed>>,
    /// When each host last sent a proxy record.
    proxied: Mutex<HashMap<IpAddr, u64>>,
}

impl CrossCheck {
    /// Registers the calls the model proposed for `host` at `at_ms`, and that
    /// `host` uses the proxy.
    pub fn proposed(&self, host: IpAddr, at_ms: u64, calls: &[ProposedToolCall]) {
        self.proxied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(host, at_ms);
        let mut map = self.proposals.lock().unwrap_or_else(|p| p.into_inner());
        for call in calls {
            // Calls without an id (Ollama's native format) cannot be matched.
            if call.id.is_empty() {
                continue;
            }
            map.insert(
                call.id.clone(),
                Proposed {
                    id: call.id.clone(),
                    name: call.name.clone(),
                    host,
                    at_ms,
                },
            );
        }
    }

    /// Whether `host` sent a proxy record within `PROXIED_FOR` of `now_ms`.
    pub fn proxied(&self, host: IpAddr, now_ms: u64) -> bool {
        self.proxied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&host)
            .is_some_and(|at| now_ms.saturating_sub(*at) < PROXIED_FOR.as_millis() as u64)
    }

    /// Matches a `decide` by its call id, consuming the proposal.
    pub fn matched(&self, call_id: Option<&str>) -> Match {
        let Some(id) = call_id else {
            return Match::NoProposal;
        };
        let mut map = self.proposals.lock().unwrap_or_else(|p| p.into_inner());
        match map.remove(id) {
            Some(_) => Match::Matched,
            None => Match::NoProposal,
        }
    }

    /// Proposals older than `WINDOW`, removed and returned. Each one is a tool
    /// call the model proposed that never reached the hook.
    pub fn expired(&self, now_ms: u64) -> Vec<Proposed> {
        let window_ms = WINDOW.as_millis() as u64;
        let mut map = self.proposals.lock().unwrap_or_else(|p| p.into_inner());
        let expired: Vec<Proposed> = map
            .iter()
            .filter(|(_, p)| now_ms.saturating_sub(p.at_ms) >= window_ms)
            .map(|(_, p)| p.clone())
            .collect();
        for proposal in &expired {
            map.remove(&proposal.id);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(id: &str, name: &str) -> ProposedToolCall {
        ProposedToolCall {
            id: id.to_owned(),
            name: name.to_owned(),
            arguments: serde_json::json!({}),
        }
    }

    #[test]
    fn a_decide_matches_and_consumes_its_proposal() {
        let cc = CrossCheck::default();
        cc.proposed("10.0.0.7".parse().unwrap(), 1000, &[call("c1", "bash")]);
        assert_eq!(cc.matched(Some("c1")), Match::Matched);
        assert_eq!(cc.matched(Some("c1")), Match::NoProposal);
    }

    #[test]
    fn a_decide_without_a_proposal_is_reported() {
        let cc = CrossCheck::default();
        assert_eq!(cc.matched(Some("ghost")), Match::NoProposal);
        assert_eq!(cc.matched(None), Match::NoProposal);
    }

    #[test]
    fn proposals_expire_after_the_window() {
        let cc = CrossCheck::default();
        cc.proposed("10.0.0.7".parse().unwrap(), 1000, &[call("c1", "bash")]);
        let window_ms = WINDOW.as_millis() as u64;
        // Still inside the window.
        assert!(cc.expired(1000 + window_ms - 1).is_empty());
        // At the window edge and beyond.
        let expired = cc.expired(1000 + window_ms);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "c1");
        assert!(cc.expired(2000 + window_ms).is_empty());
    }

    #[test]
    fn only_hosts_that_used_the_proxy_recently_are_proxied() {
        let cc = CrossCheck::default();
        let host: IpAddr = "10.0.0.7".parse().unwrap();
        assert!(!cc.proxied(host, 1000));
        // Any proxy record counts, with or without tool calls.
        cc.proposed(host, 1000, &[]);
        assert!(cc.proxied(host, 1000 + 60_000));
        assert!(!cc.proxied("10.0.0.8".parse().unwrap(), 1000));
        assert!(!cc.proxied(host, 1000 + PROXIED_FOR.as_millis() as u64));
    }

    #[test]
    fn calls_without_ids_are_not_cross_checked() {
        let cc = CrossCheck::default();
        cc.proposed("10.0.0.7".parse().unwrap(), 1000, &[call("", "bash")]);
        assert_eq!(cc.matched(Some("")), Match::NoProposal);
    }
}
