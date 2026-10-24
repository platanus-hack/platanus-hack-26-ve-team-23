//! The host daemons connected to this Core, by identity: what the witness
//! lists, and how the Core reaches a host to ask it to identify itself.
//!
//! A host is known by its Ed25519 transport identity (from the TLS
//! handshake), shown as a short fingerprint. Its hostname and OS are what it
//! says about itself and are labels only.

use std::{collections::HashMap, sync::Mutex, time::Duration};

use edge_net::quic::{self, PeerId};
use guardian_core::wire::{HostInfo, Request, Response};
use quinn::Connection;

use crate::core::now_ms;

const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Entry {
    conn: Option<Connection>,
    address: String,
    hostname: String,
    os: String,
    last_seen_ms: u64,
    boot_digest: Option<[u8; 32]>,
}

#[derive(Debug, Default)]
pub struct Hosts {
    entries: Mutex<HashMap<PeerId, Entry>>,
}

impl Hosts {
    /// A peer connected. Witness connections are not hosts and are skipped by
    /// the caller.
    pub fn connected(&self, peer: PeerId, conn: Connection) {
        let address = conn.remote_address().ip().to_string();
        if let Ok(mut entries) = self.entries.lock() {
            // Forget closed connections of peers that never introduced
            // themselves (probes, health checks), so they do not pile up.
            entries.retain(|_, e| {
                !e.hostname.is_empty()
                    || e.conn.as_ref().is_some_and(|c| c.close_reason().is_none())
            });
            let entry = entries.entry(peer).or_insert_with(|| Entry {
                conn: None,
                address: address.clone(),
                hostname: String::new(),
                os: String::new(),
                last_seen_ms: 0,
                boot_digest: None,
            });
            entry.conn = Some(conn);
            entry.address = address;
            entry.last_seen_ms = now_ms();
        }
    }

    pub fn hello(&self, peer: PeerId, hostname: &str, os: &str, boot_digest: Option<[u8; 32]>) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(&peer) {
                entry.hostname = hostname.chars().take(64).collect();
                entry.os = os.chars().take(32).collect();
                entry.boot_digest = boot_digest;
                entry.last_seen_ms = now_ms();
            }
        }
    }

    /// The boot measurement the host reported at hello (ADR-0021).
    pub fn boot_digest(&self, peer: &PeerId) -> Option<[u8; 32]> {
        let entries = self.entries.lock().ok()?;
        entries.get(peer)?.boot_digest
    }

    pub fn seen(&self, peer: &PeerId) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(peer) {
                entry.last_seen_ms = now_ms();
            }
        }
    }

    pub fn list(&self) -> Vec<HostInfo> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };
        let mut hosts: Vec<HostInfo> = entries
            .iter()
            // Only peers that introduced themselves as hosts.
            .filter(|(_, e)| !e.hostname.is_empty())
            .map(|(id, e)| HostInfo {
                id: hex::encode(id),
                fingerprint: quic::fingerprint(id),
                address: e.address.clone(),
                hostname: e.hostname.clone(),
                os: e.os.clone(),
                connected: e.conn.as_ref().is_some_and(|c| c.close_reason().is_none()),
                last_seen_ms: e.last_seen_ms,
                approved: false,
            })
            .collect();
        hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        hosts
    }

    /// Live connections of hosts that introduced themselves, for the
    /// heartbeat round (ADR-0021).
    pub fn connections(&self) -> Vec<(PeerId, Connection)> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .filter(|(_, e)| !e.hostname.is_empty())
            .filter_map(|(id, e)| {
                e.conn
                    .as_ref()
                    .filter(|c| c.close_reason().is_none())
                    .map(|c| (*id, c.clone()))
            })
            .collect()
    }

    /// The address the Core would quarantine for a host (ADR-0018).
    pub fn address(&self, peer: &PeerId) -> Option<std::net::IpAddr> {
        let entries = self.entries.lock().ok()?;
        entries.get(peer)?.address.parse().ok()
    }

    /// Asks the host to show its identification notice.
    pub async fn identify(&self, host: &PeerId, core_name: &str) -> Result<(), String> {
        let conn = {
            let entries = self.entries.lock().map_err(|_| "registry unavailable")?;
            let entry = entries.get(host).ok_or("unknown host")?;
            entry.conn.clone().ok_or("host not connected")?
        };
        let req = Request::IdentifySelf {
            core_name: core_name.to_owned(),
            fingerprint: quic::fingerprint(host),
        };
        match quic::request::<_, Response>(&conn, &req, IDENTIFY_TIMEOUT).await? {
            Response::Ack => Ok(()),
            Response::Error { message } => Err(message),
            other => Err(format!("unexpected answer: {other:?}")),
        }
    }
}
