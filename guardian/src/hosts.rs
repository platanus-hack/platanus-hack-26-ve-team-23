//! The host daemons connected to this Core, by identity: what the witness
//! lists, and how the Core reaches a host to ask it to identify itself.
//!
//! A host is known by its Ed25519 transport identity (from the TLS
//! handshake), shown as a short fingerprint. Its hostname, OS, HWID and
//! interfaces are what it says about itself: labels and links, never
//! identities on their own (ADR-0028). Its IP and MAC are what the Core
//! observes.
//!
//! Quarantine is sticky by machine: the Core remembers every contained
//! identity, observed address and MAC, and the HWID bound to a contained
//! identity. When any of them comes back from a new address or with a new
//! key, `hello` says so and the caller contains the new address too.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::Mutex,
    time::Duration,
};

use edge_net::quic::{self, PeerId};
use guardian_core::{
    machine::{is_hwid, Mac, Nic},
    wire::{HostApproval, HostInfo, Request, Response},
};
use quinn::Connection;

use crate::core::now_ms;

const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(10);
/// Interfaces kept per host: enough for a workstation with VMs and
/// containers, bounded against a daemon that sends thousands.
pub const MAX_NICS: usize = 32;
/// Hosts kept in the registry. Past this, the disconnected ones seen
/// longest ago are forgotten, so an agent minting daemon keys in a loop
/// cannot grow the Core's memory without bound.
pub const MAX_HOSTS: usize = 1024;
/// HWID bindings kept for hosts that are not approved; approved ones are
/// always kept.
pub const MAX_HWIDS: usize = 4 * MAX_HOSTS;

#[derive(Debug)]
struct Entry {
    conn: Option<Connection>,
    ip: IpAddr,
    mac: Option<Mac>,
    hostname: String,
    os: String,
    hwid: String,
    nics: Vec<Nic>,
    conflict: Option<String>,
    last_seen_ms: u64,
}

/// Forgets disconnected hosts, oldest first, until at most `keep` remain.
fn evict(entries: &mut HashMap<PeerId, Entry>, keep: usize) {
    if entries.len() <= keep {
        return;
    }
    let mut idle: Vec<(PeerId, u64)> = entries
        .iter()
        .filter(|(_, e)| !e.is_connected())
        .map(|(id, e)| (*id, e.last_seen_ms))
        .collect();
    idle.sort_by_key(|(_, seen)| *seen);
    let excess = entries.len() - keep;
    for (id, _) in idle.into_iter().take(excess) {
        entries.remove(&id);
    }
}

impl Entry {
    fn is_connected(&self) -> bool {
        self.conn
            .as_ref()
            .is_some_and(|c| c.close_reason().is_none())
    }

    fn new(ip: IpAddr) -> Self {
        Self {
            conn: None,
            ip,
            mac: None,
            hostname: String::new(),
            os: String::new(),
            hwid: String::new(),
            nics: Vec::new(),
            conflict: None,
            last_seen_ms: 0,
        }
    }
}

/// What the Core remembers about contained machines.
#[derive(Debug, Default)]
struct Contained {
    peers: HashSet<PeerId>,
    hwids: HashSet<String>,
    macs: HashSet<Mac>,
    ips: HashSet<IpAddr>,
}

/// What a host's hello means for the Core.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Hello {
    /// Contain this host's current address and MAC: the reason.
    pub recontain: Option<String>,
    /// The identifiers do not add up: raise an alert with this reason.
    pub conflict: Option<String>,
}

#[derive(Debug, Default)]
pub struct Hosts {
    entries: Mutex<HashMap<PeerId, Entry>>,
    /// The identity each HWID is bound to: the approved one, or the first
    /// that reported it.
    hwid_owner: Mutex<HashMap<String, PeerId>>,
    contained: Mutex<Contained>,
}

impl Hosts {
    /// A peer connected. Witness connections are not hosts and are skipped by
    /// the caller.
    pub fn connected(&self, peer: PeerId, conn: Connection) {
        let ip = conn.remote_address().ip();
        if let Ok(mut entries) = self.entries.lock() {
            // Forget closed connections of peers that never introduced
            // themselves (probes, health checks), so they do not pile up.
            entries.retain(|_, e| !e.hostname.is_empty() || e.is_connected());
            evict(&mut entries, MAX_HOSTS - 1);
            let entry = entries.entry(peer).or_insert_with(|| Entry::new(ip));
            entry.conn = Some(conn);
            entry.ip = ip;
            entry.last_seen_ms = now_ms();
        }
    }

    /// Binds `hwid` to `peer`, as the owner's approval does: from now on
    /// another identity reporting it is in conflict.
    pub fn bind(&self, peer: PeerId, hwid: &str) {
        if !is_hwid(hwid) {
            return;
        }
        if let Ok(mut owners) = self.hwid_owner.lock() {
            owners.insert(hwid.to_owned(), peer);
        }
    }

    /// A host introduced itself from `ip`, where the Core sees `mac`.
    /// `approved` is the owner's approval of this identity, if any.
    #[allow(clippy::too_many_arguments)] // one call site, every value is distinct
    pub fn hello(
        &self,
        peer: PeerId,
        ip: IpAddr,
        mac: Option<Mac>,
        hostname: &str,
        os: &str,
        hwid: &str,
        nics: Vec<Nic>,
        approved: Option<&HostApproval>,
    ) -> Hello {
        // A malformed HWID is dropped, never stored or compared.
        let hwid = if is_hwid(hwid) { hwid } else { "" };
        let conflict = self.conflict(peer, hwid, approved);
        let mut outcome = Hello {
            conflict: conflict.clone(),
            ..Hello::default()
        };
        if let Ok(mut entries) = self.entries.lock() {
            // Only authenticated peers get here, after `connected`.
            if !entries.contains_key(&peer) {
                evict(&mut entries, MAX_HOSTS - 1);
            }
            let entry = entries.entry(peer).or_insert_with(|| Entry::new(ip));
            entry.ip = ip;
            entry.mac = mac;
            entry.hostname = hostname.chars().take(64).collect();
            entry.os = os.chars().take(32).collect();
            entry.hwid = hwid.to_owned();
            entry.nics = nics.into_iter().take(MAX_NICS).collect();
            entry.conflict = conflict;
            entry.last_seen_ms = now_ms();
        }
        outcome.recontain = self.sticky(peer, ip, mac, hwid);
        outcome
    }

    fn conflict(
        &self,
        peer: PeerId,
        hwid: &str,
        approved: Option<&HostApproval>,
    ) -> Option<String> {
        if let Some(approval) = approved {
            if approval.hwid != hwid {
                return Some(format!(
                    "{} reports another HWID than it was approved with: its key may have been copied to another machine",
                    quic::fingerprint(&peer)
                ));
            }
        }
        if hwid.is_empty() {
            return None;
        }
        let mut owners = self.hwid_owner.lock().ok()?;
        if owners.len() >= MAX_HWIDS && !owners.contains_key(hwid) {
            // Full of HWIDs no owner approved: a flood. Not bound, not
            // trusted; the host is still denied until approved.
            return None;
        }
        let owner = *owners.entry(hwid.to_owned()).or_insert(peer);
        (owner != peer).then(|| {
            format!(
                "{} reports the HWID of {}: the same machine with a new daemon key",
                quic::fingerprint(&peer),
                quic::fingerprint(&owner)
            )
        })
    }

    /// Why this host must be contained again, if it must: it is a contained
    /// identity, MAC or machine at an address or MAC not yet contained.
    fn sticky(&self, peer: PeerId, ip: IpAddr, mac: Option<Mac>, hwid: &str) -> Option<String> {
        let contained = self.contained.lock().ok()?;
        let why = if contained.peers.contains(&peer) {
            "same daemon identity"
        } else if mac.is_some_and(|m| contained.macs.contains(&m)) {
            "same MAC"
        } else if !hwid.is_empty() && contained.hwids.contains(hwid) {
            // A forged HWID can only get the forger contained: the target is
            // always this peer's own observed address.
            "same HWID"
        } else {
            return None;
        };
        let new_ip = !contained.ips.contains(&ip);
        let new_mac = mac.is_some_and(|m| !contained.macs.contains(&m));
        let new_peer = !contained.peers.contains(&peer);
        (new_ip || new_mac || new_peer).then(|| format!("re-contained: {why}"))
    }

    /// Remembers what was contained for `peer` at `ip` with `mac`. The HWID
    /// is remembered only if it is not in conflict, so nobody can push
    /// another machine's HWID into the sticky set.
    pub fn mark_contained(&self, peer: Option<PeerId>, ip: IpAddr, mac: Option<Mac>) {
        let hwid = peer.and_then(|p| {
            let entries = self.entries.lock().ok()?;
            let entry = entries.get(&p)?;
            (entry.conflict.is_none() && !entry.hwid.is_empty()).then(|| entry.hwid.clone())
        });
        if let Ok(mut contained) = self.contained.lock() {
            contained.ips.insert(ip);
            if let Some(peer) = peer {
                contained.peers.insert(peer);
            }
            if let Some(mac) = mac {
                contained.macs.insert(mac);
            }
            if let Some(hwid) = hwid {
                contained.hwids.insert(hwid);
            }
        }
    }

    /// The observed MAC and the reported HWID of a connected host.
    pub fn identifiers(&self, peer: &PeerId) -> (Option<Mac>, String) {
        self.entries
            .lock()
            .ok()
            .and_then(|e| e.get(peer).map(|e| (e.mac, e.hwid.clone())))
            .unwrap_or_default()
    }

    pub fn seen(&self, peer: &PeerId) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(peer) {
                entry.last_seen_ms = now_ms();
            }
        }
    }

    /// Every host that introduced itself; `approved` says whether the owner
    /// approved an identity with the HWID it reports.
    pub fn list(&self, approved: impl Fn(&PeerId, &str) -> bool) -> Vec<HostInfo> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };
        let contained = self.contained.lock().ok();
        let mut hosts: Vec<HostInfo> = entries
            .iter()
            // Only peers that introduced themselves as hosts.
            .filter(|(_, e)| !e.hostname.is_empty())
            .map(|(id, e)| HostInfo {
                id: hex::encode(id),
                fingerprint: quic::fingerprint(id),
                address: e.ip.to_string(),
                hostname: e.hostname.clone(),
                os: e.os.clone(),
                connected: e.is_connected(),
                last_seen_ms: e.last_seen_ms,
                hwid: e.hwid.clone(),
                mac: e.mac,
                nics: e.nics.clone(),
                contained: contained.as_ref().is_some_and(|c| {
                    c.peers.contains(id)
                        || c.ips.contains(&e.ip)
                        || e.mac.is_some_and(|m| c.macs.contains(&m))
                        || (e.conflict.is_none() && c.hwids.contains(&e.hwid))
                }),
                approved: approved(id, &e.hwid),
                conflict: e.conflict.clone(),
            })
            .collect();
        hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        hosts
    }

    fn conn(&self, host: &PeerId) -> Result<Connection, String> {
        let entries = self.entries.lock().map_err(|_| "registry unavailable")?;
        let entry = entries.get(host).ok_or("unknown host")?;
        entry
            .conn
            .clone()
            .ok_or_else(|| "host not connected".into())
    }

    async fn ask(&self, host: &PeerId, req: &Request) -> Result<(), String> {
        let conn = self.conn(host)?;
        match quic::request::<_, Response>(&conn, req, IDENTIFY_TIMEOUT).await? {
            Response::Ack => Ok(()),
            Response::Error { message } => Err(message),
            other => Err(format!("unexpected answer: {other:?}")),
        }
    }

    /// Asks the host to show its identification notice.
    pub async fn identify(&self, host: &PeerId, core_name: &str) -> Result<(), String> {
        let req = Request::IdentifySelf {
            core_name: core_name.to_owned(),
            fingerprint: quic::fingerprint(host),
        };
        self.ask(host, &req).await
    }

    /// Hands the owner's approval to the host, which pins this Core and
    /// this owner (ADR-0029).
    pub async fn enrolled(
        &self,
        host: &PeerId,
        approval: HostApproval,
        owner_public: String,
    ) -> Result<(), String> {
        let req = Request::Enrolled {
            approval,
            owner_public,
        };
        self.ask(host, &req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: PeerId = [1u8; 32];
    const B: PeerId = [2u8; 32];
    const HWID: &str = "0123456789abcdef0123456789abcdef";

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn mac(text: &str) -> Option<Mac> {
        Mac::parse(text)
    }

    fn hello(hosts: &Hosts, peer: PeerId, at: &str, m: Option<Mac>, hwid: &str) -> Hello {
        hosts.hello(peer, ip(at), m, "rig", "linux", hwid, Vec::new(), None)
    }

    #[test]
    fn a_new_key_with_the_hwid_of_another_is_a_conflict() {
        let hosts = Hosts::default();
        assert_eq!(hello(&hosts, A, "10.0.0.5", None, HWID), Hello::default());
        let second = hello(&hosts, B, "10.0.0.6", None, HWID);
        assert!(second.conflict.unwrap().contains("new daemon key"));
        // The first identity keeps its HWID without conflict.
        assert_eq!(hello(&hosts, A, "10.0.0.5", None, HWID).conflict, None);
    }

    #[test]
    fn an_approved_identity_with_another_hwid_is_a_conflict() {
        let hosts = Hosts::default();
        let approval = HostApproval {
            core: String::new(),
            host: hex::encode(A),
            hwid: HWID.into(),
            timestamp_ms: 0,
            signature: String::new(),
        };
        let other = "ffffffffffffffffffffffffffffffff";
        let seen = hosts.hello(
            A,
            ip("10.0.0.5"),
            None,
            "rig",
            "linux",
            other,
            Vec::new(),
            Some(&approval),
        );
        assert!(seen.conflict.unwrap().contains("copied"));
    }

    #[test]
    fn malformed_hwids_are_dropped() {
        let hosts = Hosts::default();
        assert_eq!(
            hello(&hosts, A, "10.0.0.5", None, "<b>x</b>"),
            Hello::default()
        );
        assert_eq!(
            hello(&hosts, B, "10.0.0.6", None, "<b>x</b>"),
            Hello::default()
        );
    }

    #[test]
    fn a_contained_identity_at_a_new_address_is_contained_again() {
        let hosts = Hosts::default();
        hello(&hosts, A, "10.0.0.5", None, HWID);
        hosts.mark_contained(Some(A), ip("10.0.0.5"), None);
        // Same address: nothing new to contain.
        assert_eq!(hello(&hosts, A, "10.0.0.5", None, HWID).recontain, None);
        let moved = hello(&hosts, A, "10.0.0.99", None, HWID);
        assert_eq!(
            moved.recontain.as_deref(),
            Some("re-contained: same daemon identity")
        );
    }

    #[test]
    fn a_contained_machine_with_a_new_key_is_contained_again() {
        let hosts = Hosts::default();
        hello(&hosts, A, "10.0.0.5", None, HWID);
        hosts.mark_contained(Some(A), ip("10.0.0.5"), None);
        let rekeyed = hello(&hosts, B, "10.0.0.7", None, HWID);
        assert_eq!(
            rekeyed.recontain.as_deref(),
            Some("re-contained: same HWID")
        );
        assert!(rekeyed.conflict.is_some());
    }

    #[test]
    fn a_contained_mac_with_a_new_address_is_contained_again() {
        let hosts = Hosts::default();
        let m = mac("52:54:00:12:34:56");
        hello(&hosts, A, "10.0.0.5", m, "");
        hosts.mark_contained(Some(A), ip("10.0.0.5"), m);
        let other_key = hello(&hosts, B, "10.0.0.8", m, "");
        assert_eq!(
            other_key.recontain.as_deref(),
            Some("re-contained: same MAC")
        );
    }

    #[test]
    fn a_forged_hwid_never_enters_the_sticky_set() {
        let hosts = Hosts::default();
        // The victim reports its HWID first.
        hello(&hosts, A, "10.0.0.5", None, HWID);
        // The attacker claims it, gets itself contained.
        hello(&hosts, B, "10.0.0.6", None, HWID);
        hosts.mark_contained(Some(B), ip("10.0.0.6"), None);
        // The victim reconnecting from a new address is not contained.
        assert_eq!(hello(&hosts, A, "10.0.0.50", None, HWID).recontain, None);
    }

    #[test]
    fn minted_keys_cannot_grow_the_registry_without_bound() {
        let hosts = Hosts::default();
        for i in 0..(MAX_HOSTS + 200) {
            let mut peer = [0u8; 32];
            peer[..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut hwid = format!("{i:032x}");
            hwid.truncate(32);
            hosts.hello(
                peer,
                ip("10.0.0.5"),
                None,
                "rig",
                "linux",
                &hwid,
                Vec::new(),
                None,
            );
        }
        assert!(hosts.list(|_, _| false).len() <= MAX_HOSTS);
    }

    #[test]
    fn nics_are_bounded() {
        let hosts = Hosts::default();
        let many: Vec<Nic> = (0..100)
            .map(|i| Nic::new(&format!("eth{i}"), Mac([2, 0, 0, 0, 0, i])))
            .collect();
        hosts.hello(A, ip("10.0.0.5"), None, "rig", "linux", HWID, many, None);
        let listed = hosts.list(|_, _| false);
        assert_eq!(listed[0].nics.len(), MAX_NICS);
        assert!(!listed[0].connected);
    }
}
