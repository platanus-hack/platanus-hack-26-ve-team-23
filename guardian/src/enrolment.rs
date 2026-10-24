//! Hosts the owner approved (ADR-0029). The Core decides only for these:
//! every other daemon is pending and every call it relays is denied.
//!
//! An approval is the owner's signature over the Core, the daemon identity,
//! the HWID that daemon reported and the time. The HWID never identifies a
//! host on its own: it is checked together with the identity, so a copy of
//! the key on another machine (another HWID) is not approved.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use edge_net::quic::PeerId;
use guardian_core::wire::{approve_message, HostApproval};

use crate::core::{now_ms, Core};

/// An approval older than this (or this far in the future) is refused.
pub const MAX_APPROVAL_AGE_MS: u64 = 60_000;
const FILE: &str = "approved-hosts.json";

#[derive(Debug)]
pub struct Enrolment {
    path: PathBuf,
    approved: Mutex<HashMap<PeerId, HostApproval>>,
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    hex::decode(text).ok()?.try_into().ok()
}

impl Enrolment {
    /// Loads the approvals kept in `dir`. A file that does not parse is
    /// ignored (logged): no host is approved, so every call is denied.
    pub fn open(dir: &Path) -> Self {
        let path = dir.join(FILE);
        let approved = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<Vec<HostApproval>>(&bytes) {
                Ok(list) => list
                    .into_iter()
                    .filter_map(|a| Some((hex32(&a.host)?, a)))
                    .collect(),
                Err(err) => {
                    tracing::error!(%err, "approved hosts unreadable; no host is approved");
                    HashMap::new()
                }
            },
            Err(_) => HashMap::new(),
        };
        Self {
            path,
            approved: Mutex::new(approved),
        }
    }

    /// Every approved identity with the HWID it was approved with.
    pub fn bindings(&self) -> Vec<(PeerId, String)> {
        self.approved
            .lock()
            .map(|a| a.iter().map(|(k, v)| (*k, v.hwid.clone())).collect())
            .unwrap_or_default()
    }

    pub fn approval(&self, host: &PeerId) -> Option<HostApproval> {
        self.approved.lock().ok()?.get(host).cloned()
    }

    /// Whether `host`, reporting `hwid` on its current connection, is the
    /// host the owner approved.
    pub fn is_approved(&self, host: &PeerId, hwid: &str) -> bool {
        self.approval(host).is_some_and(|a| a.hwid == hwid)
    }

    /// Checks and stores the owner's approval of `host`, which reports
    /// `hwid` on its live connection.
    pub fn approve(
        &self,
        core: &Core,
        approval: &HostApproval,
        hwid: &str,
    ) -> Result<PeerId, String> {
        let host = hex32(&approval.host).ok_or("bad host id")?;
        let core_id = hex32(&approval.core).ok_or("bad core id")?;
        if core.id() != core_id {
            return Err("the approval is for another Core".into());
        }
        if approval.hwid != hwid {
            return Err("the approval names another HWID than the host reports".into());
        }
        if now_ms().abs_diff(approval.timestamp_ms) > MAX_APPROVAL_AGE_MS {
            return Err("the approval is too old".into());
        }
        let message = approve_message(&core_id, &host, &approval.hwid, approval.timestamp_ms);
        core.verify_owner(&message, &approval.signature)
            .map_err(|e| e.to_string())?;

        let mut approved = self.approved.lock().map_err(|_| "registry unavailable")?;
        approved.insert(host, approval.clone());
        let list: Vec<&HostApproval> = approved.values().collect();
        let bytes = serde_json::to_vec_pretty(&list).map_err(|e| e.to_string())?;
        // Write then rename, so a crash never leaves half a file.
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, bytes)
            .and_then(|()| fs::rename(&tmp, &self.path))
            .map_err(|e| e.to_string())?;
        Ok(host)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::core::tests::{pair_with_owner, TempDir};
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};

    pub fn sign(
        owner: &SigningKey,
        core: &Core,
        host: &PeerId,
        hwid: &str,
        at: u64,
    ) -> HostApproval {
        let core_id = core.id();
        let signature: Signature = owner.sign(&approve_message(&core_id, host, hwid, at));
        HostApproval {
            core: hex::encode(core_id),
            host: hex::encode(host),
            hwid: hwid.into(),
            timestamp_ms: at,
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }

    const HOST: PeerId = [5u8; 32];
    const HWID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn an_owner_approval_is_kept_across_restarts() {
        let dir = TempDir::new("enrol-keep");
        let core = Core::open(&dir.0).unwrap();
        let (_, owner) = pair_with_owner(&core);
        let enrolment = Enrolment::open(&dir.0);
        assert!(!enrolment.is_approved(&HOST, HWID));
        enrolment
            .approve(&core, &sign(&owner, &core, &HOST, HWID, now_ms()), HWID)
            .unwrap();
        assert!(enrolment.is_approved(&HOST, HWID));
        assert!(Enrolment::open(&dir.0).is_approved(&HOST, HWID));
    }

    #[test]
    fn the_hwid_is_checked_with_the_identity() {
        let dir = TempDir::new("enrol-hwid");
        let core = Core::open(&dir.0).unwrap();
        let (_, owner) = pair_with_owner(&core);
        let enrolment = Enrolment::open(&dir.0);
        enrolment
            .approve(&core, &sign(&owner, &core, &HOST, HWID, now_ms()), HWID)
            .unwrap();
        // The same key on another machine is not the approved host.
        assert!(!enrolment.is_approved(&HOST, "ffffffffffffffffffffffffffffffff"));
        assert!(!enrolment.is_approved(&HOST, ""));
        // Another key on the same machine is not either.
        assert!(!enrolment.is_approved(&[6u8; 32], HWID));
    }

    #[test]
    fn forged_stale_or_mismatched_approvals_are_refused() {
        let dir = TempDir::new("enrol-refuse");
        let core = Core::open(&dir.0).unwrap();
        let (_, owner) = pair_with_owner(&core);
        let enrolment = Enrolment::open(&dir.0);
        let now = now_ms();

        let stranger = SigningKey::random(&mut rand::rngs::OsRng);
        let forged = sign(&stranger, &core, &HOST, HWID, now);
        assert!(enrolment.approve(&core, &forged, HWID).is_err());

        let stale = sign(&owner, &core, &HOST, HWID, now - MAX_APPROVAL_AGE_MS - 1);
        assert!(enrolment.approve(&core, &stale, HWID).is_err());

        let other_hwid = sign(&owner, &core, &HOST, HWID, now);
        assert!(enrolment
            .approve(&core, &other_hwid, "ffffffffffffffffffffffffffffffff")
            .is_err());

        let mut other_core = sign(&owner, &core, &HOST, HWID, now);
        other_core.core = hex::encode([9u8; 32]);
        assert!(enrolment.approve(&core, &other_core, HWID).is_err());

        // A valid signature moved to another host does not verify.
        let mut moved = sign(&owner, &core, &HOST, HWID, now);
        moved.host = hex::encode([6u8; 32]);
        assert!(enrolment.approve(&core, &moved, HWID).is_err());
        assert!(!enrolment.is_approved(&[6u8; 32], HWID));
    }
}
