//! Which Core this daemon obeys, and which owner (ADR-0029).
//!
//! The pin comes from, in order:
//!
//! 1. **The build**: `HAWK_CORE_ID` (and optionally `HAWK_OWNER_PUBLIC`) set
//!    when the daemon is compiled. Fixed: nothing on the host can change it
//!    short of replacing the binary.
//! 2. **The environment**: `GUARDIAN_CORE_ID`, set by whoever installs the
//!    service.
//! 3. **Enrolment**: the owner approves this host from the app; the Core
//!    hands the signed approval over and the daemon writes `core.pin` (v2)
//!    with the Core, the owner and the epoch.
//!
//! Without any of them the daemon talks to the first active Core it finds,
//! for that session only, and persists nothing until the owner's approval
//! arrives. A v1 `core.pin` (the bare Core id) is still read.

use std::{fs, path::Path};

use guardian_core::wire::{approve_message, HostApproval};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Build,
    Env,
    Enrolment,
    /// A v1 file: the Core id only, from trust on first use.
    Legacy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub v: u32,
    /// Ed25519 identity of the Core, hex.
    pub core: String,
    /// P-256 owner key (SEC1, hex) that approved this host, once known.
    #[serde(default)]
    pub owner: Option<String>,
    /// Bumped when the owner moves this host to another Core (next step of
    /// ADR-0029); an older epoch is never accepted.
    #[serde(default)]
    pub epoch: u64,
    pub source: Source,
    #[serde(default)]
    pub approved_ms: Option<u64>,
}

fn hex32(text: &str) -> Option<[u8; 32]> {
    hex::decode(text.trim()).ok()?.try_into().ok()
}

impl Pin {
    pub fn core_id(&self) -> Option<[u8; 32]> {
        hex32(&self.core)
    }

    fn fixed(core: [u8; 32], owner: Option<String>, source: Source) -> Self {
        Self {
            v: VERSION,
            core: hex::encode(core),
            owner,
            epoch: 0,
            source,
            approved_ms: None,
        }
    }

    /// The pin compiled into this binary, if any.
    pub fn from_build() -> Option<Self> {
        let core = hex32(option_env!("HAWK_CORE_ID")?)?;
        let owner = option_env!("HAWK_OWNER_PUBLIC").map(str::to_owned);
        Some(Self::fixed(core, owner, Source::Build))
    }

    /// Reads `core.pin`: v2 JSON, or a v1 bare Core id.
    pub fn read(path: &Path) -> Option<Self> {
        let text = fs::read_to_string(path).ok()?;
        if let Ok(pin) = serde_json::from_str::<Self>(&text) {
            return (pin.v == VERSION && pin.core_id().is_some()).then_some(pin);
        }
        hex32(&text).map(|core| Self::fixed(core, None, Source::Legacy))
    }

    /// Whether this pin may be replaced by an enrolment pin written to disk.
    pub fn is_fixed(&self) -> bool {
        matches!(self.source, Source::Build | Source::Env)
    }
}

/// The pin in force: build, then environment, then file.
pub fn resolve(env: Option<[u8; 32]>, file: Option<&Path>) -> Option<Pin> {
    Pin::from_build()
        .or_else(|| env.map(|core| Pin::fixed(core, None, Source::Env)))
        .or_else(|| file.and_then(Pin::read))
}

/// Checks the owner's approval the Core handed over on the connection to
/// `core`, for this daemon (`host`, reporting `hwid`), against the pin in
/// force. Returns the pin to keep.
pub fn accept(
    current: Option<&Pin>,
    core: &[u8; 32],
    host: &[u8; 32],
    hwid: &str,
    approval: &HostApproval,
    owner_public: &str,
) -> Result<Pin, String> {
    if let Some(pin) = current {
        if pin.core_id().as_ref() != Some(core) {
            return Err("the approval came from a Core this daemon is not pinned to".into());
        }
        if let Some(owner) = &pin.owner {
            if owner != owner_public {
                return Err("the approval is signed by another owner than the pinned one".into());
            }
        }
    }
    if hex32(&approval.core).as_ref() != Some(core) {
        return Err("the approval names another Core".into());
    }
    if hex32(&approval.host).as_ref() != Some(host) {
        return Err("the approval is for another host".into());
    }
    if approval.hwid != hwid {
        return Err("the approval names another HWID than this machine's".into());
    }
    let key = hex::decode(owner_public)
        .ok()
        .and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok())
        .ok_or("the owner key is not P-256")?;
    let signature = hex::decode(&approval.signature)
        .ok()
        .and_then(|der| Signature::from_der(&der).ok())
        .ok_or("the approval signature is not DER")?;
    key.verify(
        &approve_message(core, host, hwid, approval.timestamp_ms),
        &signature,
    )
    .map_err(|_| "the owner's signature does not verify")?;

    let mut pin = current
        .cloned()
        .unwrap_or_else(|| Pin::fixed(*core, None, Source::Enrolment));
    if !pin.is_fixed() {
        pin.source = Source::Enrolment;
    }
    pin.owner = Some(owner_public.to_owned());
    pin.epoch = pin.epoch.max(1);
    pin.approved_ms = Some(approval.timestamp_ms);
    Ok(pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, SigningKey};
    use rand::rngs::OsRng;

    const CORE: [u8; 32] = [1; 32];
    const HOST: [u8; 32] = [2; 32];
    const HWID: &str = "0123456789abcdef0123456789abcdef";

    fn owner_hex(owner: &SigningKey) -> String {
        hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes())
    }

    fn approval(owner: &SigningKey, core: [u8; 32], host: [u8; 32], hwid: &str) -> HostApproval {
        let signature: Signature = owner.sign(&approve_message(&core, &host, hwid, 7));
        HostApproval {
            core: hex::encode(core),
            host: hex::encode(host),
            hwid: hwid.into(),
            timestamp_ms: 7,
            signature: hex::encode(signature.to_der().as_bytes()),
        }
    }

    #[test]
    fn an_unpinned_daemon_pins_core_and_owner_on_approval() {
        let owner = SigningKey::random(&mut OsRng);
        let pin = accept(
            None,
            &CORE,
            &HOST,
            HWID,
            &approval(&owner, CORE, HOST, HWID),
            &owner_hex(&owner),
        )
        .unwrap();
        assert_eq!(pin.core_id(), Some(CORE));
        assert_eq!(pin.owner, Some(owner_hex(&owner)));
        assert_eq!(pin.source, Source::Enrolment);
        assert_eq!(pin.epoch, 1);
        assert_eq!(pin.v, VERSION);
    }

    #[test]
    fn approvals_for_others_or_forged_are_refused() {
        let owner = SigningKey::random(&mut OsRng);
        let o = owner_hex(&owner);
        let other_hwid = "ffffffffffffffffffffffffffffffff";
        assert!(accept(
            None,
            &CORE,
            &HOST,
            HWID,
            &approval(&owner, [9; 32], HOST, HWID),
            &o
        )
        .is_err());
        assert!(accept(
            None,
            &CORE,
            &HOST,
            HWID,
            &approval(&owner, CORE, [9; 32], HWID),
            &o
        )
        .is_err());
        assert!(accept(
            None,
            &CORE,
            &HOST,
            HWID,
            &approval(&owner, CORE, HOST, other_hwid),
            &o
        )
        .is_err());
        let stranger = SigningKey::random(&mut OsRng);
        assert!(accept(
            None,
            &CORE,
            &HOST,
            HWID,
            &approval(&stranger, CORE, HOST, HWID),
            &o
        )
        .is_err());
    }

    #[test]
    fn a_pinned_daemon_ignores_other_cores_and_other_owners() {
        let owner = SigningKey::random(&mut OsRng);
        let pinned = Pin {
            owner: Some(owner_hex(&owner)),
            ..Pin::fixed(CORE, None, Source::Enrolment)
        };
        // Another Core, even with a valid approval for itself.
        let elsewhere = approval(&owner, [3; 32], HOST, HWID);
        assert!(accept(
            Some(&pinned),
            &[3; 32],
            &HOST,
            HWID,
            &elsewhere,
            &owner_hex(&owner)
        )
        .is_err());
        // The pinned Core, but another owner.
        let usurper = SigningKey::random(&mut OsRng);
        let theirs = approval(&usurper, CORE, HOST, HWID);
        assert!(accept(
            Some(&pinned),
            &CORE,
            &HOST,
            HWID,
            &theirs,
            &owner_hex(&usurper)
        )
        .is_err());
        // The pinned Core and owner.
        let ours = approval(&owner, CORE, HOST, HWID);
        assert!(accept(Some(&pinned), &CORE, &HOST, HWID, &ours, &owner_hex(&owner)).is_ok());
    }

    #[test]
    fn a_fixed_pin_stays_fixed() {
        let owner = SigningKey::random(&mut OsRng);
        let env = Pin::fixed(CORE, None, Source::Env);
        let pin = accept(
            Some(&env),
            &CORE,
            &HOST,
            HWID,
            &approval(&owner, CORE, HOST, HWID),
            &owner_hex(&owner),
        )
        .unwrap();
        assert_eq!(pin.source, Source::Env);
        assert!(pin.is_fixed());
    }

    #[test]
    fn pin_files_v1_and_v2_are_read_and_garbage_is_not() {
        let dir = std::env::temp_dir().join(format!(
            "hawk-pin-{}",
            hex::encode(rand::random::<[u8; 8]>())
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("core.pin");

        fs::write(&path, hex::encode(CORE)).unwrap();
        let legacy = Pin::read(&path).unwrap();
        assert_eq!(legacy.source, Source::Legacy);
        assert_eq!(legacy.core_id(), Some(CORE));

        let v2 = Pin {
            owner: Some("02ab".into()),
            epoch: 3,
            ..Pin::fixed(CORE, None, Source::Enrolment)
        };
        fs::write(&path, serde_json::to_vec(&v2).unwrap()).unwrap();
        assert_eq!(Pin::read(&path), Some(v2.clone()));

        let future = Pin { v: 9, ..v2 };
        fs::write(&path, serde_json::to_vec(&future).unwrap()).unwrap();
        assert_eq!(Pin::read(&path), None);
        fs::write(&path, "not a pin").unwrap();
        assert_eq!(Pin::read(&path), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_environment_wins_over_the_file() {
        // No build pin in test builds.
        if Pin::from_build().is_some() {
            return;
        }
        assert_eq!(
            resolve(Some(CORE), None).map(|p| p.source),
            Some(Source::Env)
        );
        assert_eq!(resolve(None, None), None);
    }
}
