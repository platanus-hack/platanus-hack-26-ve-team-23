//! The daemon's heartbeat state (ADR-0021): a monotonic counter and the
//! digests of the tool calls it has relayed since the previous heartbeat.
//! The key is the daemon's Ed25519 identity; on the demo it lives in
//! `host.key` (software), to move into the TPM (or the Hyper-V vTPM) with
//! measured boot later (see `PENDIENTES.md`).

use std::{path::PathBuf, sync::Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use guardian_core::{digest_set, wire::heartbeat_message};

pub struct Heartbeat {
    key: SigningKey,
    counter: Mutex<u64>,
    counter_file: Option<PathBuf>,
    observed: Mutex<Vec<[u8; 32]>>,
    boot: Option<[u8; 32]>,
}

impl std::fmt::Debug for Heartbeat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Heartbeat").finish_non_exhaustive()
    }
}

impl Heartbeat {
    /// Loads the persisted counter (if any) so a daemon restart does not send
    /// a counter that goes backwards. `boot` is this machine's boot
    /// measurement, `None` without a TPM.
    pub fn new(key: SigningKey, counter_file: Option<PathBuf>, boot: Option<[u8; 32]>) -> Self {
        let counter = counter_file
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| t.trim().parse::<u64>().ok())
            .unwrap_or(0);
        Self {
            key,
            counter: Mutex::new(counter),
            counter_file,
            observed: Mutex::new(Vec::new()),
            boot,
        }
    }

    /// This machine's boot measurement, `None` without a TPM.
    pub fn boot(&self) -> Option<[u8; 32]> {
        self.boot
    }

    /// Records a tool call the daemon relayed, for the next heartbeat.
    pub fn note_call(&self, digest: [u8; 32]) {
        if let Ok(mut observed) = self.observed.lock() {
            observed.push(digest);
        }
    }

    /// Produces a signed heartbeat for `nonce`: increments the counter,
    /// returns the counter, the digest of the observed calls and the boot
    /// measurement, and clears the observed set.
    pub fn beat(&self, nonce: &[u8]) -> (u64, [u8; 32], String, Option<[u8; 32]>) {
        let mut counter = self.counter.lock().unwrap_or_else(|p| p.into_inner());
        *counter += 1;
        if let Some(path) = &self.counter_file {
            let _ = super::write_private(path, counter.to_string().as_bytes());
        }
        let digest = {
            let mut observed = self.observed.lock().unwrap_or_else(|p| p.into_inner());
            let digest = digest_set(&observed);
            observed.clear();
            digest
        };
        let boot = self.boot.unwrap_or([0u8; 32]);
        let signature = self
            .key
            .sign(&heartbeat_message(nonce, *counter, &digest, &boot));
        (
            *counter,
            digest,
            hex::encode(signature.to_bytes()),
            self.boot,
        )
    }
}
