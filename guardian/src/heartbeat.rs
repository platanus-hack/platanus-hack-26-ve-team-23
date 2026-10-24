//! Host heartbeat state and the dead man's switch (ADR-0021). The Core
//! challenges each enrolled host over its QUIC connection; a valid signed
//! heartbeat marks the host alive. A host that has not answered within the
//! window is quarantined by the caller (`AppState::heartbeat_round`).

use std::{collections::HashMap, sync::Mutex, time::Duration};

use ed25519_dalek::Verifier as _;
use guardian_core::wire::heartbeat_message;

use crate::core::now_ms;

/// How long a host may be silent before the dead man's switch fires
/// (ADR-0022).
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct Host {
    nonce: Option<[u8; 32]>,
    last_counter: u64,
    challenged_at_ms: u64,
    last_heartbeat_ms: u64,
}

#[derive(Debug, Default)]
pub struct Heartbeats {
    hosts: Mutex<HashMap<[u8; 32], Host>>,
}

impl Heartbeats {
    /// Issues a challenge to `peer` with a fresh nonce.
    pub fn challenge(&self, peer: &[u8; 32], nonce: [u8; 32]) {
        let mut hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        let host = hosts.entry(*peer).or_insert_with(|| Host {
            nonce: None,
            last_counter: 0,
            challenged_at_ms: 0,
            last_heartbeat_ms: 0,
        });
        host.nonce = Some(nonce);
        host.challenged_at_ms = now_ms();
    }

    /// Verifies a heartbeat answer and marks the host alive: signature over
    /// the nonce, counter, digest and boot measurement; the nonce must match
    /// the outstanding challenge; the counter must increase.
    pub fn verify(
        &self,
        peer: &[u8; 32],
        nonce: &[u8],
        counter: u64,
        digest: &[u8; 32],
        boot: &[u8; 32],
        signature_hex: &str,
    ) -> Result<(), String> {
        let signature = hex::decode(signature_hex)
            .ok()
            .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
            .ok_or("bad heartbeat signature")?;
        let verifying =
            ed25519_dalek::VerifyingKey::from_bytes(peer).map_err(|_| "bad host identity")?;
        verifying
            .verify(&heartbeat_message(nonce, counter, digest, boot), &signature)
            .map_err(|_| "heartbeat signature does not verify")?;

        let mut hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        let host = hosts.get_mut(peer).ok_or("host not challenged")?;
        if host.nonce.take().as_ref().map(|n| n.as_slice()) != Some(nonce) {
            return Err("heartbeat nonce mismatch".into());
        }
        if counter <= host.last_counter {
            return Err("heartbeat counter not monotonic".into());
        }
        host.last_counter = counter;
        host.last_heartbeat_ms = now_ms();
        Ok(())
    }

    /// Hosts whose last heartbeat (or challenge) is older than the window.
    pub fn stale(&self) -> Vec<[u8; 32]> {
        self.stale_at(now_ms())
    }

    fn stale_at(&self, now: u64) -> Vec<[u8; 32]> {
        let timeout_ms = HEARTBEAT_TIMEOUT.as_millis() as u64;
        let hosts = self.hosts.lock().unwrap_or_else(|p| p.into_inner());
        let mut stale: Vec<[u8; 32]> = hosts
            .iter()
            .filter(|(_, h)| {
                let anchor = h.last_heartbeat_ms.max(h.challenged_at_ms);
                anchor > 0 && now.saturating_sub(anchor) >= timeout_ms
            })
            .map(|(peer, _)| *peer)
            .collect();
        stale.sort_unstable();
        stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use rand::rngs::OsRng;

    fn gen_key() -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let peer = key.verifying_key().to_bytes();
        (key, peer)
    }

    #[test]
    fn a_valid_heartbeat_is_accepted() {
        let (key, peer) = gen_key();
        let hb = Heartbeats::default();
        let nonce = [5u8; 32];
        hb.challenge(&peer, nonce);

        let digest = [0u8; 32];
        let boot = [0u8; 32];
        let counter = 1;
        let signature = key.sign(&heartbeat_message(&nonce, counter, &digest, &boot));
        assert!(hb
            .verify(
                &peer,
                &nonce,
                counter,
                &digest,
                &boot,
                &hex::encode(signature.to_bytes())
            )
            .is_ok());
    }

    #[test]
    fn a_wrong_signature_or_counter_is_rejected() {
        let (key, peer) = gen_key();
        let (other, _) = gen_key();
        let hb = Heartbeats::default();
        let nonce = [5u8; 32];
        hb.challenge(&peer, nonce);

        let digest = [0u8; 32];
        let boot = [0u8; 32];
        // Signed by the wrong key.
        let bad = other.sign(&heartbeat_message(&nonce, 1, &digest, &boot));
        assert!(hb
            .verify(
                &peer,
                &nonce,
                1,
                &digest,
                &boot,
                &hex::encode(bad.to_bytes())
            )
            .is_err());

        // Correct key, but the counter does not increase.
        let ok = key.sign(&heartbeat_message(&nonce, 1, &digest, &boot));
        assert!(hb
            .verify(
                &peer,
                &nonce,
                1,
                &digest,
                &boot,
                &hex::encode(ok.to_bytes())
            )
            .is_ok());
        let replay = key.sign(&heartbeat_message(&nonce, 1, &digest, &boot));
        assert!(hb
            .verify(
                &peer,
                &nonce,
                1,
                &digest,
                &boot,
                &hex::encode(replay.to_bytes())
            )
            .is_err());
    }

    #[test]
    fn a_host_that_stops_answering_goes_stale() {
        let (_, peer) = gen_key();
        let hb = Heartbeats::default();
        hb.challenge(&peer, [9u8; 32]);
        let now = now_ms();
        assert!(hb
            .stale_at(now + HEARTBEAT_TIMEOUT.as_millis() as u64 - 1)
            .is_empty());
        assert!(hb
            .stale_at(now + HEARTBEAT_TIMEOUT.as_millis() as u64)
            .contains(&peer));
    }
}
