//! The Core's signing identity: Ed25519 and ML-DSA-65 together (ADR-0019).
//!
//! Both keys are derived from 32-byte seeds the caller supplies, so this
//! crate never touches the operating system's random source.

use ml_dsa::{EncodedVerifyingKey, Keypair, MlDsa65, B32};
use serde::{Deserialize, Serialize};

/// Private signing keys of the Core.
pub struct CoreKeys {
    pub(crate) ed: ed25519_dalek::SigningKey,
    pub(crate) pq: ml_dsa::SigningKey<MlDsa65>,
}

impl std::fmt::Debug for CoreKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreKeys").finish_non_exhaustive()
    }
}

/// Public half, shared with the witness at pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorePublic {
    #[serde(with = "hex_bytes")]
    pub ed25519: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ml_dsa_65: Vec<u8>,
}

impl CoreKeys {
    /// `ed_seed` and `pq_seed` must come from a cryptographic random source
    /// and be stored sealed (TPM or OS keystore) by the caller.
    pub fn from_seeds(ed_seed: &[u8; 32], pq_seed: &[u8; 32]) -> Self {
        let pq_seed = B32::from(*pq_seed);
        Self {
            ed: ed25519_dalek::SigningKey::from_bytes(ed_seed),
            pq: ml_dsa::SigningKey::<MlDsa65>::from_seed(&pq_seed),
        }
    }

    /// The Ed25519 key, also the Core's QUIC/TLS identity (ADR-0023).
    pub fn transport_key(&self) -> &ed25519_dalek::SigningKey {
        &self.ed
    }

    pub fn public(&self) -> CorePublic {
        let pq_public: EncodedVerifyingKey<MlDsa65> = self.pq.verifying_key().encode();
        CorePublic {
            ed25519: self.ed.verifying_key().to_bytes().to_vec(),
            ml_dsa_65: pq_public.to_vec(),
        }
    }
}

/// Serde helper: byte vectors as lower-case hex strings.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seeds_same_public_keys() {
        let a = CoreKeys::from_seeds(&[1; 32], &[2; 32]).public();
        let b = CoreKeys::from_seeds(&[1; 32], &[2; 32]).public();
        assert_eq!(a, b);
        assert_eq!(a.ed25519.len(), 32);
        assert_eq!(a.ml_dsa_65.len(), 1952);
    }

    #[test]
    fn public_keys_round_trip_as_json() {
        let public = CoreKeys::from_seeds(&[3; 32], &[4; 32]).public();
        let json = serde_json::to_string(&public).unwrap();
        assert_eq!(serde_json::from_str::<CorePublic>(&json).unwrap(), public);
    }
}
