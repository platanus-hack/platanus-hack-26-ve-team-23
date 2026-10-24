//! What the Core and the witness both compute during pairing (ADR-0017,
//! ADR-0030).

use sha2::{Digest as _, Sha256};

use crate::keys::CorePublic;

pub const PAIR_DOMAIN: &[u8] = b"guardian.pair.v2";
pub const HEAD_KEYS_DOMAIN: &[u8] = b"guardian.head-keys.v1";

/// Digest of the head-signing keys (Ed25519 and ML-DSA-65) a Core generates
/// when the wizard activates it (ADR-0030).
pub fn head_keys_digest(head: &CorePublic) -> [u8; 32] {
    Sha256::new()
        .chain_update(HEAD_KEYS_DOMAIN)
        .chain_update((head.ed25519.len() as u64).to_be_bytes())
        .chain_update(&head.ed25519)
        .chain_update((head.ml_dsa_65.len() as u64).to_be_bytes())
        .chain_update(&head.ml_dsa_65)
        .finalize()
        .into()
}

/// The bytes the owner signs to pair: the Core's one-time nonce, its
/// transport identity, the head keys it generated for this activation and
/// the witness app's transport identity. The signature is valid for that
/// set only: another Core, other head keys, another app or a replayed offer
/// fails.
pub fn pair_message(nonce: &[u8], core_id: &[u8], head: &CorePublic, witness_id: &[u8]) -> Vec<u8> {
    let mut message = PAIR_DOMAIN.to_vec();
    message.extend_from_slice(nonce);
    message.extend_from_slice(core_id);
    message.extend_from_slice(&head_keys_digest(head));
    message.extend_from_slice(witness_id);
    message
}

/// Six digits both screens show during pairing, to catch a device in the
/// middle on the local network. They cover the head keys too.
pub fn confirmation_code(core_id: &[u8], head: &CorePublic, owner_public: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(b"guardian.confirm.v2")
        .chain_update(core_id)
        .chain_update(head_keys_digest(head))
        .chain_update(owner_public)
        .finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::CoreKeys;

    fn head(seed: u8) -> CorePublic {
        CoreKeys::from_seeds(&[seed; 32], &[seed; 32]).public()
    }

    #[test]
    fn code_is_six_digits_and_depends_on_every_key() {
        let a = confirmation_code(b"core", &head(1), b"owner-a");
        assert_eq!(a.len(), 6);
        assert_ne!(a, confirmation_code(b"core", &head(1), b"owner-b"));
        assert_ne!(a, confirmation_code(b"other", &head(1), b"owner-a"));
        assert_ne!(a, confirmation_code(b"core", &head(2), b"owner-a"));
    }

    #[test]
    fn message_binds_nonce_core_head_keys_and_app() {
        let base = pair_message(b"n1", b"core", &head(1), b"app");
        assert_ne!(base, pair_message(b"n2", b"core", &head(1), b"app"));
        assert_ne!(base, pair_message(b"n1", b"other", &head(1), b"app"));
        assert_ne!(base, pair_message(b"n1", b"core", &head(2), b"app"));
        assert_ne!(base, pair_message(b"n1", b"core", &head(1), b"other-app"));
    }

    #[test]
    fn the_head_digest_covers_both_keys() {
        let a = head(1);
        let mut b = a.clone();
        b.ml_dsa_65[0] ^= 1;
        assert_ne!(head_keys_digest(&a), head_keys_digest(&b));
        let mut c = a.clone();
        c.ed25519[0] ^= 1;
        assert_ne!(head_keys_digest(&a), head_keys_digest(&c));
    }
}
