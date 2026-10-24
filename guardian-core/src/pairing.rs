//! What the Core and the witness both compute during pairing (ADR-0017).

use sha2::{Digest as _, Sha256};

pub const PAIR_DOMAIN: &[u8] = b"guardian.pair.v1";

/// The bytes the owner's passkey signs to pair: the Core's one-time nonce and
/// its Ed25519 public key, so a signature cannot be reused for another Core.
pub fn pair_message(nonce: &[u8], core_ed25519: &[u8]) -> Vec<u8> {
    let mut message = PAIR_DOMAIN.to_vec();
    message.extend_from_slice(nonce);
    message.extend_from_slice(core_ed25519);
    message
}

/// Six digits both screens show during pairing, to catch a device in the
/// middle on the local network.
pub fn confirmation_code(core_ed25519: &[u8], owner_public: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(b"guardian.confirm.v1")
        .chain_update(core_ed25519)
        .chain_update(owner_public)
        .finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{n:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_six_digits_and_depends_on_both_keys() {
        let a = confirmation_code(b"core", b"owner-a");
        assert_eq!(a.len(), 6);
        assert_ne!(a, confirmation_code(b"core", b"owner-b"));
        assert_ne!(a, confirmation_code(b"other", b"owner-a"));
    }

    #[test]
    fn message_binds_nonce_and_core() {
        assert_ne!(pair_message(b"n1", b"core"), pair_message(b"n2", b"core"));
        assert_ne!(pair_message(b"n1", b"core"), pair_message(b"n1", b"x"));
    }
}
