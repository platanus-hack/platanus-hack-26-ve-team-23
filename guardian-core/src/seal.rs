//! Sealing event batches to the witness's weekly epoch key (ADR-0006,
//! ADR-0007). The Core holds only the epoch public key, so it can write the
//! record but never read it back.
//!
//! Construction: ephemeral X25519 against the epoch public key, HKDF-SHA256
//! over the shared secret (salted with both public keys), XChaCha20-Poly1305
//! with the ephemeral public key as associated data.
//!
//! Layout: `ephemeral_public (32) || nonce (24) || ciphertext + tag`.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

const INFO: &[u8] = b"guardian.seal.v1";
const HEADER: usize = 32 + 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// Shorter than the header, or the key exchange produced no secret.
    Malformed,
    /// Wrong key, or the data was altered.
    Rejected,
}

fn cipher(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let mut key = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's output limit.
    let _ = Hkdf::<Sha256>::new(Some(&salt), shared).expand(INFO, key.as_mut());
    XChaCha20Poly1305::new(key.as_ref().into())
}

pub fn seal<R: RngCore + CryptoRng>(
    recipient: &[u8; 32],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, SealError> {
    let recipient_key = PublicKey::from(*recipient);
    let ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&recipient_key);
    if !shared.was_contributory() {
        return Err(SealError::Malformed);
    }
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut nonce);

    let cipher = cipher(shared.as_bytes(), ephemeral_public.as_bytes(), recipient);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: ephemeral_public.as_bytes(),
            },
        )
        .map_err(|_| SealError::Rejected)?;

    let mut out = Vec::with_capacity(HEADER + ciphertext.len());
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open(recipient_secret: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < HEADER {
        return Err(SealError::Malformed);
    }
    let (ephemeral, rest) = sealed.split_at(32);
    let (nonce, ciphertext) = rest.split_at(24);
    let mut ephemeral_bytes = [0u8; 32];
    ephemeral_bytes.copy_from_slice(ephemeral);

    let secret = StaticSecret::from(*recipient_secret);
    let recipient = PublicKey::from(&secret);
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_bytes));
    if !shared.was_contributory() {
        return Err(SealError::Malformed);
    }
    cipher(shared.as_bytes(), &ephemeral_bytes, recipient.as_bytes())
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: ephemeral,
            },
        )
        .map_err(|_| SealError::Rejected)
}

/// The public key for an epoch secret, as the witness sends it to the Core.
pub fn epoch_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn round_trip() {
        let secret = [5u8; 32];
        let sealed = seal(&epoch_public(&secret), b"batch", &mut OsRng).unwrap();
        assert_eq!(open(&secret, &sealed).unwrap(), b"batch");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&epoch_public(&[5u8; 32]), b"batch", &mut OsRng).unwrap();
        assert_eq!(open(&[6u8; 32], &sealed), Err(SealError::Rejected));
    }

    #[test]
    fn altered_ciphertext_is_rejected() {
        let secret = [5u8; 32];
        let mut sealed = seal(&epoch_public(&secret), b"batch", &mut OsRng).unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(open(&secret, &sealed), Err(SealError::Rejected));
    }

    #[test]
    fn short_input_is_malformed() {
        assert_eq!(open(&[5u8; 32], &[0u8; 10]), Err(SealError::Malformed));
    }
}
