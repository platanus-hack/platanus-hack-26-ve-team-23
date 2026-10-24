//! Signed chain heads (ADR-0006, ADR-0019, ADR-0025): what the witness
//! stores and the archive keeps.
//!
//! A head covers one batch of events (`first_seq..=seq`): the chain head
//! after its last event and the Merkle root over the batch. It is valid only
//! if both the Ed25519 and the ML-DSA-65 signatures verify over the same
//! domain-separated bytes.

use ed25519_dalek::{Signer as _, Verifier as _};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};

use crate::chain::Digest;
use crate::keys::{hex_bytes, CoreKeys, CorePublic};

const DOMAIN: &[u8] = b"guardian.head.v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHead {
    /// First event of the batch this head covers.
    pub first_seq: u64,
    /// Sequence number of the last event covered by this head.
    pub seq: u64,
    pub timestamp_ms: u64,
    /// Chain head after event `seq`.
    #[serde(with = "hex_digest")]
    pub head: Digest,
    /// Merkle root over the events `first_seq..=seq` (ADR-0025).
    #[serde(with = "hex_digest")]
    pub merkle_root: Digest,
    #[serde(with = "hex_bytes")]
    pub ed25519_sig: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ml_dsa_65_sig: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadError {
    MalformedKey,
    MalformedSignature,
    BadEd25519,
    BadMlDsa,
}

fn message(
    first_seq: u64,
    seq: u64,
    timestamp_ms: u64,
    head: &Digest,
    merkle_root: &Digest,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 8 + 8 + 8 + 32 + 32);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(&first_seq.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m.extend_from_slice(head);
    m.extend_from_slice(merkle_root);
    m
}

impl SignedHead {
    pub fn sign(
        keys: &CoreKeys,
        first_seq: u64,
        seq: u64,
        timestamp_ms: u64,
        head: Digest,
        merkle_root: Digest,
    ) -> Self {
        let m = message(first_seq, seq, timestamp_ms, &head, &merkle_root);
        let ed = keys.ed.sign(&m);
        let pq: EncodedSignature<MlDsa65> = keys.pq.sign(&m).encode();
        Self {
            first_seq,
            seq,
            timestamp_ms,
            head,
            merkle_root,
            ed25519_sig: ed.to_bytes().to_vec(),
            ml_dsa_65_sig: pq.to_vec(),
        }
    }

    /// Number of events this head covers.
    pub fn batch_size(&self) -> u64 {
        self.seq.saturating_sub(self.first_seq) + 1
    }

    /// Checks that `event` is part of the batch this head covers, with the
    /// index and size taken from the head itself (ADR-0025). Verify the head's
    /// signatures first.
    pub fn verify_inclusion(&self, event: &crate::Event, path: &[Digest]) -> bool {
        if event.seq < self.first_seq || event.seq > self.seq {
            return false;
        }
        let (Ok(index), Ok(size)) = (
            usize::try_from(event.seq - self.first_seq),
            usize::try_from(self.batch_size()),
        ) else {
            return false;
        };
        crate::merkle::verify(
            &crate::merkle::leaf_hash(event),
            index,
            size,
            path,
            &self.merkle_root,
        )
    }

    pub fn verify(&self, public: &CorePublic) -> Result<(), HeadError> {
        let m = message(
            self.first_seq,
            self.seq,
            self.timestamp_ms,
            &self.head,
            &self.merkle_root,
        );

        let ed_key: [u8; 32] = public
            .ed25519
            .as_slice()
            .try_into()
            .map_err(|_| HeadError::MalformedKey)?;
        let ed_key = ed25519_dalek::VerifyingKey::from_bytes(&ed_key)
            .map_err(|_| HeadError::MalformedKey)?;
        let ed_sig: [u8; 64] = self
            .ed25519_sig
            .as_slice()
            .try_into()
            .map_err(|_| HeadError::MalformedSignature)?;
        ed_key
            .verify(&m, &ed25519_dalek::Signature::from_bytes(&ed_sig))
            .map_err(|_| HeadError::BadEd25519)?;

        let pq_key = EncodedVerifyingKey::<MlDsa65>::try_from(public.ml_dsa_65.as_slice())
            .map_err(|_| HeadError::MalformedKey)?;
        let pq_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&pq_key);
        let pq_sig = EncodedSignature::<MlDsa65>::try_from(self.ml_dsa_65_sig.as_slice())
            .map_err(|_| HeadError::MalformedSignature)?;
        let pq_sig =
            ml_dsa::Signature::<MlDsa65>::decode(&pq_sig).ok_or(HeadError::MalformedSignature)?;
        pq_key.verify(&m, &pq_sig).map_err(|_| HeadError::BadMlDsa)
    }
}

mod hex_digest {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(digest: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(digest))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let bytes = hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must be 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> CoreKeys {
        CoreKeys::from_seeds(&[7; 32], &[8; 32])
    }

    #[test]
    fn signed_head_verifies() {
        let k = keys();
        let head = SignedHead::sign(&k, 30, 41, 1_000, [9; 32], [8; 32]);
        assert_eq!(head.verify(&k.public()), Ok(()));
    }

    #[test]
    fn changed_head_fails_both_ways() {
        let k = keys();
        let mut head = SignedHead::sign(&k, 30, 41, 1_000, [9; 32], [8; 32]);
        head.head[0] ^= 1;
        assert_eq!(head.verify(&k.public()), Err(HeadError::BadEd25519));
    }

    #[test]
    fn a_bad_pq_signature_alone_fails() {
        let k = keys();
        let mut head = SignedHead::sign(&k, 30, 41, 1_000, [9; 32], [8; 32]);
        let other = SignedHead::sign(&k, 30, 42, 1_000, [9; 32], [8; 32]);
        head.ml_dsa_65_sig = other.ml_dsa_65_sig;
        assert_eq!(head.verify(&k.public()), Err(HeadError::BadMlDsa));
    }

    #[test]
    fn other_core_key_fails() {
        let head = SignedHead::sign(&keys(), 0, 1, 1, [0; 32], [0; 32]);
        let stranger = CoreKeys::from_seeds(&[1; 32], &[1; 32]).public();
        assert!(head.verify(&stranger).is_err());
    }

    #[test]
    fn json_round_trip() {
        let head = SignedHead::sign(&keys(), 0, 3, 4, [5; 32], [6; 32]);
        let json = serde_json::to_string(&head).unwrap();
        assert_eq!(serde_json::from_str::<SignedHead>(&json).unwrap(), head);
    }

    #[test]
    fn a_changed_merkle_root_or_range_fails() {
        let k = keys();
        let head = SignedHead::sign(&k, 30, 41, 1_000, [9; 32], [8; 32]);
        let mut root = head.clone();
        root.merkle_root[0] ^= 1;
        assert!(root.verify(&k.public()).is_err());
        let mut range = head;
        range.first_seq = 31;
        assert!(range.verify(&k.public()).is_err());
    }

    #[test]
    fn an_event_of_the_batch_is_proven_by_the_head() {
        use crate::{event::EventKind, merkle, Event};
        let events: Vec<Event> = (30..=41)
            .map(|seq| Event {
                seq,
                timestamp_ms: seq,
                kind: EventKind::Decision,
                payload: vec![1, 2],
            })
            .collect();
        let leaves: Vec<Digest> = events.iter().map(merkle::leaf_hash).collect();
        let k = keys();
        let head = SignedHead::sign(&k, 30, 41, 1_000, [9; 32], merkle::root(&leaves));
        assert_eq!(head.verify(&k.public()), Ok(()));
        let path = merkle::proof(&leaves, 5).unwrap();
        assert!(head.verify_inclusion(&events[5], &path));
        assert!(!head.verify_inclusion(&events[6], &path));
        let mut forged = events[5].clone();
        forged.payload = vec![9];
        assert!(!head.verify_inclusion(&forged, &path));
    }
}
