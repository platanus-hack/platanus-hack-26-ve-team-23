//! The hash chain over events.
//!
//! `head_n = SHA-256(DOMAIN || head_{n-1} || encode(event_n))`, starting
//! from 32 zero bytes. The witness stores signed heads; a rewritten event
//! changes every later head, so the stored ones no longer match.

use sha2::{Digest as _, Sha256};

use crate::event::Event;

pub type Digest = [u8; 32];

const DOMAIN: &[u8] = b"guardian.chain.v1";
pub const GENESIS: Digest = [0u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Events must be numbered 0, 1, 2... with no gaps.
    OutOfOrder { expected: u64, found: u64 },
    /// Recomputed head differs from the one claimed.
    HeadMismatch { at_seq: u64 },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfOrder { expected, found } => {
                write!(f, "event out of order: expected {expected}, found {found}")
            }
            Self::HeadMismatch { at_seq } => write!(f, "head mismatch at event {at_seq}"),
        }
    }
}

impl std::error::Error for ChainError {}

fn link(previous: &Digest, event: &Event) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(previous);
    hasher.update(event.encode());
    hasher.finalize().into()
}

/// Append-only chain kept by the Guardian.
#[derive(Debug, Clone)]
pub struct HashChain {
    head: Digest,
    next_seq: u64,
}

impl Default for HashChain {
    fn default() -> Self {
        Self {
            head: GENESIS,
            next_seq: 0,
        }
    }
}

impl HashChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn head(&self) -> Digest {
        self.head
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Appends the event and returns the new head.
    pub fn append(&mut self, event: &Event) -> Result<Digest, ChainError> {
        if event.seq != self.next_seq {
            return Err(ChainError::OutOfOrder {
                expected: self.next_seq,
                found: event.seq,
            });
        }
        self.head = link(&self.head, event);
        self.next_seq += 1;
        Ok(self.head)
    }
}

/// Recomputes the chain from genesis and checks it against a head the
/// witness holds for event `head_seq`.
pub fn verify(events: &[Event], head_seq: u64, expected_head: &Digest) -> Result<(), ChainError> {
    let mut chain = HashChain::new();
    for event in events {
        let head = chain.append(event)?;
        if event.seq == head_seq {
            return if &head == expected_head {
                Ok(())
            } else {
                Err(ChainError::HeadMismatch { at_seq: head_seq })
            };
        }
    }
    Err(ChainError::HeadMismatch { at_seq: head_seq })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn events(n: u64) -> Vec<Event> {
        (0..n)
            .map(|seq| Event {
                seq,
                timestamp_ms: 1_000 + seq,
                kind: EventKind::HookRequest,
                payload: format!("call {seq}").into_bytes(),
            })
            .collect()
    }

    fn head_after(events: &[Event]) -> Digest {
        let mut chain = HashChain::new();
        for e in events {
            chain.append(e).unwrap();
        }
        chain.head()
    }

    #[test]
    fn untouched_chain_verifies() {
        let evs = events(5);
        let head = head_after(&evs);
        assert_eq!(verify(&evs, 4, &head), Ok(()));
    }

    #[test]
    fn edited_event_is_detected() {
        let mut evs = events(5);
        let head = head_after(&evs);
        evs[2].payload = b"rewritten".to_vec();
        assert_eq!(
            verify(&evs, 4, &head),
            Err(ChainError::HeadMismatch { at_seq: 4 })
        );
    }

    #[test]
    fn deleted_event_is_detected() {
        let mut evs = events(5);
        let head = head_after(&evs);
        evs.remove(2);
        assert!(matches!(
            verify(&evs, 4, &head),
            Err(ChainError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn append_rejects_gaps() {
        let mut chain = HashChain::new();
        let mut evs = events(2);
        evs[1].seq = 5;
        chain.append(&evs[0]).unwrap();
        assert_eq!(
            chain.append(&evs[1]),
            Err(ChainError::OutOfOrder {
                expected: 1,
                found: 5
            })
        );
    }
}
