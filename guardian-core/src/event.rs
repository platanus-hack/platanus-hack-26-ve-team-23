//! Events in the record and their canonical encoding.
//!
//! The encoding is ours and fixed-layout (no serde) so that its bytes never
//! change with a library upgrade. Changing it breaks every existing chain;
//! the golden test below must then be updated deliberately.

/// What happened. The numeric values are part of the encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    ProxyRequest = 1,
    ProxyResponse = 2,
    HookRequest = 3,
    Decision = 4,
    Alert = 5,
    LogOpened = 6,
}

/// One entry of the record. `payload` is the encrypted batch content
/// (ADR-0006); the chain covers ciphertext, never plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub kind: EventKind,
    pub payload: Vec<u8>,
}

const DOMAIN: &[u8] = b"guardian.event.v1";

impl Event {
    /// `DOMAIN || seq || timestamp_ms || kind || len(payload) || payload`,
    /// integers big-endian.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN.len() + 8 + 8 + 1 + 8 + self.payload.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.push(self.kind as u8);
        out.extend_from_slice(&(self.payload.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_frozen() {
        let event = Event {
            seq: 1,
            timestamp_ms: 2,
            kind: EventKind::Decision,
            payload: vec![0xAA, 0xBB],
        };
        let mut expected = b"guardian.event.v1".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        expected.push(4);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2]);
        expected.extend_from_slice(&[0xAA, 0xBB]);
        assert_eq!(event.encode(), expected);
    }
}
