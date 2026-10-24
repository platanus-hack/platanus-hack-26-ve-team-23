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
    Paired = 7,
    Contained = 8,
    Released = 9,
    Configured = 10,
}

impl EventKind {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::ProxyRequest,
            2 => Self::ProxyResponse,
            3 => Self::HookRequest,
            4 => Self::Decision,
            5 => Self::Alert,
            6 => Self::LogOpened,
            7 => Self::Paired,
            8 => Self::Contained,
            9 => Self::Released,
            10 => Self::Configured,
            _ => return None,
        })
    }
}

/// Largest payload accepted when decoding, so a corrupted length field
/// cannot make the reader allocate gigabytes.
pub const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

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

    /// Inverse of `encode`. Returns the event and the number of bytes used,
    /// or `None` if the input is truncated, has a foreign domain, an unknown
    /// kind or an oversized payload.
    pub fn decode(bytes: &[u8]) -> Option<(Self, usize)> {
        let rest = bytes.strip_prefix(DOMAIN)?;
        let take8 =
            |b: &[u8]| -> Option<u64> { Some(u64::from_be_bytes(b.get(..8)?.try_into().ok()?)) };
        let seq = take8(rest)?;
        let timestamp_ms = take8(rest.get(8..)?)?;
        let kind = EventKind::from_u8(*rest.get(16)?)?;
        let len = usize::try_from(take8(rest.get(17..)?)?).ok()?;
        if len > MAX_PAYLOAD {
            return None;
        }
        let payload = rest.get(25..25 + len)?.to_vec();
        let used = DOMAIN.len() + 25 + len;
        Some((
            Self {
                seq,
                timestamp_ms,
                kind,
                payload,
            },
            used,
        ))
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

    #[test]
    fn decode_inverts_encode() {
        let event = Event {
            seq: 9,
            timestamp_ms: 77,
            kind: EventKind::Contained,
            payload: vec![1, 2, 3],
        };
        let mut bytes = event.encode();
        let used = bytes.len();
        bytes.extend_from_slice(b"next");
        assert_eq!(Event::decode(&bytes), Some((event, used)));
    }

    #[test]
    fn decode_rejects_truncated_and_foreign_input() {
        let bytes = Event {
            seq: 1,
            timestamp_ms: 1,
            kind: EventKind::Alert,
            payload: vec![0; 10],
        }
        .encode();
        assert_eq!(Event::decode(&bytes[..bytes.len() - 1]), None);
        assert_eq!(Event::decode(b"other.domain"), None);
    }
}
