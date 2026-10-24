//! The Core's state: keys, pairing, the sealed record and signed heads.
//!
//! Everything that must survive a restart lives in `GUARDIAN_DATA_DIR`:
//!
//! | File | Content |
//! |---|---|
//! | `keys.json` | Seeds of the Core's signing keys (to be sealed by the TPM) |
//! | `pairing.json` | Owner public key and the current epoch public key |
//! | `events.bin` | Encoded events, appended; replayed at start to rebuild the chain |
//! | `heads.jsonl` | Signed heads, one JSON object per line |
//!
//! The Core never holds a key that decrypts the record (ADR-0007): payloads
//! are sealed to the witness's epoch public key.

use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use detect::Verdict;
use guardian_core::{
    seal, CoreKeys, CorePublic, Decision, Event, EventKind, HashChain, Severity, SignedHead,
    ToolCall,
};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// A head is signed after this many events, or after any high or critical one.
const EVENTS_PER_HEAD: u64 = 10;
/// Metadata kept in memory for the witness dashboard.
const RECENT_EVENTS: usize = 1000;
const PAIR_DOMAIN: &[u8] = b"guardian.pair.v1";

#[derive(Debug)]
pub enum CoreError {
    Io(io::Error),
    Corrupt(&'static str),
    NotPaired,
    AlreadyPaired,
    BadPairing(&'static str),
}

impl From<io::Error> for CoreError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "i/o: {err}"),
            Self::Corrupt(what) => write!(f, "corrupt data: {what}"),
            Self::NotPaired => write!(f, "core not paired"),
            Self::AlreadyPaired => write!(f, "core already paired"),
            Self::BadPairing(why) => write!(f, "pairing rejected: {why}"),
        }
    }
}

impl std::error::Error for CoreError {}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    ed25519_seed: String,
    ml_dsa_65_seed: String,
}

/// What the Core stores after pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    /// Owner public key, P-256 SEC1 encoded, hex.
    pub owner_public: String,
    /// Current weekly epoch public key (X25519), hex.
    pub epoch_public: String,
    pub paired_at_ms: u64,
}

/// What the phone sends to pair (ADR-0017).
#[derive(Debug, Deserialize)]
pub struct PairRequest {
    pub owner_public: String,
    pub epoch_public: String,
    /// ECDSA P-256 signature (DER, hex) over
    /// `guardian.pair.v1 || nonce || core Ed25519 public key`.
    pub signature: String,
}

/// What a new Core offers to the phone.
#[derive(Debug, Clone, Serialize)]
pub struct PairOffer {
    pub core_public: CorePublic,
    pub nonce: String,
}

/// Metadata of one event, shown in the dashboard. Never the sealed content.
#[derive(Debug, Clone, Serialize)]
pub struct EventMeta {
    pub seq: u64,
    pub timestamp_ms: u64,
    pub kind: &'static str,
    pub session: Option<String>,
    pub tool: Option<String>,
    pub decision: Option<&'static str>,
    pub rule: Option<String>,
    pub severity: Option<Severity>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub paired: bool,
    pub events: u64,
    pub head: String,
    pub last_signed_seq: Option<u64>,
}

enum Pairing {
    Unpaired { nonce: [u8; 32] },
    Paired(PairingRecord),
}

struct Inner {
    pairing: Pairing,
    chain: HashChain,
    events: File,
    heads: Vec<SignedHead>,
    recent: VecDeque<EventMeta>,
    unsigned: u64,
}

pub struct Core {
    keys: CoreKeys,
    public: CorePublic,
    dir: PathBuf,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex32(text: &str, what: &'static str) -> Result<[u8; 32], CoreError> {
    hex::decode(text)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(CoreError::Corrupt(what))
}

fn load_or_create_keys(dir: &Path) -> Result<CoreKeys, CoreError> {
    let path = dir.join("keys.json");
    if path.exists() {
        let file: KeyFile = serde_json::from_slice(&fs::read(&path)?)
            .map_err(|_| CoreError::Corrupt("keys.json"))?;
        return Ok(CoreKeys::from_seeds(
            &hex32(&file.ed25519_seed, "keys.json")?,
            &hex32(&file.ml_dsa_65_seed, "keys.json")?,
        ));
    }
    let (ed, pq) = (random32(), random32());
    let file = KeyFile {
        ed25519_seed: hex::encode(ed),
        ml_dsa_65_seed: hex::encode(pq),
    };
    write_private(
        &path,
        &serde_json::to_vec_pretty(&file).map_err(|_| CoreError::Corrupt("keys"))?,
    )?;
    Ok(CoreKeys::from_seeds(&ed, &pq))
}

/// Writes a file readable only by the Core's user where the OS supports it.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// Rebuilds the chain from `events.bin`. Any gap, reordering or trailing
/// garbage is reported as corruption rather than silently skipped.
fn replay(path: &Path) -> Result<HashChain, CoreError> {
    let mut chain = HashChain::new();
    if !path.exists() {
        return Ok(chain);
    }
    let mut bytes = Vec::new();
    File::open(path)?.read_to_end(&mut bytes)?;
    let mut offset = 0;
    while offset < bytes.len() {
        let (event, used) =
            Event::decode(&bytes[offset..]).ok_or(CoreError::Corrupt("events.bin"))?;
        chain
            .append(&event)
            .map_err(|_| CoreError::Corrupt("events.bin order"))?;
        offset += used;
    }
    Ok(chain)
}

fn load_heads(path: &Path) -> Result<Vec<SignedHead>, CoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    fs::read_to_string(path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|_| CoreError::Corrupt("heads.jsonl")))
        .collect()
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

impl Core {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        let keys = load_or_create_keys(&dir)?;
        let public = keys.public();

        let pairing_path = dir.join("pairing.json");
        let pairing = if pairing_path.exists() {
            Pairing::Paired(
                serde_json::from_slice(&fs::read(&pairing_path)?)
                    .map_err(|_| CoreError::Corrupt("pairing.json"))?,
            )
        } else {
            Pairing::Unpaired { nonce: random32() }
        };

        let events_path = dir.join("events.bin");
        let chain = replay(&events_path)?;
        let events = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&events_path)?;
        let heads = load_heads(&dir.join("heads.jsonl"))?;
        let unsigned = chain.next_seq() - heads.last().map_or(0, |h| h.seq + 1);

        Ok(Self {
            keys,
            public,
            dir,
            inner: Mutex::new(Inner {
                pairing,
                chain,
                events,
                heads,
                recent: VecDeque::new(),
                unsigned,
            }),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, CoreError> {
        self.inner
            .lock()
            .map_err(|_| CoreError::Corrupt("state lock poisoned"))
    }

    pub fn public(&self) -> &CorePublic {
        &self.public
    }

    pub fn is_paired(&self) -> bool {
        self.lock()
            .map(|i| matches!(i.pairing, Pairing::Paired(_)))
            .unwrap_or(false)
    }

    pub fn pair_offer(&self) -> Result<PairOffer, CoreError> {
        match &self.lock()?.pairing {
            Pairing::Unpaired { nonce } => Ok(PairOffer {
                core_public: self.public.clone(),
                nonce: hex::encode(nonce),
            }),
            Pairing::Paired(_) => Err(CoreError::AlreadyPaired),
        }
    }

    /// Verifies the owner's signature over the offer and activates the Core.
    /// Returns the confirmation code.
    pub fn pair(&self, request: &PairRequest) -> Result<String, CoreError> {
        let mut inner = self.lock()?;
        let Pairing::Unpaired { nonce } = &inner.pairing else {
            return Err(CoreError::AlreadyPaired);
        };
        let owner = hex::decode(&request.owner_public)
            .map_err(|_| CoreError::BadPairing("owner key not hex"))?;
        let owner_key = VerifyingKey::from_sec1_bytes(&owner)
            .map_err(|_| CoreError::BadPairing("owner key not P-256"))?;
        hex32(&request.epoch_public, "epoch key")
            .map_err(|_| CoreError::BadPairing("epoch key not 32 bytes"))?;
        let signature = hex::decode(&request.signature)
            .ok()
            .and_then(|der| Signature::from_der(&der).ok())
            .ok_or(CoreError::BadPairing("signature not DER"))?;

        let mut message = PAIR_DOMAIN.to_vec();
        message.extend_from_slice(nonce);
        message.extend_from_slice(&self.public.ed25519);
        owner_key
            .verify(&message, &signature)
            .map_err(|_| CoreError::BadPairing("signature does not verify"))?;

        let record = PairingRecord {
            owner_public: request.owner_public.clone(),
            epoch_public: request.epoch_public.clone(),
            paired_at_ms: now_ms(),
        };
        write_private(
            &self.dir.join("pairing.json"),
            &serde_json::to_vec_pretty(&record).map_err(|_| CoreError::Corrupt("pairing"))?,
        )?;
        inner.pairing = Pairing::Paired(record);
        let code = confirmation_code(&self.public.ed25519, &owner);

        let meta = EventMeta {
            kind: "paired",
            ..EventMeta::empty()
        };
        Self::append(
            &self.keys,
            &self.dir,
            &mut inner,
            EventKind::Paired,
            b"paired",
            meta,
            true,
        )?;
        Ok(code)
    }

    /// Records a decision. If the record cannot be written, the caller must
    /// deny: an action that cannot be recorded does not run.
    pub fn record_decision(&self, call: &ToolCall, verdict: &Verdict) -> Result<(), CoreError> {
        let mut inner = self.lock()?;
        let epoch = match &inner.pairing {
            Pairing::Paired(record) => hex32(&record.epoch_public, "epoch key")?,
            Pairing::Unpaired { .. } => return Err(CoreError::NotPaired),
        };
        let plaintext = serde_json::to_vec(&serde_json::json!({
            "call": call,
            "decision": verdict.decision,
            "findings": verdict.findings,
            "contain": verdict.contain,
        }))
        .map_err(|_| CoreError::Corrupt("decision encoding"))?;
        let sealed = seal::seal(&epoch, &plaintext, &mut OsRng)
            .map_err(|_| CoreError::Corrupt("sealing failed"))?;

        let top = verdict.findings.iter().max_by_key(|f| f.severity);
        let meta = EventMeta {
            kind: "decision",
            session: Some(call.session.clone()),
            tool: Some(call.tool.clone()),
            decision: Some(match verdict.decision {
                Decision::Allow => "allow",
                Decision::Deny { .. } => "deny",
                Decision::Ask { .. } => "ask",
            }),
            rule: top.map(|f| f.rule.clone()),
            severity: top.map(|f| f.severity),
            reason: top.map(|f| f.reason.clone()),
            ..EventMeta::empty()
        };
        let urgent = top.is_some_and(|f| f.severity >= Severity::High);
        Self::append(
            &self.keys,
            &self.dir,
            &mut inner,
            EventKind::Decision,
            &sealed,
            meta,
            urgent,
        )
    }

    fn append(
        keys: &CoreKeys,
        dir: &Path,
        inner: &mut Inner,
        kind: EventKind,
        payload: &[u8],
        mut meta: EventMeta,
        urgent: bool,
    ) -> Result<(), CoreError> {
        let event = Event {
            seq: inner.chain.next_seq(),
            timestamp_ms: now_ms(),
            kind,
            payload: payload.to_vec(),
        };
        inner.events.write_all(&event.encode())?;
        inner.events.sync_data()?;
        let head = inner
            .chain
            .append(&event)
            .map_err(|_| CoreError::Corrupt("chain order"))?;

        meta.seq = event.seq;
        meta.timestamp_ms = event.timestamp_ms;
        if inner.recent.len() == RECENT_EVENTS {
            inner.recent.pop_front();
        }
        inner.recent.push_back(meta);

        inner.unsigned += 1;
        if urgent || inner.unsigned >= EVENTS_PER_HEAD {
            let signed = SignedHead::sign(keys, event.seq, event.timestamp_ms, head);
            let mut line = serde_json::to_vec(&signed).map_err(|_| CoreError::Corrupt("head"))?;
            line.push(b'\n');
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("heads.jsonl"))?
                .write_all(&line)?;
            inner.heads.push(signed);
            inner.unsigned = 0;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<Status, CoreError> {
        let inner = self.lock()?;
        Ok(Status {
            paired: matches!(inner.pairing, Pairing::Paired(_)),
            events: inner.chain.next_seq(),
            head: hex::encode(inner.chain.head()),
            last_signed_seq: inner.heads.last().map(|h| h.seq),
        })
    }

    /// Signed heads covering events after `since` (all when `None`).
    pub fn heads_since(&self, since: Option<u64>) -> Result<Vec<SignedHead>, CoreError> {
        let inner = self.lock()?;
        Ok(inner
            .heads
            .iter()
            .filter(|h| since.is_none_or(|s| h.seq > s))
            .cloned()
            .collect())
    }

    /// Dashboard metadata of events after `since`, oldest first.
    pub fn events_since(&self, since: Option<u64>) -> Result<Vec<EventMeta>, CoreError> {
        let inner = self.lock()?;
        Ok(inner
            .recent
            .iter()
            .filter(|e| since.is_none_or(|s| e.seq > s))
            .cloned()
            .collect())
    }
}

impl EventMeta {
    fn empty() -> Self {
        Self {
            seq: 0,
            timestamp_ms: 0,
            kind: "",
            session: None,
            tool: None,
            decision: None,
            rule: None,
            severity: None,
            reason: None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use guardian_core::{verify, Finding};
    use p256::ecdsa::{signature::Signer as _, SigningKey};

    pub struct TempDir(pub PathBuf);

    impl TempDir {
        pub fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("guardian-test-{name}-{}", hex::encode(random32())));
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Pairs `core` the way the phone would; returns the epoch secret.
    pub fn pair(core: &Core) -> [u8; 32] {
        let owner = SigningKey::random(&mut OsRng);
        let offer = core.pair_offer().unwrap();
        let mut message = PAIR_DOMAIN.to_vec();
        message.extend_from_slice(&hex::decode(&offer.nonce).unwrap());
        message.extend_from_slice(&offer.core_public.ed25519);
        let signature: Signature = owner.sign(&message);
        let epoch_secret = random32();
        core.pair(&PairRequest {
            owner_public: hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes()),
            epoch_public: hex::encode(seal::epoch_public(&epoch_secret)),
            signature: hex::encode(signature.to_der().as_bytes()),
        })
        .unwrap();
        epoch_secret
    }

    fn call() -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: "bash".into(),
            args: serde_json::json!({ "command": "ls" }),
            cwd: "/w".into(),
        }
    }

    fn verdict(severity: Option<Severity>) -> Verdict {
        detect::policy::apply(
            severity
                .map(|s| Finding {
                    rule: "test".into(),
                    severity: s,
                    reason: "test".into(),
                })
                .into_iter()
                .collect(),
        )
    }

    #[test]
    fn unpaired_core_records_nothing() {
        let dir = TempDir::new("unpaired");
        let core = Core::open(&dir.0).unwrap();
        assert!(!core.is_paired());
        assert!(matches!(
            core.record_decision(&call(), &verdict(None)),
            Err(CoreError::NotPaired)
        ));
    }

    #[test]
    fn pairing_rejects_a_bad_signature() {
        let dir = TempDir::new("badpair");
        let core = Core::open(&dir.0).unwrap();
        let owner = SigningKey::random(&mut OsRng);
        let signature: Signature = owner.sign(b"something else");
        let result = core.pair(&PairRequest {
            owner_public: hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes()),
            epoch_public: hex::encode([9u8; 32]),
            signature: hex::encode(signature.to_der().as_bytes()),
        });
        assert!(matches!(result, Err(CoreError::BadPairing(_))));
        assert!(!core.is_paired());
    }

    #[test]
    fn records_are_sealed_chained_signed_and_survive_restart() {
        let dir = TempDir::new("record");
        let epoch_secret;
        let public;
        {
            let core = Core::open(&dir.0).unwrap();
            epoch_secret = pair(&core);
            public = core.public().clone();
            core.record_decision(&call(), &verdict(None)).unwrap();
            core.record_decision(&call(), &verdict(Some(Severity::High)))
                .unwrap();
            assert!(core.pair_offer().is_err());
        }

        let core = Core::open(&dir.0).unwrap();
        assert!(core.is_paired());
        let status = core.status().unwrap();
        assert_eq!(status.events, 3);

        // The last head was signed because the last decision was high.
        let heads = core.heads_since(None).unwrap();
        let last = heads.last().unwrap();
        assert_eq!(last.seq, 2);
        assert_eq!(last.verify(&public), Ok(()));

        // The stored events replay to that head, and their payloads open
        // only with the witness's epoch secret.
        let bytes = fs::read(dir.0.join("events.bin")).unwrap();
        let mut events = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let (event, used) = Event::decode(&bytes[offset..]).unwrap();
            events.push(event);
            offset += used;
        }
        assert_eq!(verify(&events, 2, &last.head), Ok(()));
        let opened = seal::open(&epoch_secret, &events[1].payload).unwrap();
        assert!(String::from_utf8(opened)
            .unwrap()
            .contains("\"tool\":\"bash\""));
        assert!(seal::open(&[0u8; 32], &events[1].payload).is_err());
    }

    #[test]
    fn confirmation_code_is_six_digits_and_key_dependent() {
        let a = confirmation_code(b"core", b"owner-a");
        let b = confirmation_code(b"core", b"owner-b");
        assert_eq!(a.len(), 6);
        assert_ne!(a, b);
    }
}
