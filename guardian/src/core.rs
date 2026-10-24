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
    merkle,
    pairing::{confirmation_code, pair_message},
    seal,
    wire::{config_hash, configure_message, ConfigSummary, CoreConfig},
    CoreKeys, CorePublic, Decision, Event, EventKind, HashChain, Severity, SignedHead, ToolCall,
};
use integrations::archive::ArchiveBatch;
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// A head is signed after this many events, or after any high or critical one.
const EVENTS_PER_HEAD: u64 = 10;
/// Metadata kept in memory for the witness dashboard.
const RECENT_EVENTS: usize = 1000;

#[derive(Debug)]
pub enum CoreError {
    Io(io::Error),
    Corrupt(&'static str),
    NotPaired,
    AlreadyPaired,
    BadPairing(&'static str),
    BadConfig(String),
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
            Self::BadConfig(why) => write!(f, "configuration rejected: {why}"),
        }
    }
}

impl std::error::Error for CoreError {}

/// The head-signing keys, written when the Core is activated (ADR-0030).
/// A Core from before ADR-0030 wrote this at first boot and used its
/// Ed25519 seed as the transport identity too.
#[derive(Serialize, Deserialize)]
struct KeyFile {
    ed25519_seed: String,
    ml_dsa_65_seed: String,
}

/// The transport identity, written at first boot (ADR-0030).
#[derive(Serialize, Deserialize)]
struct TransportFile {
    ed25519_seed: String,
}

/// What the Core stores after pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRecord {
    /// Owner public key, P-256 SEC1 encoded, hex.
    pub owner_public: String,
    /// Current weekly epoch public key (X25519), hex.
    pub epoch_public: String,
    pub paired_at_ms: u64,
    /// Transport identity (Ed25519, hex) of the witness app bound at pairing;
    /// the only peer the Core serves its record and configuration to.
    pub witness_id: String,
}

/// What the phone sends to pair (ADR-0017).
#[derive(Debug, Deserialize)]
pub struct PairRequest {
    pub owner_public: String,
    pub epoch_public: String,
    /// ECDSA P-256 signature (DER, hex) over `pairing::pair_message`: the
    /// nonce, the transport identity, the head keys offered and the app.
    pub signature: String,
}

/// What a dormant Core offers to the phone: the head keys it generated for
/// this activation and a one-time nonce.
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
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub paired: bool,
    pub events: u64,
    pub head: String,
    pub last_signed_seq: Option<u64>,
}

enum Pairing {
    /// Dormant. `pending` holds the seeds of the head keys generated when
    /// the wizard asked for the offer; they are kept only in memory until
    /// the owner's signature over them arrives.
    Unpaired {
        nonce: [u8; 32],
        pending: Option<([u8; 32], [u8; 32])>,
    },
    Paired(PairingRecord),
}

struct Inner {
    pairing: Pairing,
    /// The head-signing keys, from activation on.
    head: Option<(CoreKeys, CorePublic)>,
    chain: HashChain,
    events: File,
    heads: Vec<SignedHead>,
    recent: VecDeque<EventMeta>,
    /// Events since the last signed head: the batch the next head covers
    /// (ADR-0025).
    batch: Vec<Event>,
}

pub struct Core {
    /// The transport identity (ADR-0023), from first boot.
    transport: ed25519_dalek::SigningKey,
    id: [u8; 32],
    dir: PathBuf,
    inner: Mutex<Inner>,
    /// Off-site archive of every signed batch, when configured (ADR-0026).
    archiver: std::sync::OnceLock<integrations::archive::Archiver>,
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

/// The transport identity: created at first boot, or the Ed25519 seed of a
/// Core from before ADR-0030 (one key for both roles).
fn load_or_create_transport(dir: &Path) -> Result<ed25519_dalek::SigningKey, CoreError> {
    let path = dir.join("transport.json");
    if path.exists() {
        let file: TransportFile = serde_json::from_slice(&fs::read(&path)?)
            .map_err(|_| CoreError::Corrupt("transport.json"))?;
        return Ok(ed25519_dalek::SigningKey::from_bytes(&hex32(
            &file.ed25519_seed,
            "transport.json",
        )?));
    }
    let legacy = dir.join("keys.json");
    let seed = if legacy.exists() {
        let file: KeyFile = serde_json::from_slice(&fs::read(&legacy)?)
            .map_err(|_| CoreError::Corrupt("keys.json"))?;
        hex32(&file.ed25519_seed, "keys.json")?
    } else {
        random32()
    };
    let file = TransportFile {
        ed25519_seed: hex::encode(seed),
    };
    write_private(
        &path,
        &serde_json::to_vec_pretty(&file).map_err(|_| CoreError::Corrupt("transport"))?,
    )?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

/// The head keys written at activation, if any.
fn load_head_keys(dir: &Path) -> Result<Option<CoreKeys>, CoreError> {
    let path = dir.join("keys.json");
    if !path.exists() {
        return Ok(None);
    }
    let file: KeyFile =
        serde_json::from_slice(&fs::read(&path)?).map_err(|_| CoreError::Corrupt("keys.json"))?;
    Ok(Some(CoreKeys::from_seeds(
        &hex32(&file.ed25519_seed, "keys.json")?,
        &hex32(&file.ml_dsa_65_seed, "keys.json")?,
    )))
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

/// Rebuilds the chain from `events.bin` and returns it with the events from
/// `batch_from` on (those not yet covered by a signed head). Any gap,
/// reordering or trailing garbage is reported as corruption rather than
/// silently skipped.
fn replay(path: &Path, batch_from: u64) -> Result<(HashChain, Vec<Event>), CoreError> {
    let mut chain = HashChain::new();
    let mut batch = Vec::new();
    if !path.exists() {
        return Ok((chain, batch));
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
        if event.seq >= batch_from {
            batch.push(event);
        }
        offset += used;
    }
    Ok((chain, batch))
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

/// Who signed a configuration (ADR-0027).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigSource {
    /// The owner, from the paired app.
    Owner,
    /// The enterprise signer the owner authorised, fetched remotely.
    Enterprise,
}

impl ConfigSource {
    pub fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Enterprise => "enterprise",
        }
    }
}

/// What the Core reports about a configuration: no secrets.
pub fn summary(config: &CoreConfig) -> ConfigSummary {
    ConfigSummary {
        name: config.name.clone(),
        firewall: config.firewall.kind().to_owned(),
        version: config.version,
        hash: hex::encode(config_hash(config)),
        enterprise: config.enterprise_signer.is_some(),
        enterprise_signer: config.enterprise_signer.clone(),
        thresholds: config.thresholds,
    }
}

/// Checks an ECDSA P-256 signature (DER, hex) by `public_hex` (SEC1).
fn verify_p256(public_hex: &str, message: &[u8], signature_hex: &str) -> Result<(), CoreError> {
    let key = hex::decode(public_hex)
        .ok()
        .and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok())
        .ok_or_else(|| CoreError::BadConfig("enterprise signer is not a P-256 key".into()))?;
    let signature = hex::decode(signature_hex)
        .ok()
        .and_then(|der| Signature::from_der(&der).ok())
        .ok_or_else(|| CoreError::BadConfig("signature not DER".into()))?;
    key.verify(message, &signature)
        .map_err(|_| CoreError::BadConfig("signature does not verify".into()))
}

impl Core {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, CoreError> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        // First moment: only the transport identity, so the Core can be
        // discovered and reached over QUIC while it waits for the app.
        let transport = load_or_create_transport(&dir)?;
        let id = transport.verifying_key().to_bytes();

        let pairing_path = dir.join("pairing.json");
        let (pairing, head) = if pairing_path.exists() {
            let record: PairingRecord = serde_json::from_slice(&fs::read(&pairing_path)?)
                .map_err(|_| CoreError::Corrupt("pairing.json"))?;
            let keys = load_head_keys(&dir)?
                .ok_or(CoreError::Corrupt("a paired Core without keys.json"))?;
            let public = keys.public();
            (Pairing::Paired(record), Some((keys, public)))
        } else {
            // Dormant: head keys of an older first boot, if any, are not
            // used; activation generates new ones.
            (
                Pairing::Unpaired {
                    nonce: random32(),
                    pending: None,
                },
                None,
            )
        };

        let heads = load_heads(&dir.join("heads.jsonl"))?;
        let events_path = dir.join("events.bin");
        let (chain, batch) = replay(&events_path, heads.last().map_or(0, |h| h.seq + 1))?;
        let events = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&events_path)?;

        Ok(Self {
            transport,
            id,
            dir,
            inner: Mutex::new(Inner {
                pairing,
                head,
                chain,
                events,
                heads,
                recent: VecDeque::new(),
                batch,
            }),
            archiver: std::sync::OnceLock::new(),
        })
    }

    /// Starts handing every signed batch to the off-site archive.
    pub fn set_archiver(&self, archiver: integrations::archive::Archiver) {
        let _ = self.archiver.set(archiver);
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, CoreError> {
        self.inner
            .lock()
            .map_err(|_| CoreError::Corrupt("state lock poisoned"))
    }

    /// The transport identity (Ed25519 public key): what the app and the
    /// daemons pin and what discovery announces.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    pub fn transport_key(&self) -> &ed25519_dalek::SigningKey {
        &self.transport
    }

    /// The head keys, once the owner's app activated the Core (ADR-0030).
    pub fn head_public(&self) -> Option<CorePublic> {
        self.lock().ok()?.head.as_ref().map(|(_, p)| p.clone())
    }

    /// Where the Core keeps its state.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The paired owner's public key (P-256 SEC1, hex).
    pub fn owner_public(&self) -> Option<String> {
        match &self.lock().ok()?.pairing {
            Pairing::Paired(record) => Some(record.owner_public.clone()),
            Pairing::Unpaired { .. } => None,
        }
    }

    /// The witness identity bound at pairing.
    pub fn witness_id(&self) -> Option<[u8; 32]> {
        let inner = self.lock().ok()?;
        match &inner.pairing {
            Pairing::Paired(record) => hex32(&record.witness_id, "witness").ok(),
            Pairing::Unpaired { .. } => None,
        }
    }

    /// The owner's configuration, if any (ADR-0024).
    pub fn config(&self) -> Option<CoreConfig> {
        serde_json::from_slice(&fs::read(self.dir.join("config.json")).ok()?).ok()
    }

    /// Applies the next configuration of the chain (ADR-0027).
    ///
    /// - The owner signs from the app; an enterprise signer, if the owner
    ///   authorised one, signs configurations fetched remotely.
    /// - `version` must be exactly the active one plus one, and `prev` the
    ///   hash of the active configuration: an old configuration can never be
    ///   replayed and history cannot fork.
    /// - Only the owner can set, change or remove the enterprise signer, and a
    ///   remote configuration must not carry router secrets in clear text.
    ///
    /// Every applied configuration is appended to `config-chain.jsonl` and
    /// recorded as a `Configured` event in the main chain.
    pub fn apply_config(
        &self,
        config: &CoreConfig,
        signature_hex: &str,
        source: ConfigSource,
    ) -> Result<ConfigSummary, CoreError> {
        let current = self.config();
        let message = configure_message(config);
        match source {
            ConfigSource::Owner => self.verify_owner(&message, signature_hex)?,
            ConfigSource::Enterprise => {
                let signer = current
                    .as_ref()
                    .and_then(|c| c.enterprise_signer.clone())
                    .ok_or_else(|| {
                        CoreError::BadConfig("remote configuration is not authorised".into())
                    })?;
                verify_p256(&signer, &message, signature_hex)?;
                if config.enterprise_signer.as_deref() != Some(signer.as_str()) {
                    return Err(CoreError::BadConfig(
                        "only the owner can change the enterprise signer".into(),
                    ));
                }
                if config.has_secrets() {
                    return Err(CoreError::BadConfig(
                        "a remote configuration must not carry router secrets".into(),
                    ));
                }
            }
        }
        if !config.thresholds.is_valid() {
            return Err(CoreError::BadConfig(
                "thresholds: a high finding must at least ask, and asking cannot start above denying"
                    .into(),
            ));
        }
        let expected_version = current.as_ref().map_or(1, |c| c.version + 1);
        if config.version != expected_version {
            return Err(CoreError::BadConfig(format!(
                "version {} given, {expected_version} expected (no rollback, no skipping)",
                config.version
            )));
        }
        let expected_prev = current
            .as_ref()
            .map(|c| hex::encode(config_hash(c)))
            .unwrap_or_default();
        if config.prev != expected_prev {
            return Err(CoreError::BadConfig(
                "it does not follow the active configuration".into(),
            ));
        }

        write_private(
            &self.dir.join("config.json"),
            &serde_json::to_vec_pretty(config).map_err(|_| CoreError::Corrupt("config"))?,
        )?;
        let link = serde_json::json!({
            "version": config.version,
            "hash": hex::encode(config_hash(config)),
            "prev": config.prev,
            "source": source.name(),
            "signature": signature_hex,
            "applied_at_ms": now_ms(),
        });
        let mut line = serde_json::to_vec(&link).map_err(|_| CoreError::Corrupt("config chain"))?;
        line.push(b'\n');
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("config-chain.jsonl"))?
            .write_all(&line)?;

        let summary = summary(config);
        let meta = EventMeta {
            kind: "configured",
            reason: Some(format!(
                "configuration v{} by {} ({})",
                config.version,
                source.name(),
                summary.firewall
            )),
            ..EventMeta::empty()
        };
        // The sealed content never includes secrets.
        let content = serde_json::json!({ "summary": summary, "source": source.name() });
        self.record(EventKind::Configured, meta, &content, true)?;
        Ok(summary)
    }

    pub fn is_paired(&self) -> bool {
        self.lock()
            .map(|i| matches!(i.pairing, Pairing::Paired(_)))
            .unwrap_or(false)
    }

    /// The wizard starts the activation (ADR-0030): the second moment. The
    /// Core generates its head keys now, once per boot, and offers their
    /// public half with a one-time nonce. Nothing is written until the
    /// owner's signature over them arrives.
    pub fn pair_offer(&self) -> Result<PairOffer, CoreError> {
        let mut inner = self.lock()?;
        match &mut inner.pairing {
            Pairing::Unpaired { nonce, pending } => {
                let (ed, pq) = *pending.get_or_insert_with(|| (random32(), random32()));
                Ok(PairOffer {
                    core_public: CoreKeys::from_seeds(&ed, &pq).public(),
                    nonce: hex::encode(nonce),
                })
            }
            Pairing::Paired(_) => Err(CoreError::AlreadyPaired),
        }
    }

    /// Verifies the owner's signature over the offer and activates the Core.
    /// Returns the confirmation code.
    pub fn pair(&self, request: &PairRequest, witness_id: &[u8; 32]) -> Result<String, CoreError> {
        let mut inner = self.lock()?;
        let Pairing::Unpaired { nonce, pending } = &inner.pairing else {
            return Err(CoreError::AlreadyPaired);
        };
        let (ed_seed, pq_seed) =
            pending.ok_or(CoreError::BadPairing("ask for the pairing offer first"))?;
        let head = CoreKeys::from_seeds(&ed_seed, &pq_seed);
        let head_public = head.public();
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

        let message = pair_message(nonce, &self.id, &head_public, witness_id);
        owner_key
            .verify(&message, &signature)
            .map_err(|_| CoreError::BadPairing("signature does not verify"))?;

        // The head keys are written first: a Core is never paired without
        // the keys the owner signed for.
        let key_file = KeyFile {
            ed25519_seed: hex::encode(ed_seed),
            ml_dsa_65_seed: hex::encode(pq_seed),
        };
        write_private(
            &self.dir.join("keys.json"),
            &serde_json::to_vec_pretty(&key_file).map_err(|_| CoreError::Corrupt("keys"))?,
        )?;

        let record = PairingRecord {
            owner_public: request.owner_public.clone(),
            epoch_public: request.epoch_public.clone(),
            paired_at_ms: now_ms(),
            witness_id: hex::encode(witness_id),
        };
        write_private(
            &self.dir.join("pairing.json"),
            &serde_json::to_vec_pretty(&record).map_err(|_| CoreError::Corrupt("pairing"))?,
        )?;
        inner.pairing = Pairing::Paired(record);
        let code = confirmation_code(&self.id, &head_public, &owner);
        inner.head = Some((head, head_public));

        let meta = EventMeta {
            kind: "paired",
            ..EventMeta::empty()
        };
        self.append(&mut inner, EventKind::Paired, b"paired", meta, true)?;
        Ok(code)
    }

    /// Records a decision. If the record cannot be written, the caller must
    /// deny: an action that cannot be recorded does not run.
    pub fn record_decision(
        &self,
        call: &ToolCall,
        verdict: &Verdict,
    ) -> Result<EventMeta, CoreError> {
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
            host: call.host.clone(),
            ..EventMeta::empty()
        };
        let urgent = top.is_some_and(|f| f.severity >= Severity::High);
        self.append(&mut inner, EventKind::Decision, &sealed, meta, urgent)
    }

    fn append(
        &self,
        inner: &mut Inner,
        kind: EventKind,
        payload: &[u8],
        mut meta: EventMeta,
        urgent: bool,
    ) -> Result<EventMeta, CoreError> {
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
        inner.recent.push_back(meta.clone());

        inner.batch.push(event.clone());
        if urgent || inner.batch.len() as u64 >= EVENTS_PER_HEAD {
            let first_seq = inner.batch.first().map_or(event.seq, |e| e.seq);
            let leaves: Vec<_> = inner.batch.iter().map(merkle::leaf_hash).collect();
            let (keys, _) = inner.head.as_ref().ok_or(CoreError::NotPaired)?;
            let signed = SignedHead::sign(
                keys,
                first_seq,
                event.seq,
                event.timestamp_ms,
                head,
                merkle::root(&leaves),
            );
            let head_json = serde_json::to_vec(&signed).map_err(|_| CoreError::Corrupt("head"))?;
            let mut line = head_json.clone();
            line.push(b'\n');
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join("heads.jsonl"))?
                .write_all(&line)?;
            if let Some(archiver) = self.archiver.get() {
                archiver.submit(ArchiveBatch {
                    first_seq,
                    seq: event.seq,
                    events: inner.batch.iter().flat_map(Event::encode).collect(),
                    head_json,
                });
            }
            inner.heads.push(signed);
            inner.batch.clear();
        }
        Ok(meta)
    }

    /// Records any other event (alerts, containment): `content` is sealed to
    /// the epoch key like every payload, `meta` is what the dashboard and the
    /// sinks see.
    pub fn record(
        &self,
        kind: EventKind,
        meta: EventMeta,
        content: &serde_json::Value,
        urgent: bool,
    ) -> Result<EventMeta, CoreError> {
        let mut inner = self.lock()?;
        let epoch = match &inner.pairing {
            Pairing::Paired(record) => hex32(&record.epoch_public, "epoch key")?,
            Pairing::Unpaired { .. } => return Err(CoreError::NotPaired),
        };
        let plaintext =
            serde_json::to_vec(content).map_err(|_| CoreError::Corrupt("event encoding"))?;
        let sealed = seal::seal(&epoch, &plaintext, &mut OsRng)
            .map_err(|_| CoreError::Corrupt("sealing failed"))?;
        self.append(&mut inner, kind, &sealed, meta, urgent)
    }

    /// Checks a signature by the paired owner (DER, hex) over `message`.
    pub fn verify_owner(&self, message: &[u8], signature_hex: &str) -> Result<(), CoreError> {
        let inner = self.lock()?;
        let Pairing::Paired(record) = &inner.pairing else {
            return Err(CoreError::NotPaired);
        };
        let owner = hex::decode(&record.owner_public)
            .ok()
            .and_then(|b| VerifyingKey::from_sec1_bytes(&b).ok())
            .ok_or(CoreError::Corrupt("owner key"))?;
        let signature = hex::decode(signature_hex)
            .ok()
            .and_then(|der| Signature::from_der(&der).ok())
            .ok_or(CoreError::BadPairing("signature not DER"))?;
        owner
            .verify(message, &signature)
            .map_err(|_| CoreError::BadPairing("owner signature does not verify"))
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

    /// The sealed events of `[from_seq, to_seq]`, oldest first, re-read from
    /// `events.bin`. Payloads stay sealed: the Core cannot read them
    /// (ADR-0007).
    pub fn events_range(&self, from_seq: u64, to_seq: u64) -> Result<Vec<Event>, CoreError> {
        let _guard = self.lock()?;
        let path = self.dir.join("events.bin");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(path)?;
        let mut offset = 0;
        let mut out = Vec::new();
        while offset < bytes.len() {
            let (event, used) =
                Event::decode(&bytes[offset..]).ok_or(CoreError::Corrupt("events.bin"))?;
            if event.seq >= from_seq && event.seq <= to_seq {
                out.push(event);
            }
            offset += used;
        }
        Ok(out)
    }
}

impl EventMeta {
    pub fn empty() -> Self {
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
            host: None,
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

    /// Transport identity of the test witness.
    pub const WITNESS: [u8; 32] = [42u8; 32];

    /// Pairs `core` the way the phone would; returns the epoch secret.
    pub fn pair(core: &Core) -> [u8; 32] {
        pair_with_owner(core).0
    }

    /// Like `pair`, and also returns the owner's signing key.
    pub fn pair_with_owner(core: &Core) -> ([u8; 32], SigningKey) {
        let owner = SigningKey::random(&mut OsRng);
        let offer = core.pair_offer().unwrap();
        let message = pair_message(
            &hex::decode(&offer.nonce).unwrap(),
            &core.id(),
            &offer.core_public,
            &WITNESS,
        );
        let signature: Signature = owner.sign(&message);
        let epoch_secret = random32();
        core.pair(
            &PairRequest {
                owner_public: hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes()),
                epoch_public: hex::encode(seal::epoch_public(&epoch_secret)),
                signature: hex::encode(signature.to_der().as_bytes()),
            },
            &WITNESS,
        )
        .unwrap();
        (epoch_secret, owner)
    }

    fn call() -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: "bash".into(),
            args: serde_json::json!({ "command": "ls" }),
            cwd: "/w".into(),
            host: None,
            call_id: None,
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
        let result = core.pair(
            &PairRequest {
                owner_public: hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes()),
                epoch_public: hex::encode([9u8; 32]),
                signature: hex::encode(signature.to_der().as_bytes()),
            },
            &WITNESS,
        );
        assert!(matches!(result, Err(CoreError::BadPairing(_))));
        assert!(!core.is_paired());
    }

    /// ADR-0030: the transport identity at first boot, the head keys only
    /// when the wizard activates the Core, written only once the owner
    /// signed for them.
    #[test]
    fn head_keys_are_born_at_activation_not_at_boot() {
        let dir = TempDir::new("two-moments");
        let core = Core::open(&dir.0).unwrap();
        let id = core.id();
        assert!(dir.0.join("transport.json").exists());
        assert!(!dir.0.join("keys.json").exists());
        assert!(core.head_public().is_none());

        // The wizard asks for the offer: keys exist in memory only, and the
        // same ones are offered again until pairing.
        let offer = core.pair_offer().unwrap();
        assert_eq!(core.pair_offer().unwrap().core_public, offer.core_public);
        assert!(!dir.0.join("keys.json").exists());
        assert_ne!(offer.core_public.ed25519, id.to_vec());

        pair(&core);
        assert!(dir.0.join("keys.json").exists());
        assert_eq!(core.head_public(), Some(offer.core_public.clone()));
        drop(core);

        // A restart keeps both identities.
        let core = Core::open(&dir.0).unwrap();
        assert_eq!(core.id(), id);
        assert_eq!(core.head_public(), Some(offer.core_public));
    }

    #[test]
    fn pairing_needs_the_offer_and_a_signature_over_its_head_keys() {
        let dir = TempDir::new("pair-head");
        let core = Core::open(&dir.0).unwrap();
        let owner = SigningKey::random(&mut OsRng);
        let owner_public = hex::encode(owner.verifying_key().to_encoded_point(true).as_bytes());
        let request = |signature: Signature| PairRequest {
            owner_public: owner_public.clone(),
            epoch_public: hex::encode(seal::epoch_public(&random32())),
            signature: hex::encode(signature.to_der().as_bytes()),
        };
        // No offer asked yet: nothing to sign for.
        let early: Signature = owner.sign(b"anything");
        assert!(matches!(
            core.pair(&request(early), &WITNESS),
            Err(CoreError::BadPairing(_))
        ));

        // Signed over other head keys than the ones offered.
        let offer = core.pair_offer().unwrap();
        let nonce = hex::decode(&offer.nonce).unwrap();
        let other = CoreKeys::from_seeds(&[7; 32], &[7; 32]).public();
        let wrong: Signature = owner.sign(&pair_message(&nonce, &core.id(), &other, &WITNESS));
        assert!(core.pair(&request(wrong), &WITNESS).is_err());
        assert!(!dir.0.join("keys.json").exists());

        let right: Signature = owner.sign(&pair_message(
            &nonce,
            &core.id(),
            &offer.core_public,
            &WITNESS,
        ));
        assert!(core.pair(&request(right), &WITNESS).is_ok());
        assert!(core.is_paired());
    }

    /// A Core from before ADR-0030 used one Ed25519 key for both roles: it
    /// keeps its identity and its pinned head keys.
    #[test]
    fn a_core_from_before_two_moments_keeps_its_keys() {
        let dir = TempDir::new("legacy-keys");
        let (ed, pq) = ([3u8; 32], [4u8; 32]);
        fs::create_dir_all(&dir.0).unwrap();
        fs::write(
            dir.0.join("keys.json"),
            serde_json::to_vec(&KeyFile {
                ed25519_seed: hex::encode(ed),
                ml_dsa_65_seed: hex::encode(pq),
            })
            .unwrap(),
        )
        .unwrap();
        fs::write(
            dir.0.join("pairing.json"),
            serde_json::to_vec(&PairingRecord {
                owner_public: "02".into(),
                epoch_public: hex::encode([0u8; 32]),
                paired_at_ms: 1,
                witness_id: hex::encode(WITNESS),
            })
            .unwrap(),
        )
        .unwrap();
        let core = Core::open(&dir.0).unwrap();
        let legacy = CoreKeys::from_seeds(&ed, &pq).public();
        assert_eq!(core.id().to_vec(), legacy.ed25519);
        assert_eq!(core.head_public(), Some(legacy));
    }

    #[test]
    fn records_are_sealed_chained_signed_and_survive_restart() {
        let dir = TempDir::new("record");
        let epoch_secret;
        let public;
        {
            let core = Core::open(&dir.0).unwrap();
            epoch_secret = pair(&core);
            public = core.head_public().unwrap();
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
    fn heads_cover_contiguous_batches_and_prove_their_events() {
        let dir = TempDir::new("merkle");
        let core = Core::open(&dir.0).unwrap();
        pair(&core);
        let public = core.head_public().unwrap();
        for _ in 0..12 {
            core.record_decision(&call(), &verdict(None)).unwrap();
        }
        core.record_decision(&call(), &verdict(Some(Severity::High)))
            .unwrap();

        let heads = core.heads_since(None).unwrap();
        // Batches follow each other with no gap and no overlap.
        let mut next = 0;
        for head in &heads {
            assert_eq!(head.verify(&public), Ok(()));
            assert_eq!(head.first_seq, next);
            next = head.seq + 1;
        }

        // Any stored event is proven by the head of its batch.
        let bytes = fs::read(dir.0.join("events.bin")).unwrap();
        let mut events = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let (event, used) = Event::decode(&bytes[offset..]).unwrap();
            events.push(event);
            offset += used;
        }
        let head = heads
            .iter()
            .find(|h| h.first_seq <= 5 && 5 <= h.seq)
            .unwrap();
        let batch = &events[head.first_seq as usize..=head.seq as usize];
        let leaves: Vec<_> = batch.iter().map(merkle::leaf_hash).collect();
        let index = 5 - head.first_seq as usize;
        let path = merkle::proof(&leaves, index).unwrap();
        assert!(head.verify_inclusion(&events[5], &path));

        // After a restart, the open batch continues where it was.
        drop(core);
        let core = Core::open(&dir.0).unwrap();
        core.record_decision(&call(), &verdict(Some(Severity::High)))
            .unwrap();
        let last = core.heads_since(None).unwrap().pop().unwrap();
        assert_eq!(last.first_seq, next);
    }

    fn signed(config: &CoreConfig, key: &SigningKey) -> String {
        let signature: Signature = key.sign(&configure_message(config));
        hex::encode(signature.to_der().as_bytes())
    }

    fn next(current: Option<&CoreConfig>, name: &str) -> CoreConfig {
        CoreConfig {
            name: name.into(),
            firewall: guardian_core::wire::FirewallConfig::DryRun,
            version: current.map_or(1, |c| c.version + 1),
            prev: current
                .map(|c| hex::encode(config_hash(c)))
                .unwrap_or_default(),
            enterprise_signer: current.and_then(|c| c.enterprise_signer.clone()),
            thresholds: current.map(|c| c.thresholds).unwrap_or_default(),
        }
    }

    #[test]
    fn thresholds_travel_in_the_chain_and_keep_their_floors() {
        let dir = TempDir::new("config-thresholds");
        let core = Core::open(&dir.0).unwrap();
        let (_, owner) = pair_with_owner(&core);

        let mut v1 = next(None, "lab");
        v1.thresholds = guardian_core::wire::Thresholds {
            ask_from: Severity::Low,
            deny_from: Severity::Medium,
        };
        let summary = core
            .apply_config(&v1, &signed(&v1, &owner), ConfigSource::Owner)
            .unwrap();
        assert_eq!(summary.thresholds, v1.thresholds);
        assert_eq!(core.config().unwrap().thresholds, v1.thresholds);

        // A high finding allowed without asking breaks a floor: refused.
        let mut lax = next(Some(&v1), "lab");
        lax.thresholds = guardian_core::wire::Thresholds {
            ask_from: Severity::Critical,
            deny_from: Severity::Critical,
        };
        assert!(core
            .apply_config(&lax, &signed(&lax, &owner), ConfigSource::Owner)
            .is_err());
        assert_eq!(core.config().unwrap().version, 1);
    }

    #[test]
    fn the_configuration_chain_refuses_rollback_skips_and_forks() {
        let dir = TempDir::new("config-chain");
        let core = Core::open(&dir.0).unwrap();
        let (_, owner) = pair_with_owner(&core);

        let v1 = next(None, "one");
        core.apply_config(&v1, &signed(&v1, &owner), ConfigSource::Owner)
            .unwrap();
        let v2 = next(Some(&v1), "two");
        core.apply_config(&v2, &signed(&v2, &owner), ConfigSource::Owner)
            .unwrap();
        assert_eq!(core.config().unwrap().version, 2);

        // Replaying v1, even with its valid signature, is a rollback.
        assert!(core
            .apply_config(&v1, &signed(&v1, &owner), ConfigSource::Owner)
            .is_err());
        // Skipping a version.
        let mut skip = next(Some(&v2), "skip");
        skip.version = 4;
        assert!(core
            .apply_config(&skip, &signed(&skip, &owner), ConfigSource::Owner)
            .is_err());
        // A fork: right version, wrong previous link.
        let mut fork = next(Some(&v2), "fork");
        fork.prev = hex::encode(config_hash(&v1));
        assert!(core
            .apply_config(&fork, &signed(&fork, &owner), ConfigSource::Owner)
            .is_err());
        // A stranger's signature.
        let stranger = SigningKey::random(&mut OsRng);
        let v3 = next(Some(&v2), "three");
        assert!(core
            .apply_config(&v3, &signed(&v3, &stranger), ConfigSource::Owner)
            .is_err());

        // The applied links are in the chain file and in the record.
        let chain = fs::read_to_string(dir.0.join("config-chain.jsonl")).unwrap();
        assert_eq!(chain.lines().count(), 2);
        let kinds: Vec<_> = core
            .events_since(None)
            .unwrap()
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(kinds.iter().filter(|k| **k == "configured").count(), 2);
    }

    #[test]
    fn the_enterprise_signer_needs_the_owner_and_cannot_replace_itself() {
        let dir = TempDir::new("config-enterprise");
        let core = Core::open(&dir.0).unwrap();
        let (_, owner) = pair_with_owner(&core);
        let enterprise = SigningKey::random(&mut OsRng);
        let enterprise_public =
            hex::encode(enterprise.verifying_key().to_encoded_point(true).as_bytes());

        // Not authorised yet.
        let v1 = next(None, "remote");
        assert!(core
            .apply_config(&v1, &signed(&v1, &enterprise), ConfigSource::Enterprise)
            .is_err());

        // The owner authorises it.
        let mut v1 = next(None, "owner");
        v1.enterprise_signer = Some(enterprise_public.clone());
        core.apply_config(&v1, &signed(&v1, &owner), ConfigSource::Owner)
            .unwrap();

        // The enterprise signer can now publish the next link.
        let v2 = next(Some(&v1), "from-iac");
        core.apply_config(&v2, &signed(&v2, &enterprise), ConfigSource::Enterprise)
            .unwrap();
        assert_eq!(core.config().unwrap().name, "from-iac");

        // But it cannot change or remove the signer, nor carry secrets.
        let mut takeover = next(Some(&v2), "takeover");
        takeover.enterprise_signer = None;
        assert!(core
            .apply_config(
                &takeover,
                &signed(&takeover, &enterprise),
                ConfigSource::Enterprise
            )
            .is_err());
        let mut secret = next(Some(&v2), "secret");
        secret.firewall = guardian_core::wire::FirewallConfig::Openwrt {
            url: "https://r".into(),
            user: "hawk".into(),
            password: "plain".into(),
            cert_sha256: None,
        };
        assert!(core
            .apply_config(
                &secret,
                &signed(&secret, &enterprise),
                ConfigSource::Enterprise
            )
            .is_err());

        // The owner still can.
        let mut owner_change = next(Some(&v2), "owner-again");
        owner_change.enterprise_signer = None;
        core.apply_config(
            &owner_change,
            &signed(&owner_change, &owner),
            ConfigSource::Owner,
        )
        .unwrap();
        assert!(core.config().unwrap().enterprise_signer.is_none());
    }
}
