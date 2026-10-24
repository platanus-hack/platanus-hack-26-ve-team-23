//! Commands the web view may call. All logic lives here: the web view only
//! shows results, and no key material ever crosses into it (ADR-0013).
//!
//! The owner key and the epoch key are kept in the app's data directory for
//! the desktop build and the demo. On Android they move into the Keystore
//! (see PENDIENTES.md); the commands do not change.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use edge_net::http::{client, get_json, post_json};
use guardian_core::{
    pairing::{confirmation_code, pair_message},
    seal, CorePublic, SignedHead,
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tauri::Manager;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const CALL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ANSWER: usize = 4 * 1024 * 1024;
/// Heads shown in the dashboard, newest last.
const HEADS_SHOWN: usize = 50;

#[derive(Debug, Serialize)]
pub struct AppInfo {
    version: &'static str,
    paired_here: bool,
}

#[derive(Debug, Deserialize)]
struct Offer {
    core_public: CorePublic,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct Paired {
    confirmation_code: String,
}

#[derive(Debug, Serialize)]
pub struct PairResult {
    /// Must match the code the Core prints in its log.
    confirmation_code: String,
}

#[derive(Debug, Serialize)]
pub struct HeadView {
    seq: u64,
    timestamp_ms: u64,
    head: String,
    valid: bool,
}

#[derive(Debug, Serialize)]
pub struct Dashboard {
    reachable: bool,
    error: Option<String>,
    /// This app holds the owner key the Core was paired with.
    paired_here: bool,
    /// The Core's identity equals the one pinned at pairing.
    identity_matches: Option<bool>,
    status: Option<serde_json::Value>,
    events: Vec<serde_json::Value>,
    heads_total: usize,
    heads_invalid: usize,
    heads: Vec<HeadView>,
}

fn data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn base(core_url: &str) -> Result<String, String> {
    let url = core_url.trim().trim_end_matches('/');
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(url.to_owned())
    } else {
        Err("the Core address must start with http:// or https://".into())
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn owner_key(dir: &Path) -> Result<SigningKey, String> {
    let path = dir.join("owner.key");
    if let Ok(text) = fs::read_to_string(&path) {
        let bytes = hex::decode(text.trim()).map_err(|_| "owner.key is corrupt")?;
        return SigningKey::from_slice(&bytes).map_err(|_| "owner.key is corrupt".to_owned());
    }
    let key = SigningKey::random(&mut OsRng);
    write_private(&path, hex::encode(key.to_bytes()).as_bytes()).map_err(|e| e.to_string())?;
    Ok(key)
}

fn epoch_secret(dir: &Path) -> Result<[u8; 32], String> {
    let path = dir.join("epoch.key");
    if let Ok(text) = fs::read_to_string(&path) {
        return hex::decode(text.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| "epoch.key is corrupt".to_owned());
    }
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    write_private(&path, hex::encode(secret).as_bytes()).map_err(|e| e.to_string())?;
    Ok(secret)
}

fn pinned(dir: &Path) -> Option<CorePublic> {
    serde_json::from_slice(&fs::read(dir.join("pinned.json")).ok()?).ok()
}

#[tauri::command]
pub fn app_info(app: tauri::AppHandle) -> Result<AppInfo, String> {
    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        paired_here: pinned(&data_dir(&app)?).is_some(),
    })
}

/// Pairs this app with a Core that has not been paired yet (ADR-0017).
#[tauri::command]
pub async fn pair_core(app: tauri::AppHandle, core_url: String) -> Result<PairResult, String> {
    let dir = data_dir(&app)?;
    if pinned(&dir).is_some() {
        return Err("this app is already paired with a Core".into());
    }
    let base = base(&core_url)?;
    let http = client(CONNECT_TIMEOUT);

    let offer: Offer = get_json(&http, &format!("{base}/pair"), CALL_TIMEOUT, MAX_ANSWER)
        .await
        .map_err(|e| format!("could not get the pairing offer: {e:?}"))?;
    let nonce = hex::decode(&offer.nonce).map_err(|_| "the Core sent a bad nonce")?;

    let owner = owner_key(&dir)?;
    let epoch = epoch_secret(&dir)?;
    let owner_public = owner.verifying_key().to_encoded_point(true);
    let signature: Signature = owner.sign(&pair_message(&nonce, &offer.core_public.ed25519));

    let answer: Paired = post_json(
        &http,
        &format!("{base}/pair"),
        &serde_json::json!({
            "owner_public": hex::encode(owner_public.as_bytes()),
            "epoch_public": hex::encode(seal::epoch_public(&epoch)),
            "signature": hex::encode(signature.to_der().as_bytes()),
        }),
        CALL_TIMEOUT,
        MAX_ANSWER,
    )
    .await
    .map_err(|e| format!("the Core rejected the pairing: {e:?}"))?;

    let expected = confirmation_code(&offer.core_public.ed25519, owner_public.as_bytes());
    if answer.confirmation_code != expected {
        return Err("confirmation codes differ: someone may be in the middle".into());
    }
    fs::write(
        dir.join("pinned.json"),
        serde_json::to_vec(&offer.core_public).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(PairResult {
        confirmation_code: expected,
    })
}

/// Everything the dashboard shows, with the signed heads verified against the
/// identity pinned at pairing.
#[tauri::command]
pub async fn dashboard(app: tauri::AppHandle, core_url: String) -> Result<Dashboard, String> {
    let dir = data_dir(&app)?;
    let base = base(&core_url)?;
    let http = client(CONNECT_TIMEOUT);
    let pin = pinned(&dir);

    let status: serde_json::Value =
        match get_json(&http, &format!("{base}/status"), CALL_TIMEOUT, MAX_ANSWER).await {
            Ok(status) => status,
            Err(err) => {
                return Ok(Dashboard {
                    reachable: false,
                    error: Some(format!("Core unreachable: {err:?}")),
                    paired_here: pin.is_some(),
                    identity_matches: None,
                    status: None,
                    events: Vec::new(),
                    heads_total: 0,
                    heads_invalid: 0,
                    heads: Vec::new(),
                })
            }
        };
    let identity: Option<CorePublic> =
        get_json(&http, &format!("{base}/identity"), CALL_TIMEOUT, MAX_ANSWER)
            .await
            .ok();
    let events: Vec<serde_json::Value> =
        get_json(&http, &format!("{base}/events"), CALL_TIMEOUT, MAX_ANSWER)
            .await
            .unwrap_or_default();
    let heads: Vec<SignedHead> =
        get_json(&http, &format!("{base}/heads"), CALL_TIMEOUT, MAX_ANSWER)
            .await
            .unwrap_or_default();

    let identity_matches = match (&pin, &identity) {
        (Some(pin), Some(identity)) => Some(pin == identity),
        _ => None,
    };
    // Heads are checked against the pinned key, never against what the Core
    // claims now: a swapped Core fails every head.
    let views: Vec<HeadView> = heads
        .iter()
        .map(|h| HeadView {
            seq: h.seq,
            timestamp_ms: h.timestamp_ms,
            head: hex::encode(h.head),
            valid: pin.as_ref().is_some_and(|p| h.verify(p).is_ok()),
        })
        .collect();
    let invalid = views.iter().filter(|h| !h.valid).count();
    let shown = views.len().saturating_sub(HEADS_SHOWN);

    Ok(Dashboard {
        reachable: true,
        error: None,
        paired_here: pin.is_some(),
        identity_matches,
        status: Some(status),
        events,
        heads_total: views.len(),
        heads_invalid: invalid,
        heads: views.into_iter().skip(shown).collect(),
    })
}
