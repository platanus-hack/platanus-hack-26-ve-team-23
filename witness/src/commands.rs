//! Commands the web view may call.

use guardian_core::chain::GENESIS;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AppInfo {
    version: &'static str,
    /// Head of an empty chain, shown until the Guardian sends the first one.
    genesis_head: String,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION"),
        genesis_head: hex::encode(GENESIS),
    }
}
