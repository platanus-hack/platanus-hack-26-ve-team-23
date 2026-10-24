//! The witness app. The same crate builds the desktop app (`cargo run -p
//! witness`) and the Android APK (`cargo tauri android build`); the mobile
//! entry point below is what the APK starts.
//!
//! All logic runs in Rust commands. The web view only displays results;
//! key material never crosses into it (ADR-0013).

mod commands;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = tracing_subscriber::fmt().try_init();
    let result = tauri::Builder::default()
        .manage(commands::Link::default())
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::discover,
            commands::pair_core,
            commands::configure_core,
            commands::identify_host,
            commands::forget_core,
            commands::dashboard
        ])
        .run(tauri::generate_context!());
    if let Err(err) = result {
        tracing::error!(%err, "witness stopped with an error");
    }
}
