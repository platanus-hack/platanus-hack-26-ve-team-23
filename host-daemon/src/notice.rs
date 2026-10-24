//! The identification notice: when the owner presses "Identify" for this
//! host in the app, the Core asks the daemon to show itself on this
//! machine's screen, so the right machine can be found among dozens.
//!
//! The text is built here from sanitised values and passed to the system
//! notifier as a single argument, never through a shell.

use std::process::Command;

/// Keeps letters, digits and a few separators, and caps the length, so a
/// value from the network can never become command syntax.
fn clean(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | ':'))
        .take(max)
        .collect()
}

pub fn message(core_name: &str, fingerprint: &str, hostname: &str) -> String {
    format!(
        "HAWK: {} is identifying this machine. Host {} - fingerprint {}",
        clean(core_name, 40),
        clean(hostname, 40),
        clean(fingerprint, 24)
    )
}

/// Shows `text` to the people at this machine. Returns whether a notifier
/// accepted it; the log line is written either way.
pub fn show(text: &str) -> bool {
    tracing::warn!("{text}");
    let attempts: Vec<(&str, Vec<String>)> = if cfg!(windows) {
        // `msg *` reaches every interactive session, also when the daemon
        // runs as a service without a desktop of its own.
        vec![("msg", vec!["*".into(), "/TIME:120".into(), text.into()])]
    } else if cfg!(target_os = "macos") {
        vec![(
            "osascript",
            vec![
                "-e".into(),
                format!("display notification \"{text}\" with title \"HAWK\""),
            ],
        )]
    } else {
        vec![
            (
                "notify-send",
                vec!["-u".into(), "critical".into(), "HAWK".into(), text.into()],
            ),
            ("wall", vec![text.into()]),
        ]
    };
    attempts.into_iter().any(|(program, args)| {
        Command::new(program)
            .args(&args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_from_the_network_cannot_carry_syntax() {
        let text = message("Lab\"; rm -rf /", "a1b2-c3d4", "pc-01$(x)");
        assert!(!text.contains('"'));
        assert!(!text.contains(';'));
        assert!(!text.contains('$'));
        assert!(text.contains("a1b2-c3d4"));
    }
}
