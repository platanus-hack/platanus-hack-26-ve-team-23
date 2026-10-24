//! Decides on tool calls: rules first, then the classifier (ADR-0005).
//!
//! The rules are written against the evaluation set (ADR-0010), which does
//! not exist yet. Until then every call is denied: the Guardian fails
//! closed, it never allows by default.

#![forbid(unsafe_code)]

use guardian_core::{Decision, ToolCall};

/// Stateful detector: sequence rules need the recent calls of a session.
#[derive(Debug, Default)]
pub struct Detector {}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decide(&mut self, _call: &ToolCall) -> Decision {
        Decision::deny("no detection rules loaded yet")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_until_rules_exist() {
        let call = ToolCall {
            session: "s".into(),
            tool: "bash".into(),
            args: serde_json::json!({ "command": "ls" }),
            cwd: "/work".into(),
        };
        assert!(!Detector::new().decide(&call).is_allow());
    }
}
