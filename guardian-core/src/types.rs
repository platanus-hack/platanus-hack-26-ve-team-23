//! Messages exchanged between the agent hook and the Guardian.

use serde::{Deserialize, Serialize};

/// A tool call the agent wants to run, as sent by the hook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub session: String,
    pub tool: String,
    pub args: serde_json::Value,
    pub cwd: String,
}

/// The Guardian's answer. Anything other than `Allow` stops the tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny {
        reason: String,
    },
    /// The owner decides on the phone; the hook waits, and denies on timeout.
    Ask {
        reason: String,
    },
}

impl Decision {
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_wire_format_is_tagged() {
        let json = serde_json::to_string(&Decision::deny("log deletion")).unwrap();
        assert_eq!(json, r#"{"decision":"deny","reason":"log deletion"}"#);
        let allow: Decision = serde_json::from_str(r#"{"decision":"allow"}"#).unwrap();
        assert!(allow.is_allow());
    }
}
