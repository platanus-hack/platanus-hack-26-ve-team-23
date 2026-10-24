//! Decides on tool calls: rules first, then the classifier (ADR-0005), and
//! the policy that turns their findings into one outcome (ADR-0022).
//!
//! Concrete rules are written against the evaluation set (ADR-0010); this
//! crate provides the engine they plug into.

#![forbid(unsafe_code)]

pub mod catalogue;
pub mod data;
pub mod policy;
pub mod rules;
pub mod workspace;

use guardian_core::{wire::Thresholds, Decision, Finding, ToolCall};

pub use catalogue::{builtin, builtin_data, load_dir};
pub use data::{DataRule, Field, RuleFile};
pub use policy::Verdict;
pub use rules::Rule;
pub use workspace::WorkspaceWrite;

/// Runs every rule on a call and applies the policy.
#[derive(Debug, Default)]
pub struct Detector {
    rules: Vec<Box<dyn Rule>>,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rules(rules: Vec<Box<dyn Rule>>) -> Self {
        Self { rules }
    }

    pub fn decide(&mut self, call: &ToolCall) -> Verdict {
        self.decide_with(call, &Thresholds::default())
    }

    /// Decides with the owner's thresholds (ADR-0033).
    pub fn decide_with(&mut self, call: &ToolCall, thresholds: &Thresholds) -> Verdict {
        let findings: Vec<Finding> = self.rules.iter().filter_map(|r| r.check(call)).collect();
        policy::apply_with(findings, thresholds)
    }

    /// Convenience for callers that only need the answer.
    pub fn decision(&mut self, call: &ToolCall) -> Decision {
        self.decide(call).decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::Severity;

    #[derive(Debug)]
    struct DeletesHistory;

    impl Rule for DeletesHistory {
        fn check(&self, call: &ToolCall) -> Option<Finding> {
            let command = call.args.get("command")?.as_str()?;
            command.contains(".bash_history").then(|| Finding {
                rule: "test.history".into(),
                severity: Severity::High,
                reason: "deletes shell history".into(),
            })
        }
    }

    fn bash(command: &str) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: "bash".into(),
            args: serde_json::json!({ "command": command }),
            cwd: "/work".into(),
            host: None,
            call_id: None,
        }
    }

    #[test]
    fn no_finding_is_allowed() {
        assert!(Detector::new().decision(&bash("ls")).is_allow());
    }

    #[test]
    fn a_rule_finding_denies() {
        let mut detector = Detector::with_rules(vec![Box::new(DeletesHistory)]);
        assert!(!detector.decision(&bash("rm ~/.bash_history")).is_allow());
        assert!(detector.decision(&bash("cargo test")).is_allow());
    }
}
