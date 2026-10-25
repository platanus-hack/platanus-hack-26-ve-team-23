//! The classifier stage as a familiarity check (ADR-0036).
//!
//! The trained model recognises legitimate traffic, not novel attacks, so the
//! stage asks "is this like the legitimate calls we trained on?" and never
//! allows an unfamiliar one on its own word. Rules run first and still decide
//! through the policy (ADR-0022); this only adds a finding.
//!
//! The familiarity it can judge today is shell programs: a `bash` call whose
//! program is not in the allowlist is unfamiliar. `write`/`edit`/`read` inside
//! the workspace are the agent's ordinary work and are left to the existing
//! rules (`WorkspaceWrite`, secrets), so the stage does not block normal
//! editing. The artifact is distilled from the training corpus by
//! `training/export_familiarity.py`; it is not Granite running in the Core.

use std::collections::{BTreeMap, HashSet};

use guardian_core::{Finding, Severity, ToolCall};
use serde::Deserialize;

use crate::rules::Rule;

/// Prefixes that are not the program: privilege and wrapper commands.
const WRAPPERS: [&str; 7] = ["sudo", "doas", "env", "command", "exec", "nice", "nohup"];

#[derive(Debug, Deserialize)]
struct Artifact {
    programs: Vec<String>,
    unfamiliar_severity: BTreeMap<String, Severity>,
    default_unfamiliar_severity: Severity,
}

/// The familiarity stage: a program allowlist and the severity an unfamiliar
/// call gets per tool.
#[derive(Debug)]
pub struct Familiarity {
    programs: HashSet<String>,
    unfamiliar_severity: BTreeMap<String, Severity>,
    default_unfamiliar_severity: Severity,
}

impl Familiarity {
    /// The embedded artifact, parsed at start. Panics on a broken artifact so
    /// the Core fails closed rather than silently skipping the stage, the same
    /// contract as the embedded rule catalogue (ADR-0005, ADR-0036).
    #[allow(clippy::expect_used)]
    pub fn builtin() -> Self {
        let artifact: Artifact = serde_json::from_str(include_str!("../model/familiarity.json"))
            .expect("the embedded familiarity artifact is valid JSON");
        Self::from_artifact(artifact)
    }

    fn from_artifact(artifact: Artifact) -> Self {
        Self {
            programs: artifact.programs.into_iter().collect(),
            unfamiliar_severity: artifact.unfamiliar_severity,
            default_unfamiliar_severity: artifact.default_unfamiliar_severity,
        }
    }

    fn severity_for(&self, tool: &str) -> Severity {
        *self
            .unfamiliar_severity
            .get(tool)
            .unwrap_or(&self.default_unfamiliar_severity)
    }
}

impl Rule for Familiarity {
    fn check(&self, call: &ToolCall) -> Option<Finding> {
        // Only the shell is judged by familiarity; other tools are covered by
        // the path and field rules.
        if call.tool != "bash" {
            return None;
        }
        let command = call.args.get("command").and_then(|v| v.as_str())?;
        let reason = match program(command) {
            Some(name) if self.programs.contains(&name) => return None,
            Some(name) => format!("unfamiliar command: {name}"),
            None => "command the stage cannot parse".to_owned(),
        };
        Some(Finding {
            rule: "hawk.classifier.unfamiliar".into(),
            severity: self.severity_for(&call.tool),
            reason,
        })
    }
}

/// The program a shell line runs: its first bare token, with `VAR=value`
/// prefixes and wrapper commands skipped. `None` when the line does not start
/// with a plain program (a leading pipe, a subshell, an assignment only),
/// which the stage treats as unfamiliar.
fn program(command: &str) -> Option<String> {
    for token in command.split_whitespace() {
        if let Some((prefix, _)) = token.split_once('=') {
            if prefix.is_empty() || is_program(prefix) {
                continue; // VAR=value
            }
        }
        let name = token.rsplit('/').next().unwrap_or(token);
        if WRAPPERS.contains(&name) {
            continue;
        }
        return is_program(name).then(|| name.to_owned());
    }
    None
}

/// A program name: starts alphanumeric, then word characters, `.`, `+` or `-`.
fn is_program(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '+' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn stage() -> Familiarity {
        Familiarity::from_artifact(Artifact {
            programs: vec!["git".into(), "npm".into(), "cat".into()],
            unfamiliar_severity: BTreeMap::from([("bash".into(), Severity::High)]),
            default_unfamiliar_severity: Severity::Medium,
        })
    }

    #[test]
    fn a_familiar_program_does_not_fire() {
        assert!(stage().check(&bash("git status")).is_none());
        assert!(stage().check(&bash("VAR=1 npm test")).is_none());
        assert!(stage().check(&bash("cat file | grep x")).is_none());
        assert!(stage().check(&bash("/usr/bin/git log")).is_none());
    }

    #[test]
    fn an_unfamiliar_program_fires_high() {
        let finding = stage().check(&bash("frobnicate --all")).expect("fires");
        assert_eq!(finding.severity, Severity::High);
        let piped = stage().check(&bash("| sh")).expect("unparseable fires");
        assert_eq!(piped.severity, Severity::High);
    }

    #[test]
    fn non_shell_tools_are_left_to_the_rules() {
        let mut read = bash("x");
        read.tool = "read".into();
        read.args = serde_json::json!({ "path": "src/secret.rs" });
        assert!(stage().check(&read).is_none());
    }

    #[test]
    fn the_embedded_artifact_parses_and_knows_git() {
        let stage = Familiarity::builtin();
        assert!(stage.check(&bash("git status")).is_none());
        assert!(stage.check(&bash("npm run build")).is_none());
    }

    #[test]
    fn program_parses_wrappers_and_assignments() {
        assert_eq!(program("sudo apt update").as_deref(), Some("apt"));
        assert_eq!(program("A=1 B=2 make").as_deref(), Some("make"));
        assert_eq!(program("env X=1 node app.js").as_deref(), Some("node"));
        assert_eq!(program("(subshell)"), None);
    }
}
