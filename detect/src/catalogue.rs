//! The built-in rule catalogue and its loader (ADR-0005).
//!
//! The catalogue is data: one JSON object per rule, embedded in the binary so
//! the Core works out of the box, and loadable from a directory for custom
//! rules. The workspace-write rule stays in code (`workspace.rs`); everything
//! else is data.

use std::{fs, path::Path};

use crate::{
    data::{compile_rule, DataRule, RuleFile},
    rules::Rule,
    workspace::WorkspaceWrite,
};

/// The embedded data rules, compiled.
// The embedded file is a compile-time constant: `expect` fails the Core at
// start rather than silently missing attacks, which is the fail-closed
// behaviour ADR-0005 requires.
#[allow(clippy::expect_used)]
pub fn builtin_data() -> Vec<DataRule> {
    let files: Vec<RuleFile> = serde_json::from_str(include_str!("../rules/default.json"))
        .expect("the embedded rule catalogue is valid JSON");
    files
        .into_iter()
        .map(|file| DataRule::compile(file).expect("every embedded rule compiles"))
        .collect()
}

/// The built-in catalogue, embedded at compile time: the data rules plus the
/// workspace-write rule. Panics at start on a broken catalogue: it must fail
/// closed, not silently miss attacks.
pub fn builtin() -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = builtin_data()
        .into_iter()
        .map(|rule| Box::new(rule) as Box<dyn Rule>)
        .collect();
    rules.push(Box::new(WorkspaceWrite));
    rules
}

/// Loads every `*.json` file in `dir` (each a single rule object or an array
/// of them), plus the workspace-write rule.
pub fn load_dir(dir: &Path) -> Result<Vec<Box<dyn Rule>>, String> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let files: Vec<RuleFile> = if value.is_array() {
            serde_json::from_value(value).map_err(|e| format!("{}: {e}", path.display()))?
        } else {
            vec![serde_json::from_value(value).map_err(|e| format!("{}: {e}", path.display()))?]
        };
        for file in files {
            rules.push(compile_rule(file)?);
        }
    }
    rules.push(Box::new(WorkspaceWrite));
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Field;
    use guardian_core::ToolCall;

    fn call(tool: &str, args: serde_json::Value) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: tool.into(),
            args,
            cwd: "/work".into(),
            host: None,
            call_id: None,
        }
    }

    /// Every rule in the catalogue: every `fire` example must fire, every
    /// `deny` example must not (ADR-0005).
    #[test]
    fn every_example_behaves_as_declared() {
        let rules = builtin_data();
        assert!(
            rules.len() >= 10,
            "expected a real catalogue, got {}",
            rules.len()
        );
        for rule in &rules {
            let Some(examples) = rule.examples() else {
                continue;
            };
            let tool = rule
                .tools()
                .first()
                .cloned()
                .unwrap_or_else(|| "bash".into());
            let args = |value: &str| {
                let key = match rule.field() {
                    Field::Command => "command",
                    Field::Path => "path",
                    Field::Url => "url",
                };
                serde_json::json!({ key: value })
            };
            for fire in &examples.fire {
                assert!(
                    rule.check(&call(&tool, args(fire))).is_some(),
                    "rule {} must fire on {fire:?}",
                    rule.id()
                );
            }
            for deny in &examples.deny {
                assert!(
                    rule.check(&call(&tool, args(deny))).is_none(),
                    "rule {} must not fire on {deny:?}",
                    rule.id()
                );
            }
        }
    }

    #[test]
    fn the_workspace_rule_is_included() {
        let rules = builtin();
        assert_eq!(rules.len(), builtin_data().len() + 1);
    }
}
