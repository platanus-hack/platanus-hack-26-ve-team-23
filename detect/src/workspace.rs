//! A rule that stays in code: writing outside the workspace (ADR-0005).
//!
//! Data rules match a single field with patterns, but "is this path outside
//! the working directory" needs a comparison against `cwd`, so it lives here.
//! The path is normalised lexically (`.`, `..`) before the comparison; a
//! target above the workspace is a high finding.

use std::path::{Component, Path, PathBuf};

use guardian_core::{Finding, Severity, ToolCall};

use crate::rules::Rule;

const PATH_FIELDS: [&str; 5] = ["path", "file_path", "to", "destination", "src"];

#[derive(Debug)]
pub struct WorkspaceWrite;

impl Rule for WorkspaceWrite {
    fn check(&self, call: &ToolCall) -> Option<Finding> {
        let target = target_path(call)?;
        let cwd = Path::new(&call.cwd);
        outside(cwd, target).then(|| Finding {
            rule: "hawk.workspace.write".into(),
            severity: Severity::High,
            reason: "writes outside the workspace".into(),
        })
    }
}

fn target_path(call: &ToolCall) -> Option<&str> {
    PATH_FIELDS
        .iter()
        .find_map(|k| call.args.get(k).and_then(|v| v.as_str()))
}

/// Resolves `.` and `..` lexically, without touching the filesystem (the
/// target may not exist yet).
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Whether `target`, resolved against `cwd`, lands outside `cwd`.
fn outside(cwd: &Path, target: &str) -> bool {
    let target = Path::new(target);
    let absolute = if target.is_absolute() {
        normalize(target)
    } else {
        normalize(&cwd.join(target))
    };
    let cwd = normalize(cwd);
    !absolute.starts_with(&cwd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(cwd: &str, path: &str) -> ToolCall {
        ToolCall {
            session: "s".into(),
            tool: "write_file".into(),
            args: serde_json::json!({ "path": path }),
            cwd: cwd.into(),
            host: None,
            call_id: None,
        }
    }

    fn checked(cwd: &str, path: &str) -> bool {
        WorkspaceWrite.check(&write(cwd, path)).is_some()
    }

    #[test]
    fn inside_the_workspace_is_allowed() {
        assert!(!checked("/work", "src/main.rs"));
        assert!(!checked("/work", "notes/../src/lib.rs"));
        assert!(!checked("/work", "/work/out.bin"));
    }

    #[test]
    fn outside_the_workspace_fires() {
        assert!(checked("/work", "../secret.txt"));
        assert!(checked("/work", "/etc/passwd"));
        assert!(checked("/work", "/tmp/../etc/shadow"));
        assert!(checked("/work", "sub/../../../root/.bashrc"));
    }

    #[test]
    fn no_path_field_is_ignored() {
        let call = ToolCall {
            session: "s".into(),
            tool: "bash".into(),
            args: serde_json::json!({ "command": "ls" }),
            cwd: "/work".into(),
            host: None,
            call_id: None,
        };
        assert!(WorkspaceWrite.check(&call).is_none());
    }
}
