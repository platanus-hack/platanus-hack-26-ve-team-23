//! Agents besides OpenCode (ADR-0034): the `hook` command Claude Code and
//! Codex run before every tool call, and `hooks install|uninstall|status`,
//! which registers that command in their configuration.
//!
//! Both agents send a `PreToolUse` event as JSON on stdin and block the tool
//! when the hook exits with code 2 (the reason goes to stderr). The hook
//! normalises the call to the shape the rules read, asks this machine's
//! daemon, and denies on any failure: a hook that cannot reach HAWK must not
//! let the tool run.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    time::Duration,
};

use guardian_core::{Decision, ToolCall};
use serde::Deserialize;
use serde_json::{json, Map, Value};

/// Longer than the owner's 60 s to answer an `ask` (ADR-0022), shorter than
/// the timeout the hook is registered with.
const HOOK_DECIDE_TIMEOUT: Duration = Duration::from_secs(80);
/// What the agent waits for the hook before giving up (registered value).
const HOOK_TIMEOUT_SECS: u64 = 90;
const MAX_STDIN_BYTES: u64 = 4 * 1024 * 1024;

/// The agents with a `PreToolUse` hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    pub const ALL: [Agent; 2] = [Agent::Claude, Agent::Codex];

    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }

    pub fn parse(name: &str) -> Option<Agent> {
        Agent::ALL.into_iter().find(|a| a.name() == name)
    }
}

/// The `PreToolUse` input both agents send (Claude Code and Codex share the
/// field names).
#[derive(Debug, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(default)]
    pub tool_use_id: Option<String>,
}

fn string_field(input: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match input.get(*k) {
        Some(Value::String(s)) => Some(s.clone()),
        // Codex passes some commands as an argv array.
        Some(Value::Array(parts)) => Some(
            parts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    })
}

/// The files an `apply_patch` touches, from its `*** ... File:` headers.
fn patch_paths(patch: &str) -> Vec<String> {
    patch
        .lines()
        .filter_map(|line| {
            [
                "*** Add File: ",
                "*** Update File: ",
                "*** Delete File: ",
                "*** Move to: ",
            ]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix))
        })
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect()
}

/// The path the workspace rule should judge: one that leaves the project if
/// any does, otherwise the first.
fn riskiest(paths: &[String]) -> Option<String> {
    paths
        .iter()
        .find(|p| p.starts_with('/') || p.starts_with('~') || p.contains("..") || p.contains(':'))
        .or_else(|| paths.first())
        .cloned()
}

/// Maps an agent's tool call to the shape the rules read (`detect`): `bash`
/// with `command`, `write`/`edit`/`read` with `path`, `webfetch` with `url`.
/// The session carries the agent's name, so the record says who acted.
pub fn normalize(agent: Agent, input: HookInput) -> ToolCall {
    let raw = input.tool_input;
    let name = input.tool_name.to_ascii_lowercase();
    let (tool, args) = match name.as_str() {
        "bash" | "shell" | "local_shell" | "exec_command" | "unified_exec" => {
            let command = string_field(&raw, &["command", "cmd"]).unwrap_or_default();
            (
                "bash".to_owned(),
                json!({ "command": command, "input": raw }),
            )
        }
        "write" => {
            let path = string_field(&raw, &["file_path", "path"]).unwrap_or_default();
            ("write".to_owned(), json!({ "path": path, "input": raw }))
        }
        "edit" | "multiedit" | "notebookedit" => {
            let path =
                string_field(&raw, &["file_path", "notebook_path", "path"]).unwrap_or_default();
            ("edit".to_owned(), json!({ "path": path, "input": raw }))
        }
        "apply_patch" => {
            let patch = string_field(&raw, &["input", "patch", "command"]).unwrap_or_default();
            let paths = patch_paths(&patch);
            let path = riskiest(&paths).unwrap_or_default();
            (
                "edit".to_owned(),
                json!({ "path": path, "paths": paths, "input": raw }),
            )
        }
        "read" => {
            let path = string_field(&raw, &["file_path", "path"]).unwrap_or_default();
            ("read".to_owned(), json!({ "path": path, "input": raw }))
        }
        "webfetch" => {
            let url = string_field(&raw, &["url"]).unwrap_or_default();
            ("webfetch".to_owned(), json!({ "url": url, "input": raw }))
        }
        _ => {
            let args = match raw {
                Value::Object(_) => raw,
                other => json!({ "input": other }),
            };
            (name, args)
        }
    };
    ToolCall {
        session: format!(
            "{}:{}",
            agent.name(),
            input.session_id.unwrap_or_else(|| "unknown".into())
        ),
        tool,
        args,
        cwd: input.cwd.unwrap_or_default(),
        host: None,
        call_id: input.tool_use_id,
    }
}

/// What the hook does with the daemon's answer: `None` lets the tool run
/// (through the agent's own permission flow), `Some(reason)` blocks it.
/// Anything but an explicit allow blocks.
pub fn verdict(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Deny { reason } => Some(format!("Blocked by HAWK: {reason}")),
        Decision::Ask { reason } => Some(format!("Blocked by HAWK (no answer): {reason}")),
    }
}

/// `hawk-host-daemon hook <agent>`: reads the event on stdin, asks the
/// daemon, and returns the exit code (0 runs the tool, 2 blocks it).
pub async fn run_hook(agent: Agent, daemon: &str) -> i32 {
    let mut stdin = String::new();
    if std::io::stdin()
        .take(MAX_STDIN_BYTES)
        .read_to_string(&mut stdin)
        .is_err()
    {
        return block("Blocked by HAWK: could not read the tool call");
    }
    let input: HookInput = match serde_json::from_str(&stdin) {
        Ok(input) => input,
        Err(_) => return block("Blocked by HAWK: malformed tool call"),
    };
    let call = normalize(agent, input);
    let client = edge_net::http::client(Duration::from_secs(2));
    let url = format!("{}/decide", daemon.trim_end_matches('/'));
    let decision: Decision =
        match edge_net::http::post_json(&client, &url, &call, HOOK_DECIDE_TIMEOUT, 64 * 1024).await
        {
            Ok(decision) => decision,
            Err(_) => {
                return block("Blocked by HAWK: the HAWK daemon on this machine is not answering")
            }
        };
    match verdict(&decision) {
        None => 0,
        Some(reason) => block(&reason),
    }
}

fn block(reason: &str) -> i32 {
    eprintln!("{reason}");
    2
}

// Registering the hook --------------------------------------------------------

/// Where each agent keeps its user configuration.
pub fn config_path(agent: Agent, home: &Path) -> PathBuf {
    match agent {
        Agent::Claude => std::env::var_os("CLAUDE_CONFIG_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".claude"))
            .join("settings.json"),
        Agent::Codex => std::env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".codex"))
            .join("hooks.json"),
    }
}

/// The command line the agent runs: this binary, quoted, with `hook <agent>`.
pub fn hook_command(exe: &Path, agent: Agent) -> String {
    format!("\"{}\" hook {}", exe.display(), agent.name())
}

fn is_ours(handler: &Value, agent: Agent) -> bool {
    handler
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| {
            c.contains("host-daemon") && c.ends_with(&format!(" hook {}", agent.name()))
        })
}

/// The `PreToolUse` groups without HAWK's handler (and without groups left
/// empty by removing it).
fn without_ours(groups: &[Value], agent: Agent) -> Vec<Value> {
    groups
        .iter()
        .filter_map(|group| {
            let mut group = group.clone();
            if let Some(handlers) = group.get_mut("hooks").and_then(Value::as_array_mut) {
                let before = handlers.len();
                handlers.retain(|h| !is_ours(h, agent));
                if handlers.is_empty() && before > 0 {
                    return None;
                }
            }
            Some(group)
        })
        .collect()
}

/// The configuration with HAWK's hook registered once, everything else kept.
pub fn with_hook(config: &Value, agent: Agent, command: &str) -> Value {
    let mut root = match config {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    let mut hooks = match root.get("hooks") {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    };
    let current = hooks
        .get("PreToolUse")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut groups = without_ours(&current, agent);
    let mut handler =
        json!({ "type": "command", "command": command, "timeout": HOOK_TIMEOUT_SECS });
    let group = match agent {
        // Claude Code fails open on a crashed hook unless told otherwise.
        Agent::Claude => {
            handler["onFailure"] = json!("block");
            json!({ "matcher": "*", "hooks": [handler] })
        }
        // Codex: no matcher means every tool.
        Agent::Codex => json!({ "hooks": [handler] }),
    };
    groups.push(group);
    hooks.insert("PreToolUse".into(), Value::Array(groups));
    root.insert("hooks".into(), Value::Object(hooks));
    Value::Object(root)
}

/// The configuration with HAWK's hook removed, everything else kept.
pub fn without_hook(config: &Value, agent: Agent) -> Value {
    let mut config = config.clone();
    if let Some(groups) = config
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
        .and_then(Value::as_array_mut)
    {
        *groups = without_ours(groups, agent);
    }
    config
}

/// Whether HAWK's hook is registered in `config`.
pub fn has_hook(config: &Value, agent: Agent) -> bool {
    config
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
        .is_some_and(|groups| {
            groups.iter().any(|g| {
                g.get("hooks")
                    .and_then(Value::as_array)
                    .is_some_and(|hs| hs.iter().any(|h| is_ours(h, agent)))
            })
        })
}

fn read_config(path: &Path) -> Result<Value, String> {
    match fs::read_to_string(path) {
        Ok(text) if text.trim().is_empty() => Ok(json!({})),
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            format!(
                "{} is not valid JSON ({e}); not touching it",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_config(path: &Path, config: &Value) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // One backup of the file as it was before HAWK first touched it.
    let backup = path.with_extension("json.hawk-backup");
    if path.exists() && !backup.exists() {
        fs::copy(path, &backup).map_err(|e| format!("{}: {e}", backup.display()))?;
    }
    let text = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(path, text + "\n").map_err(|e| format!("{}: {e}", path.display()))
}

/// `hooks install|uninstall|status [agent]`: edits each agent's user
/// configuration. Returns the lines to print, or an error.
pub fn manage(
    action: &str,
    only: Option<Agent>,
    home: &Path,
    exe: &Path,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for agent in Agent::ALL
        .into_iter()
        .filter(|a| only.is_none_or(|o| o == *a))
    {
        let path = config_path(agent, home);
        let config = read_config(&path)?;
        match action {
            "install" => {
                let updated = with_hook(&config, agent, &hook_command(exe, agent));
                write_config(&path, &updated)?;
                out.push(format!(
                    "{}: hook registered in {}",
                    agent.name(),
                    path.display()
                ));
                if agent == Agent::Codex {
                    out.push(
                        "codex: open Codex and approve the hook with /hooks (Codex asks once)"
                            .into(),
                    );
                }
            }
            "uninstall" => {
                if path.exists() {
                    write_config(&path, &without_hook(&config, agent))?;
                }
                out.push(format!(
                    "{}: hook removed from {}",
                    agent.name(),
                    path.display()
                ));
            }
            "status" => out.push(format!(
                "{}: {}",
                agent.name(),
                if has_hook(&config, agent) {
                    "watched by HAWK"
                } else {
                    "NOT watched by HAWK"
                }
            )),
            other => {
                return Err(format!(
                    "unknown action {other:?}: install, uninstall or status"
                ))
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(tool: &str, tool_input: Value) -> HookInput {
        HookInput {
            session_id: Some("s1".into()),
            cwd: Some("/work".into()),
            tool_name: tool.into(),
            tool_input,
            tool_use_id: Some("toolu_1".into()),
        }
    }

    #[test]
    fn claude_bash_becomes_the_shape_the_rules_read() {
        let call = normalize(
            Agent::Claude,
            input("Bash", json!({ "command": "rm -rf src" })),
        );
        assert_eq!(call.tool, "bash");
        assert_eq!(call.args["command"], "rm -rf src");
        assert_eq!(call.session, "claude:s1");
        assert_eq!(call.cwd, "/work");
        assert_eq!(call.call_id.as_deref(), Some("toolu_1"));
    }

    #[test]
    fn codex_argv_commands_are_joined() {
        let call = normalize(
            Agent::Codex,
            input("exec_command", json!({ "cmd": ["git", "push", "-f"] })),
        );
        assert_eq!(call.tool, "bash");
        assert_eq!(call.args["command"], "git push -f");
        assert_eq!(call.session, "codex:s1");
    }

    #[test]
    fn writes_and_edits_carry_their_path() {
        let call = normalize(
            Agent::Claude,
            input(
                "Write",
                json!({ "file_path": "/etc/hosts", "content": "x" }),
            ),
        );
        assert_eq!(
            (call.tool.as_str(), call.args["path"].as_str()),
            ("write", Some("/etc/hosts"))
        );
        let call = normalize(
            Agent::Claude,
            input("Edit", json!({ "file_path": "src/a.rs" })),
        );
        assert_eq!(
            (call.tool.as_str(), call.args["path"].as_str()),
            ("edit", Some("src/a.rs"))
        );
    }

    #[test]
    fn apply_patch_is_judged_by_the_path_that_leaves_the_project() {
        let patch = "*** Begin Patch\n*** Update File: src/a.rs\n*** Add File: ../../.bashrc\n*** End Patch";
        let call = normalize(
            Agent::Codex,
            input("apply_patch", json!({ "input": patch })),
        );
        assert_eq!(call.tool, "edit");
        assert_eq!(call.args["path"], "../../.bashrc");
        assert_eq!(call.args["paths"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn unknown_tools_keep_their_arguments() {
        let call = normalize(
            Agent::Claude,
            input("mcp__db__query", json!({ "sql": "select 1" })),
        );
        assert_eq!(call.tool, "mcp__db__query");
        assert_eq!(call.args["sql"], "select 1");
    }

    #[test]
    fn only_an_explicit_allow_lets_the_tool_run() {
        assert!(verdict(&Decision::Allow).is_none());
        assert!(verdict(&Decision::deny("x")).is_some());
        assert!(verdict(&Decision::Ask { reason: "r".into() }).is_some());
    }

    #[test]
    fn installing_keeps_other_settings_and_is_idempotent() {
        let exe = Path::new("/usr/local/bin/hawk-host-daemon");
        let mine = json!({ "type": "command", "command": "/home/me/check.sh" });
        let config = json!({
            "model": "opus",
            "hooks": {
                "PreToolUse": [{ "matcher": "Bash", "hooks": [mine.clone()] }],
                "Stop": [{ "hooks": [{ "type": "command", "command": "notify" }] }]
            }
        });
        let once = with_hook(&config, Agent::Claude, &hook_command(exe, Agent::Claude));
        let twice = with_hook(&once, Agent::Claude, &hook_command(exe, Agent::Claude));
        assert_eq!(once, twice);
        assert_eq!(once["model"], "opus");
        assert!(once["hooks"]["Stop"].is_array());
        let groups = once["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["hooks"][0], mine);
        assert_eq!(groups[1]["matcher"], "*");
        assert_eq!(groups[1]["hooks"][0]["onFailure"], "block");
        assert!(has_hook(&once, Agent::Claude));
        assert!(!has_hook(&once, Agent::Codex));

        let removed = without_hook(&once, Agent::Claude);
        assert!(!has_hook(&removed, Agent::Claude));
        assert_eq!(
            removed["hooks"]["PreToolUse"].as_array().unwrap()[0]["hooks"][0],
            mine
        );
    }

    #[test]
    fn codex_registration_matches_every_tool() {
        let exe = Path::new("/usr/local/bin/hawk-host-daemon");
        let config = with_hook(&json!({}), Agent::Codex, &hook_command(exe, Agent::Codex));
        let group = &config["hooks"]["PreToolUse"][0];
        assert!(group.get("matcher").is_none());
        assert_eq!(
            group["hooks"][0]["command"],
            "\"/usr/local/bin/hawk-host-daemon\" hook codex"
        );
        assert!(group["hooks"][0].get("onFailure").is_none());
    }

    #[test]
    fn manage_writes_a_backup_and_refuses_broken_json() {
        let home = std::env::temp_dir().join(format!(
            "hawk-agents-{}",
            hex::encode(rand::random::<[u8; 6]>())
        ));
        let exe = Path::new("/usr/local/bin/hawk-host-daemon");
        let settings = home.join(".claude").join("settings.json");
        fs::create_dir_all(settings.parent().unwrap()).unwrap();
        fs::write(&settings, r#"{"theme":"dark"}"#).unwrap();

        manage("install", Some(Agent::Claude), &home, exe).unwrap();
        let written: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(written["theme"], "dark");
        assert!(has_hook(&written, Agent::Claude));
        assert!(settings.with_extension("json.hawk-backup").exists());
        assert!(
            manage("status", Some(Agent::Claude), &home, exe).unwrap()[0]
                .contains("watched by HAWK")
        );

        fs::write(&settings, "{ not json").unwrap();
        assert!(manage("install", Some(Agent::Claude), &home, exe).is_err());
        assert_eq!(fs::read_to_string(&settings).unwrap(), "{ not json");
        let _ = fs::remove_dir_all(&home);
    }
}
