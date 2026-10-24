//! The evaluation runner (ADR-0010).
//!
//! - `eval validate` loads and validates the embedded task set.
//! - `eval list` prints the tasks grouped by kind and category.
//! - `eval metrics results.json` computes the metrics of one configuration.
//! - `eval run` resets a sandbox per task and runs the agent command
//!   (`EVAL_AGENT_CMD`, default `opencode`); collecting the Core's decisions
//!   is the M2/M3 integration (see `eval/README.md`).

#![forbid(unsafe_code)]
// `eval` is a command-line tool: printing the metrics and task list is its
// entire output, so the stdout lint is disabled here.
#![allow(clippy::print_stdout)]

use std::process::{Command, ExitCode};

use eval::metrics::{compute, TaskResult};
use eval::task::{Kind, Task};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("validate");
    match cmd {
        "validate" => validate(),
        "list" => list(),
        "metrics" => metrics(args.get(2).map(String::as_str)),
        "run" => run(),
        other => {
            eprintln!("eval: unknown command {other:?} (validate, list, metrics, run)");
            ExitCode::FAILURE
        }
    }
}

fn validate() -> ExitCode {
    let tasks = eval::tasks();
    let legit = tasks.iter().filter(|t| t.kind == Kind::Legit).count();
    let attacks = tasks.iter().filter(|t| t.kind == Kind::Attack).count();
    println!("ok: {legit} legitimate, {attacks} attack tasks");
    ExitCode::SUCCESS
}

fn list() -> ExitCode {
    let tasks = eval::tasks();
    for task in &tasks {
        let category = task.category.map_or("-", |c| match c {
            eval::task::Category::History => "history",
            eval::task::Category::Logs => "logs",
            eval::task::Category::Exfil => "exfil",
            eval::task::Category::Hook => "hook",
            eval::task::Category::Records => "records",
            eval::task::Category::MultiStep => "multi-step",
        });
        let kind = match task.kind {
            Kind::Legit => "legit ",
            Kind::Attack => "attack",
        };
        println!("{kind} {category:9} {}  {}", task.id, task.prompt);
    }
    ExitCode::SUCCESS
}

fn metrics(path: Option<&str>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("eval metrics <results.json>");
        return ExitCode::FAILURE;
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("eval: {err}");
            return ExitCode::FAILURE;
        }
    };
    let results: Vec<TaskResult> = match serde_json::from_str(&text) {
        Ok(results) => results,
        Err(err) => {
            eprintln!("eval: bad results file: {err}");
            return ExitCode::FAILURE;
        }
    };
    let m = compute(&results);
    println!("attacks            {}", m.attacks);
    println!("legitimate         {}", m.legit);
    println!("safety             {:.3}", m.safety);
    println!("false positives    {:.3}", m.false_positive_rate);
    println!("usefulness         {:.3}", m.usefulness);
    println!("evasion detection  {:.3}", m.evasion_detection);
    println!("avg latency (ms)   {:.1}", m.avg_latency_ms);
    ExitCode::SUCCESS
}

/// Resets a sandbox, writes the task's files, and runs the agent. Decision
/// collection from the Core is the M2/M3 integration and is not wired here.
fn run() -> ExitCode {
    let tasks = eval::tasks();
    let agent = std::env::var("EVAL_AGENT_CMD").unwrap_or_else(|_| "opencode".into());
    let mut failed = 0usize;
    for task in &tasks {
        match run_one(&agent, task) {
            Ok(()) => println!("{} ok", task.id),
            Err(err) => {
                eprintln!("{} failed: {err}", task.id);
                failed += 1;
            }
        }
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run_one(agent: &str, task: &Task) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!("hawk-eval-{}", task.id));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (path, content) in &task.files {
        let full = dir.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&full, content).map_err(|e| e.to_string())?;
    }
    let status = Command::new(agent)
        .arg("run")
        .arg(&task.prompt)
        .current_dir(&dir)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("agent exited {status}"))
    }
}
