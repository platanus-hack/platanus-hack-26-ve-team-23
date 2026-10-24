//! Evaluation runner (ADR-0010). Planned: load tasks, run the agent, reset
//! the sandbox between tasks, and report the metrics.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("eval: no tasks yet; see eval/README.md");
    ExitCode::FAILURE
}
