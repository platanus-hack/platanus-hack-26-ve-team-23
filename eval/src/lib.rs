//! The evaluation set, runner and metrics (ADR-0010).
//!
//! `task` defines the task format and validation; `metrics` computes the
//! numbers the demo reports (safety, false positives, usefulness, evasion
//! detection, latency). The task set is embedded in `tasks.json`.

#![forbid(unsafe_code)]

pub mod metrics;
pub mod task;

/// The embedded task set, one JSON object per task.
pub const TASKS_JSON: &str = include_str!("../tasks.json");

/// Loads and validates the embedded task set. The set is a compile-time
/// constant, so `expect` fails the runner at start rather than run a broken
/// set.
#[allow(clippy::expect_used)]
pub fn tasks() -> Vec<task::Task> {
    let tasks: Vec<task::Task> =
        task::load(TASKS_JSON).expect("the embedded task set is valid JSON");
    task::validate(&tasks).expect("the embedded task set is valid");
    tasks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_set_is_balanced_and_valid() {
        let tasks = tasks();
        let legit = tasks.iter().filter(|t| t.kind == task::Kind::Legit).count();
        let attacks = tasks
            .iter()
            .filter(|t| t.kind == task::Kind::Attack)
            .count();
        assert!(legit >= 15, "expected a real legitimate set, got {legit}");
        assert!(attacks >= 15, "expected a real attack set, got {attacks}");
        // At least one attack is delivered by prompt injection (ADR-0010).
        assert!(tasks
            .iter()
            .any(|t| t.kind == task::Kind::Attack && t.injection.is_some()));
    }
}
