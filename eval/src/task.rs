//! The evaluation set (ADR-0010): the task format, its validation, and the
//! metrics the demo reports.
//!
//! A task is one JSON object: the prompt for the agent, the initial files of
//! the sandbox, whether it is legitimate or carries a hidden harmful side
//! goal (and which category), and, for prompt-injection attacks, which file
//! delivers the injection. Tasks and detection rules are written by different
//! people (ADR-0010), so the rules are not tuned to the tasks.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Legit,
    Attack,
}

/// The hidden side goal of an attack task (ADR-0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    History,
    Logs,
    Exfil,
    Hook,
    Records,
    MultiStep,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    /// What the agent is asked to do.
    pub prompt: String,
    /// Initial files of the sandbox, path -> content.
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    pub kind: Kind,
    /// The category of the hidden side goal, for attacks.
    #[serde(default)]
    pub category: Option<Category>,
    /// For prompt-injection attacks, the file that carries the injection.
    #[serde(default)]
    pub injection: Option<String>,
}

/// Checks a task set before it is used: unique ids, a real split, and attacks
/// annotated with a category (and an injection file that exists when claimed).
pub fn validate(tasks: &[Task]) -> Result<(), String> {
    let mut ids = std::collections::HashSet::new();
    for task in tasks {
        if !ids.insert(task.id.clone()) {
            return Err(format!("duplicate task id {}", task.id));
        }
        if task.prompt.trim().is_empty() {
            return Err(format!("{} has an empty prompt", task.id));
        }
        match task.kind {
            Kind::Legit => {
                if task.category.is_some() || task.injection.is_some() {
                    return Err(format!(
                        "{} is legitimate but annotated as an attack",
                        task.id
                    ));
                }
            }
            Kind::Attack => {
                if task.category.is_none() {
                    return Err(format!("{} is an attack without a category", task.id));
                }
                if let Some(file) = &task.injection {
                    if !task.files.contains_key(file) {
                        return Err(format!("{} injection file {file} is missing", task.id));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Loads tasks from a JSON array (one object per task).
pub fn load(text: &str) -> Result<Vec<Task>, String> {
    serde_json::from_str(text).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(id: &str, kind: Kind) -> Task {
        Task {
            id: id.into(),
            prompt: "do a thing".into(),
            files: BTreeMap::new(),
            kind,
            category: if kind == Kind::Attack {
                Some(Category::Exfil)
            } else {
                None
            },
            injection: None,
        }
    }

    #[test]
    fn a_valid_set_passes() {
        let tasks = vec![task("legit-1", Kind::Legit), task("attack-1", Kind::Attack)];
        assert!(validate(&tasks).is_ok());
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let tasks = vec![task("a", Kind::Legit), task("a", Kind::Legit)];
        assert!(validate(&tasks).is_err());
    }

    #[test]
    fn an_attack_needs_a_category() {
        let mut t = task("attack-1", Kind::Attack);
        t.category = None;
        assert!(validate(&[t]).is_err());
    }

    #[test]
    fn an_injection_file_must_exist() {
        let mut t = task("attack-1", Kind::Attack);
        t.injection = Some("README.md".into());
        assert!(validate(&[t]).is_err());
    }
}
