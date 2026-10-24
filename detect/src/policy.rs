//! Findings to one outcome (ADR-0022): the highest severity decides.
//!
//! Fail closed on failure, not on silence: no finding means allow. Errors
//! are handled by the callers, which deny.

use guardian_core::{Decision, Finding, Severity};

/// The outcome of a decision and what produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    /// Every finding, recorded with the decision.
    pub findings: Vec<Finding>,
    /// A critical finding: the Core must quarantine the host (ADR-0018).
    pub contain: bool,
}

pub fn apply(findings: Vec<Finding>) -> Verdict {
    let top = findings.iter().max_by_key(|f| f.severity);
    let (decision, contain) = match top {
        None => (Decision::Allow, false),
        Some(f) => {
            let reason = format!("{}: {}", f.rule, f.reason);
            match f.severity {
                Severity::Critical => (Decision::Deny { reason }, true),
                Severity::High => (Decision::Deny { reason }, false),
                Severity::Medium => (Decision::Ask { reason }, false),
                Severity::Low => (Decision::Allow, false),
            }
        }
    };
    Verdict {
        decision,
        findings,
        contain,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule: format!("r.{severity:?}"),
            severity,
            reason: "x".into(),
        }
    }

    #[test]
    fn highest_severity_decides() {
        let v = apply(vec![finding(Severity::Medium), finding(Severity::Critical)]);
        assert!(matches!(v.decision, Decision::Deny { .. }));
        assert!(v.contain);
        assert_eq!(v.findings.len(), 2);
    }

    #[test]
    fn outcomes_per_severity() {
        assert!(apply(vec![]).decision.is_allow());
        assert!(apply(vec![finding(Severity::Low)]).decision.is_allow());
        assert!(matches!(
            apply(vec![finding(Severity::Medium)]).decision,
            Decision::Ask { .. }
        ));
        let high = apply(vec![finding(Severity::High)]);
        assert!(matches!(high.decision, Decision::Deny { .. }));
        assert!(!high.contain);
    }
}
