//! Findings to one outcome (ADR-0022): the highest severity decides, through
//! the owner's thresholds (ADR-0033).
//!
//! Fail closed on failure, not on silence: no finding means allow. Errors
//! are handled by the callers, which deny.

use guardian_core::{wire::Thresholds, Decision, Finding, Severity};

/// The outcome of a decision and what produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    /// Every finding, recorded with the decision.
    pub findings: Vec<Finding>,
    /// A critical finding: the Core must quarantine the host (ADR-0018).
    pub contain: bool,
}

/// The default table of ADR-0022.
pub fn apply(findings: Vec<Finding>) -> Verdict {
    apply_with(findings, &Thresholds::default())
}

/// The owner's thresholds decide medium and high findings; a critical one
/// always denies and quarantines.
pub fn apply_with(findings: Vec<Finding>, thresholds: &Thresholds) -> Verdict {
    // The Core refuses thresholds that break the floors; clamp anyway so a
    // high finding can never be allowed unseen.
    let ask_from = thresholds.ask_from.min(Severity::High);
    let top = findings.iter().max_by_key(|f| f.severity);
    let (decision, contain) = match top {
        None => (Decision::Allow, false),
        Some(f) => {
            let reason = format!("{}: {}", f.rule, f.reason);
            if f.severity == Severity::Critical {
                (Decision::Deny { reason }, true)
            } else if f.severity >= thresholds.deny_from {
                (Decision::Deny { reason }, false)
            } else if f.severity >= ask_from {
                (Decision::Ask { reason }, false)
            } else {
                (Decision::Allow, false)
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

    fn with(severity: Severity, ask_from: Severity, deny_from: Severity) -> Verdict {
        apply_with(
            vec![finding(severity)],
            &Thresholds {
                ask_from,
                deny_from,
            },
        )
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

    #[test]
    fn strict_thresholds_ask_and_deny_earlier() {
        use Severity::*;
        assert!(matches!(
            with(Low, Low, Medium).decision,
            Decision::Ask { .. }
        ));
        assert!(matches!(
            with(Medium, Low, Medium).decision,
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn permissive_thresholds_still_ask_about_high() {
        use Severity::*;
        assert!(with(Medium, High, Critical).decision.is_allow());
        assert!(matches!(
            with(High, High, Critical).decision,
            Decision::Ask { .. }
        ));
    }

    #[test]
    fn critical_always_denies_and_contains() {
        use Severity::*;
        let v = with(Critical, High, Critical);
        assert!(matches!(v.decision, Decision::Deny { .. }));
        assert!(v.contain);
    }

    #[test]
    fn thresholds_past_the_floor_are_clamped() {
        use Severity::*;
        // ask_from above high is refused by the Core; if it ever arrives, a
        // high finding still asks instead of passing.
        assert!(matches!(
            with(High, Critical, Critical).decision,
            Decision::Ask { .. }
        ));
    }
}
