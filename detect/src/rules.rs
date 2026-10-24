//! The interface every detection rule implements.

use guardian_core::{Finding, ToolCall};

/// A rule looks at one call and reports at most one finding. Rules must not
/// panic or block: they run on every tool call, on a 2 GB board.
pub trait Rule: std::fmt::Debug + Send + Sync {
    fn check(&self, call: &ToolCall) -> Option<Finding>;
}
