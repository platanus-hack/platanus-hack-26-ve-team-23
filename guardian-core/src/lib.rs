//! Shared definitions for every binary: what a tool call and a decision look
//! like, how an event is encoded, and how the hash chain links events.
//!
//! This crate is the only definition of how an event is hashed (ADR-0012).
//! It does no I/O, so the Guardian, the witness and the evaluation agree
//! byte for byte.

#![forbid(unsafe_code)]

pub mod chain;
pub mod event;
pub mod types;

pub use chain::{verify, ChainError, Digest, HashChain};
pub use event::{Event, EventKind};
pub use types::{Decision, ToolCall};
