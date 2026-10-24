//! Networking shared by the host daemon and the Core (ADR-0016).
//!
//! Every read is bounded in time and size before anything is parsed.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod http;
pub mod quic;
