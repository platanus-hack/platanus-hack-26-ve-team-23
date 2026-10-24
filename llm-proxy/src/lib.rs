//! OpenAI-compatible proxy between the agent and Ollama (ADR-0004).
//!
//! Planned: forward `/v1/chat/completions` and Ollama's paths, record every
//! request and response, and extract the tool calls the model proposes for
//! the cross-check against hook requests.

#![forbid(unsafe_code)]

/// Where the proxy forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    /// Base URL of Ollama on the PC, for example `http://192.168.1.10:11434`.
    pub upstream: String,
}
