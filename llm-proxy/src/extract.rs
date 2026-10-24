//! Tool-call extraction from OpenAI-compatible chat responses (ADR-0004).
//!
//! OpenCode talks to the proxy in OpenAI's shape, whatever serves behind it
//! (Ollama in the demo). A response proposes tool calls in one of two forms:
//!
//! - **Non-streaming**: one JSON object, `choices[].message.tool_calls[]`.
//! - **Streaming**: a Server-Sent-Events body whose `data:` lines carry
//!   chunks; a tool call's `id` and `name` arrive once and its `arguments`
//!   arrive as fragments that must be accumulated.
//!
//! This module is pure: it parses bytes and values only, so it is tested
//! against captured responses without any network.

use guardian_core::wire::ProposedToolCall;
use serde_json::Value;

/// A tool call's `arguments`: a JSON string in OpenAI's format, an object in
/// Ollama's native format. A string that is not valid JSON is kept as a
/// string so a malformed payload can still be recorded (ADR-0004: the proxy
/// must never drop a request because it failed to parse).
fn parse_arguments(raw: &Value) -> Value {
    match raw {
        Value::String(text) => {
            serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.clone()))
        }
        other => other.clone(),
    }
}

/// Extracts every tool call of one `message` object (OpenAI or Ollama shape).
fn from_message(message: &Value) -> Vec<ProposedToolCall> {
    let Some(calls) = message.get("tool_calls").and_then(Value::as_array) else {
        return Vec::new();
    };
    calls
        .iter()
        .filter_map(|call| {
            let function = call.get("function")?;
            let name = function.get("name")?.as_str()?.to_owned();
            let id = call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let arguments = parse_arguments(function.get("arguments")?);
            Some(ProposedToolCall {
                id,
                name,
                arguments,
            })
        })
        .collect()
}

/// Tool calls from a complete, non-streaming response body. Handles OpenAI's
/// `choices[].message` and Ollama's native `message`.
pub fn tool_calls_from_response(body: &Value) -> Vec<ProposedToolCall> {
    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        let mut out = Vec::new();
        for choice in choices {
            if let Some(message) = choice.get("message") {
                out.extend(from_message(message));
            }
        }
        return out;
    }
    body.get("message").map(from_message).unwrap_or_default()
}

/// Parses one SSE line into its JSON payload. Returns `None` for comments,
/// blank lines, keep-alives, `event:`/`id:` fields and the `[DONE]`
/// sentinel. OpenAI sends one JSON object per `data:` line; multi-event lines
/// are not produced by the endpoints we front.
pub fn parse_sse_line(line: &str) -> Option<Value> {
    let trimmed = line.trim_start();
    let payload = trimmed.strip_prefix("data:")?.trim();
    if payload.is_empty() || payload == "[DONE]" {
        return None;
    }
    serde_json::from_str(payload).ok()
}

#[derive(Debug, Default)]
struct Accum {
    id: String,
    name: String,
    args: String,
}

/// Accumulates the tool-call deltas of a streaming response and yields the
/// complete calls. Tool calls are indexed; `id` and `name` arrive in the
/// first chunk and `arguments` accumulate as fragments.
#[derive(Debug, Default)]
pub struct SseAccumulator {
    calls: Vec<Accum>,
    finished: Vec<ProposedToolCall>,
}

impl SseAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one decoded streaming chunk.
    pub fn push_chunk(&mut self, chunk: &Value) {
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            return;
        };
        for choice in choices {
            if let Some(deltas) = choice
                .get("delta")
                .and_then(|d| d.get("tool_calls"))
                .and_then(Value::as_array)
            {
                for delta in deltas {
                    let index = delta.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    while self.calls.len() <= index {
                        self.calls.push(Accum::default());
                    }
                    let slot = &mut self.calls[index];
                    if let Some(id) = delta.get("id").and_then(Value::as_str) {
                        slot.id = id.to_owned();
                    }
                    if let Some(function) = delta.get("function") {
                        if let Some(name) = function.get("name").and_then(Value::as_str) {
                            slot.name = name.to_owned();
                        }
                        if let Some(args) = function.get("arguments").and_then(Value::as_str) {
                            slot.args.push_str(args);
                        }
                    }
                }
            }
            if choice
                .get("finish_reason")
                .and_then(Value::as_str)
                .is_some()
            {
                self.finalize_all();
            }
        }
    }

    fn finalize_all(&mut self) {
        for call in self.calls.drain(..) {
            self.finished.push(ProposedToolCall {
                id: call.id,
                name: call.name,
                arguments: parse_arguments(&Value::String(call.args)),
            });
        }
    }

    /// Called once the stream ends: returns every complete tool call.
    pub fn finish(&mut self) -> Vec<ProposedToolCall> {
        self.finalize_all();
        std::mem::take(&mut self.finished)
    }
}

/// Tool calls from a complete SSE body (the concatenation of every `data:`
/// line). Convenience for callers that buffer the stream.
pub fn tool_calls_from_sse(body: &str) -> Vec<ProposedToolCall> {
    let mut acc = SseAccumulator::new();
    for line in body.lines() {
        if let Some(chunk) = parse_sse_line(line) {
            acc.push_chunk(&chunk);
        }
    }
    acc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(json: &str) -> Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn extracts_openai_tool_calls_with_ids() {
        let body = value(
            r#"{
              "choices": [{
                "message": {
                  "role": "assistant",
                  "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": { "name": "bash", "arguments": "{\"command\":\"ls\"}" }
                  }]
                }
              }]
            }"#,
        );
        let calls = tool_calls_from_response(&body);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_1");
        assert_eq!(calls[0].name, "bash");
        assert_eq!(calls[0].arguments["command"], "ls");
    }

    #[test]
    fn extracts_ollama_native_tool_calls() {
        let body = value(
            r#"{
              "message": {
                "role": "assistant",
                "tool_calls": [{
                  "function": { "name": "write_file", "arguments": { "path": "/tmp/x" } }
                }]
              }
            }"#,
        );
        let calls = tool_calls_from_response(&body);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "write_file");
        assert_eq!(calls[0].arguments["path"], "/tmp/x");
        assert_eq!(calls[0].id, "");
    }

    #[test]
    fn malformed_arguments_are_kept_as_strings() {
        let body = value(
            r#"{"choices":[{"message":{"tool_calls":[{"id":"c","function":{"name":"bash","arguments":"not json"}}]}}]}"#,
        );
        let calls = tool_calls_from_response(&body);
        assert_eq!(calls[0].arguments, Value::String("not json".into()));
    }

    #[test]
    fn no_tool_calls_is_empty() {
        assert!(
            tool_calls_from_response(&value(r#"{"choices":[{"message":{"content":"hi"}}]}"#))
                .is_empty()
        );
        assert!(tool_calls_from_response(&value(r#"{"foo":1}"#)).is_empty());
    }

    #[test]
    fn sse_lines_are_parsed_and_junk_is_ignored() {
        assert!(parse_sse_line("data: {\"a\":1}").is_some());
        assert!(parse_sse_line("data: [DONE]").is_none());
        assert!(parse_sse_line(": keep-alive").is_none());
        assert!(parse_sse_line("event: message").is_none());
        assert!(parse_sse_line("").is_none());
        assert!(parse_sse_line("data: nope").is_none());
    }

    #[test]
    fn streaming_tool_call_fragments_are_accumulated() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"type\":\"function\",\"function\":{\"name\":\"bash\",\"arguments\":\"\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"command\\\":\\\"rm\"}}]},\"finish_reason\":null}]}\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\" -rf /\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n",
            "data: [DONE]\n",
        );
        let calls = tool_calls_from_sse(sse);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].id, "call_9");
        assert_eq!(calls[0].name, "bash");
        assert_eq!(calls[0].arguments["command"], "rm -rf /");
    }
}
