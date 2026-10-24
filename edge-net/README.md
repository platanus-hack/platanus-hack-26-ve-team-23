# edge-net

Networking for the edges (ADR-0016). HTTP/1.1 on hyper and tokio with our
own accept loop, and later the framed protocol between the host daemon, the
Core and the mobile app.

- **Status:** HTTP server helpers implemented with tests. Framed protocol
  planned.

## Main entry points

- `http::serve`: accept loop, one task per connection, header read timeout.
- `http::read_json`: reads at most N bytes, then parses JSON.
- `http::json`, `http::text`: responses.

## What it must never do

- Parse a body before its size is capped.
- Implement HTTP parsing or cryptography itself.

## Tests

`cargo test -p edge-net`.
