# Common tasks. Install just with `cargo install just`, then run `just` to
# list the recipes.

set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

# List the recipes.
default:
    @just --list

# Format the code.
fmt:
    cargo fmt --all

# Check formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Clippy with warnings as errors, every crate and target.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Tests of every crate.
test:
    cargo test --workspace

# Everything a pull request must pass.
check: fmt-check lint test

# Advisories, licences and sources of every dependency (needs cargo-deny).
audit:
    cargo deny check

# Run the Core locally (QUIC on 0.0.0.0:7443).
guardian:
    cargo run -p guardian

# QUIC hello against a Core.
probe addr="127.0.0.1:7443":
    cargo run -p guardian -- probe {{addr}}

# Run the host daemon (loopback HTTP for the hook, QUIC to the Core).
daemon:
    cargo run -p host-daemon

# The witness app on the desktop.
witness:
    cargo run -p witness

# The witness APK (needs the Tauri CLI, Android SDK and NDK).
witness-apk:
    cd witness; cargo tauri android build --apk

# The Guardian image for the Raspberry Pi (arm64).
build-pi:
    docker buildx build --platform linux/arm64 -f docker/guardian.Dockerfile -t guardian:arm64 --load .

# Checks inside the development container.
docker-check:
    docker compose run --rm check

# The Core in a container limited to 2 GB, then a QUIC hello against it.
docker-smoke:
    docker compose up -d --build guardian
    docker compose run --rm smoke
