# Development image: everything `just check` and `just audit` need, including
# the Linux libraries Tauri links against, so the witness crate is linted and
# tested too.

FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config curl file \
        libwebkit2gtk-4.1-dev libxdo-dev libssl-dev \
        libayatana-appindicator3-dev librsvg2-dev \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy \
    && cargo install --locked just cargo-deny

ENV CARGO_TARGET_DIR=/cargo-target
WORKDIR /work
CMD ["just", "check"]
