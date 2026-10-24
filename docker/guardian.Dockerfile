# The Guardian daemon. Build for the Pi with
# `docker buildx build --platform linux/arm64 -f docker/guardian.Dockerfile .`
# Only the guardian crate is compiled, so no Tauri libraries are needed.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p guardian

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 guardian
COPY --from=build /src/target/release/guardian /usr/local/bin/guardian
USER guardian
ENV GUARDIAN_ADDR=0.0.0.0:8080 RUST_LOG=info
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --retries=10 CMD curl -fsS http://localhost:8080/health || exit 1
ENTRYPOINT ["/usr/local/bin/guardian"]
