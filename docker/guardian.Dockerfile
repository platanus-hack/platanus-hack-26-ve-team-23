# The Guardian daemon. Build for the Pi with
# `docker buildx build --platform linux/arm64 -f docker/guardian.Dockerfile .`
# Only the guardian crate is compiled, so no Tauri libraries are needed.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p guardian

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 guardian \
    && mkdir /data && chown guardian /data
COPY --from=build /src/target/release/guardian /usr/local/bin/guardian
USER guardian
ENV GUARDIAN_ADDR=0.0.0.0:7443 GUARDIAN_DATA_DIR=/data RUST_LOG=info
VOLUME /data
EXPOSE 7443/udp
# QUIC only (ADR-0023): the health check is a QUIC hello from the binary itself.
HEALTHCHECK --interval=5s --timeout=4s --retries=10 CMD ["/usr/local/bin/guardian", "probe", "127.0.0.1:7443"]
ENTRYPOINT ["/usr/local/bin/guardian"]
