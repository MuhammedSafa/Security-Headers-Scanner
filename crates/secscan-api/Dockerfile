# Multi-stage build for secscan-api (Rust)
FROM rust:1-slim-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates

RUN cargo build --release --bin secscan-api

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -m -s /usr/sbin/nologin secscan \
    && mkdir -p /data \
    && chown -R secscan:secscan /data

WORKDIR /app
COPY --from=builder /build/target/release/secscan-api /usr/local/bin/secscan-api

ENV HOST=0.0.0.0 \
    PORT=4000 \
    RUST_LOG=secscan_api=info,secscan_core=info,tower_http=info \
    LAST_SCAN_PATH=/data/last-scan.yaml

USER secscan
EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:4000/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/secscan-api"]
