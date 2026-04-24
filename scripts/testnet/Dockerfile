# Build a minimal image that runs axiom-node.
FROM rust:1.93-slim AS builder
WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release -p axiom-cli

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data axiom \
 && mkdir -p /data && chown axiom:axiom /data
COPY --from=builder /src/target/release/axiom-node /usr/local/bin/axiom-node
USER axiom
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/axiom-node"]
