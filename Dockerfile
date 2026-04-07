FROM rust:1.94-bookworm AS builder
WORKDIR /workspace
COPY aegis-seal-gateway/ ./aegis-seal-gateway/
COPY aegis-proto/ ./aegis-proto/
WORKDIR /workspace/aegis-seal-gateway
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    podman \
    fuse-overlayfs \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /workspace/aegis-seal-gateway/target/release/aegis-seal-gateway /usr/local/bin/aegis-seal-gateway
EXPOSE 8089
EXPOSE 50055
CMD ["aegis-seal-gateway"]
