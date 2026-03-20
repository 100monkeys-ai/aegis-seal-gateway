FROM rust:1.88-bookworm AS builder
WORKDIR /workspace
COPY aegis-smcp-gateway/ ./aegis-smcp-gateway/
COPY aegis-proto/ ./aegis-proto/
WORKDIR /workspace/aegis-smcp-gateway
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /workspace/aegis-smcp-gateway/target/release/aegis-smcp-gateway /usr/local/bin/aegis-smcp-gateway
EXPOSE 8089
EXPOSE 50055
CMD ["aegis-smcp-gateway"]
