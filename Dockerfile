FROM rust:1.88-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY aegis-proto ./aegis-proto
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/aegis-smcp-gateway /usr/local/bin/aegis-smcp-gateway
EXPOSE 8089
CMD ["aegis-smcp-gateway"]
