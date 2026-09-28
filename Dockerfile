# The compiler is the one rust-toolchain.toml pins: that file is copied in with
# the repository below and rustup obeys it. This image carries exactly that
# version (its RUST_VERSION is 1.98.1), by digest, so nothing is downloaded but
# the file's components, and on bookworm so the binary's glibc (2.36) matches
# the debian:bookworm-slim runtime stage. Move it with rust-toolchain.toml.
FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS builder
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
