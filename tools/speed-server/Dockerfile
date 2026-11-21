# SPDX-License-Identifier: LicenseRef-PolyForm-Shield-1.0.0
#
# pw-speed-server container image (multi-stage, distroless, non-root).
#
# The build context MUST be the repository root (the Cargo workspace needs every member manifest):
#
#   docker build -f tools/speed-server/Dockerfile -t pw-speed-server .
#   docker run --rm -p 8080:8080 \
#     -e PW_SPEED_NODE_ID=mia -e PW_SPEED_NODE_NAME=Miami -e PW_SPEED_NODE_LOCATION="Miami, US" \
#     pw-speed-server
#
# Native TLS is compiled in (`--features tls`); mount certificates and point [tls] at them, or terminate TLS
# in a reverse proxy (recommended, see README.md). There is no shell in the image, so use an HTTP probe on
# /healthz for health checks.

ARG RUST_VERSION=1.100.0

FROM rust:${RUST_VERSION}-bookworm AS build
WORKDIR /src
# Manifests, lockfile and sources of the whole workspace (see Dockerfile.dockerignore for what is excluded).
COPY Cargo.toml Cargo.lock rust-toolchain.toml clippy.toml ./
COPY crates crates
COPY apps apps
COPY tools tools
RUN cargo build --release --locked -p pw-speed-server --features tls

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/pw-speed-server /usr/local/bin/pw-speed-server
# Unprivileged port; map it with `-p 443:8080` or put a reverse proxy in front.
ENV PW_SPEED_LISTEN=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/pw-speed-server"]
