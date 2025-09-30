# syntax=docker/dockerfile:1.6

FROM rust:1.76-slim AS builder
WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY config ./config
COPY scripts ./scripts
RUN cargo fetch --locked

# Copy the rest of the source tree and build the release binary
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim AS runtime

ARG SHAKA_PACKAGER_VERSION=v2.6.1
ARG SHAKA_PACKAGER_SHA256=328317e8f12dbcf9a5a172704699c2da51e54feb68cec5787666c2ab07b2c88d

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl ffmpeg \
    && curl -fsSL "https://github.com/shaka-project/shaka-packager/releases/download/${SHAKA_PACKAGER_VERSION}/packager-linux-x64" -o /usr/local/bin/packager \
    && echo "${SHAKA_PACKAGER_SHA256}  /usr/local/bin/packager" | sha256sum -c - \
    && chmod +x /usr/local/bin/packager \
    && ln -s /usr/local/bin/packager /usr/local/bin/shaka-packager \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/sProx /usr/local/bin/sprox
COPY config ./config

ENV RUST_LOG=info \
    RUST_BACKTRACE=1

EXPOSE 8080
ENTRYPOINT ["sprox"]
CMD ["--config", "config/routes.yaml"]
