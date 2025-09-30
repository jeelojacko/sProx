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
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/sProx /usr/local/bin/sprox
COPY config ./config

ENV RUST_LOG=info \
    RUST_BACKTRACE=1

EXPOSE 8080
ENTRYPOINT ["sprox"]
CMD ["--config", "config/routes.yaml"]
