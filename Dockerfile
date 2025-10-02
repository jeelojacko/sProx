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
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime-deps

ARG TARGETARCH
ARG SHAKA_PACKAGER_VERSION=v2.6.1
ARG SHAKA_PACKAGER_SHA256_AMD64=328317e8f12dbcf9a5a172704699c2da51e54feb68cec5787666c2ab07b2c88d
ARG SHAKA_PACKAGER_SHA256_ARM64=ebeed27e7c1546ca85c08effd45ef2a95b64255228385526868194dcfea0750d

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) shaka_packager_asset="packager-linux-x64"; shaka_packager_sha="${SHAKA_PACKAGER_SHA256_AMD64}" ;; \
        arm64) shaka_packager_asset="packager-linux-arm64"; shaka_packager_sha="${SHAKA_PACKAGER_SHA256_ARM64}" ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl ffmpeg; \
    curl -fsSL "https://github.com/shaka-project/shaka-packager/releases/download/${SHAKA_PACKAGER_VERSION}/${shaka_packager_asset}" -o /usr/local/bin/packager; \
    echo "${shaka_packager_sha}  /usr/local/bin/packager" | sha256sum -c -; \
    chmod +x /usr/local/bin/packager; \
    ln -s /usr/local/bin/packager /usr/local/bin/shaka-packager; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /runtime-rootfs/usr/local/bin /runtime-rootfs/usr/bin /runtime-rootfs/etc/ssl/certs; \
    cp /usr/bin/ffmpeg /runtime-rootfs/usr/bin/; \
    cp /usr/bin/ffprobe /runtime-rootfs/usr/bin/; \
    cp /usr/local/bin/packager /runtime-rootfs/usr/local/bin/packager; \
    ln -s packager /runtime-rootfs/usr/local/bin/shaka-packager; \
    cp /etc/ssl/certs/ca-certificates.crt /runtime-rootfs/etc/ssl/certs/; \
    libs="$(for bin in /usr/bin/ffmpeg /usr/bin/ffprobe /usr/local/bin/packager; do \
        ldd "${bin}" | awk '/=>/ { print $3 } /^\\s*\\// { print $1 }'; \
    done | sort -u)"; \
    for lib in ${libs}; do \
        if [ -f "${lib}" ]; then \
            dest="/runtime-rootfs$(dirname "${lib}")"; \
            mkdir -p "${dest}"; \
            cp "${lib}" "${dest}"; \
        fi; \
    done

FROM gcr.io/distroless/cc-debian12:latest AS runtime

WORKDIR /app

ENV RUST_LOG=info \
    RUST_BACKTRACE=1 \
    SPROX_CONFIG=/config/routes.yaml

COPY --from=runtime-deps /runtime-rootfs/ /
COPY --from=builder /app/target/release/sProx /usr/local/bin/sprox
COPY --from=builder --chown=nonroot:nonroot /app/config /config

USER 65532:65532

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/sprox", "healthcheck", "--url", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/usr/local/bin/sprox"]
