# sProx

sProx is a Rust-based streaming proxy tailored for HTTP video delivery workflows. The
service sits between playback clients and one or more upstream origins, providing
adaptive bitrate (ABR) manifest rewriting, optional DASH-to-HLS conversion, and a
central place to enforce security controls. The codebase is intentionally modular so
that individual sub-systems (routing, manifest processing, DRM) can be implemented in
isolation while maintaining a cohesive data flow across the proxy pipeline.

## Table of contents

- [High-level architecture](#high-level-architecture)
- [Configuration model](#configuration-model)
- [Operational guidance](#operational-guidance)
- [Local development](#local-development)
- [Repository layout](#repository-layout)
- [Additional documentation](#additional-documentation)

## High-level architecture

At a glance the proxy is split across three primary layers that collaborate to service
requests:

```
┌────────────────────┐      ┌──────────────────────┐      ┌───────────────────────────┐
│  Edge listeners    │◄────►│  Routing orchestrator │◄────►│  Streaming transformation │
│  (Axum/Tokio)      │      │  & middleware         │      │  & cache adaptors          │
└────────────────────┘      └──────────────────────┘      └───────────────────────────┘
          │                            │                                 │
          ▼                            ▼                                 ▼
   TLS termination /          Policy enforcement                Manifest + segment
   HTTP/2 upgrades            (authn/z, rate limiting)           rewriting, DRM hooks
```

1. **Edge listeners** – Tokio-based servers accept HTTP or HTTPS traffic (depending on
   the route configuration) and normalise requests into an internal representation.
2. **Routing orchestrator** – Selects the upstream origin for the request, applies
   middleware (authentication, logging, rate limiting), and controls retries or failover.
3. **Streaming transformation layer** – Performs manifest manipulation (HLS/DASH), URL
   rewriting, optional transmuxing, and integrates with DRM key services.

Supporting modules provide telemetry (structured logging, metrics collectors), shared
configuration stores, and async job workers for background housekeeping tasks (e.g.
certificate rotation or cache warm-up). A more detailed component breakdown lives in
[`docs/architecture-overview.md`](docs/architecture-overview.md).

## Configuration model

All runtime behaviour is driven through declarative configuration files under the
`config/` directory. The defaults focus on `config/routes.yaml`, which defines the set of
listener endpoints and their downstream origins:

```yaml
routes:
  - id: "vod-edge"
    listen:
      host: "0.0.0.0"
      port: 8080
      tls:
        enabled: false
    upstream:
      origin: "https://origin.example.com/vod"
      tls:
        enabled: true
        sni_hostname: "origin.example.com"
        insecure_skip_verify: false
      socks5:
        enabled: false
    hls:
      enabled: true
      rewrite_playlist_urls: true
      base_url: "https://cdn.example.com/hls/"
      drm:
        clear_key_service: "https://drm.example.com/keys"
        token_header: "Authorization"
```

Key configuration concepts:

- **Listeners** – Control the transport protocol (HTTP/1.1, HTTP/2, QUIC), TLS settings
  for inbound traffic, and concurrency limits (to be implemented).
- **Upstreams** – Describe where traffic is proxied, including TLS requirements,
  optional SOCKS5 tunnelling, and retry budgets.
- **Streaming toggles** – Enable playlist rewriting, segment URL translation, DRM key
  acquisition, and future transcoding jobs.
- **Environment overrides** – Sensitive values (API tokens, TLS private keys) are loaded
  from environment variables. See `.env.example` for supported overrides.

Each configuration file is validated during start-up. Failing validation should prevent
the service from booting, which protects against partial rollouts with inconsistent
manifests or insecure TLS policies.

## Operational guidance

Operating a streaming proxy requires careful consideration of security, compliance, and
performance characteristics:

- **TLS** –
  - Terminate TLS at the edge listener when receiving HTTPS traffic from clients. Use
    certificates issued by a trusted CA and enable OCSP stapling where possible.
  - For upstream TLS, set `insecure_skip_verify` to `true` only in controlled testing
    environments; production deployments must validate certificates to avoid MITM
    attacks.
  - Automate certificate rotation using ACME (Let’s Encrypt) or an internal PKI and keep
    the private keys in restricted file system paths with correct permissions.
- **Security warnings** –
  - Always review manifest rewriting code paths to ensure URLs are not rewritten to
    insecure schemas. Mixed content (HTTP in HTTPS manifests) can expose session data.
  - Enable request logging and anomaly detection to spot credential stuffing or token
    reuse attempts.
  - When using SOCKS5 proxies, restrict access to authenticated tunnels and prefer
    mutually authenticated TLS between sProx and the proxy server.
- **DRM considerations** –
  - Integrate with a key server over HTTPS and authenticate requests with short-lived
    tokens. Cache keys in memory only for the duration required to fulfil client
    requests.
  - For Widevine or FairPlay workflows, ensure that sProx does not persist license
    responses to disk and that all DRM metadata is encrypted in transit.
- **Scaling** –
  - Run multiple instances behind a load balancer to handle burst traffic. Horizontal
    scaling is often preferable to single-node vertical scaling due to ABR manifest
    concurrency patterns.
  - Monitor CPU utilisation of manifest processing routines; heavy transmuxing should be
    offloaded to dedicated media workers when possible.

Further operational playbooks (disaster recovery, observability, canary rollouts) will be
added as the implementation matures. For interim guidance consult
[`docs/operational-notes.md`](docs/operational-notes.md).

## Local development

1. **Install prerequisites**
   - Rust toolchain (stable channel) via [`rustup`](https://rustup.rs/). The repository
     pins the toolchain version in `rust-toolchain.toml`.
   - `cargo` components: `rustfmt` and `clippy`. These install automatically when you
     run `rustup component add rustfmt clippy` if they are missing.
   - Optional: FFmpeg and Shaka Packager for validating manifest rewrites and transmuxing
     flows during development.
2. **Clone and bootstrap**
   - `git clone https://github.com/<org>/sProx.git`
   - `cd sProx`
   - Copy `.env.example` to `.env` and customise values for local testing (tokens, TLS
     file paths).
3. **Run the toolchain**
   - Format: `cargo fmt --all`
   - Lint: `cargo clippy --all-targets --all-features -- -D warnings`
   - Test: `cargo test`
   - Build: `cargo build`
4. **Editor setup**
   - VS Code users can leverage the provided `.vscode` workspace settings for
     `rust-analyzer`, format-on-save, and Clippy diagnostics.
   - For JetBrains or Neovim, ensure the Rust plugin reads `rust-toolchain.toml` so that
     the correct compiler version is used for IDE features.
5. **Running locally** (future implementation)
   - Once the binary exposes runtime flags, start the proxy with
     `cargo run -- --config config/routes.yaml`.
   - Use tools like `curl` or [`hurl`](https://hurl.dev/) to validate basic proxying.

## Containerized workflow

Build and run the proxy in a container to match production-like deployments or to
avoid installing the Rust toolchain locally:

```bash
# Build the optimized image
docker build -t sprox:latest .

# Run the container, exposing the default listener and mounting local configs
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/config:/app/config:ro" \
  sprox:latest --config config/routes.yaml
```

The `scripts/docker-run.sh` helper automates the build/run workflow. It produces a
local `sprox:local` image (override with `IMAGE_NAME`) and starts the container with
the configuration directory mounted read-only:

```bash
./scripts/docker-run.sh
```

Pass any additional arguments after the script invocation to forward them to the
containerized binary (for example `./scripts/docker-run.sh --config config/routes.yaml`).

## Repository layout

```
sProx/
├─ Cargo.toml             # Rust manifest
├─ .env.example           # Sample environment variables (secrets are excluded)
├─ config/                # Configuration files (routing rules, TLS toggles)
├─ docs/                  # Additional documentation and design notes
├─ packagers/             # Helper scripts for FFmpeg/Shaka Packager
├─ scripts/               # Repository automation (formatting, linting)
└─ src/
   ├─ main.rs             # Application entry point (to be implemented)
   ├─ app.rs              # Axum application builder (future work)
   └─ stream/             # Streaming helpers (HLS, DASH, conversions)
```

## Additional documentation

Supplementary documents live in the `docs/` directory:

- [`architecture-overview.md`](docs/architecture-overview.md) – expanded diagrams and
  explanations of planned subsystems.
- [`operational-notes.md`](docs/operational-notes.md) – security, TLS, and DRM checklists
  for running sProx in production.

These documents will evolve alongside feature development; contributions that keep the
architecture and operational runbooks up to date are welcome.
