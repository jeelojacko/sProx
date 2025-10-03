# sProx

sProx is a Rust-based streaming proxy tailored for HTTP video delivery workflows. The
service sits between playback clients and one or more upstream origins, providing
adaptive bitrate (ABR) manifest rewriting, optional DASH-to-HLS conversion, and a
central place to enforce security controls. The codebase is intentionally modular so
that individual sub-systems (routing, manifest processing, DRM) can be implemented in
isolation while maintaining a cohesive data flow across the proxy pipeline.

## Table of contents

- [Key capabilities](#key-capabilities)
- [High-level architecture](#high-level-architecture)
- [Configuration model](#configuration-model)
- [Operational guidance](#operational-guidance)
- [Runtime endpoints](#runtime-endpoints)
- [Observability and rate limiting](#observability-and-rate-limiting)
- [Local development](#local-development)
- [Environment variables](#environment-variables)
- [Containerized workflow](#containerized-workflow)
- [Repository layout](#repository-layout)
- [Additional documentation](#additional-documentation)

## Key capabilities

- **Multi-route HTTP/S proxying** – Route requests to multiple origins based on host globs,
  listener ports, and protocol allowlists while keeping retries, TLS, and header policies
  declarative.
- **Direct stream endpoint** – `/proxy/stream` safely proxies byte-range requests to an
  allowlisted set of destinations, enforces shared secrets when configured, validates
  override headers, and blocks requests that resolve to private networks.
- **Manifest enrichment** – Optional HLS features rewrite playlist URLs, enforce CDN base
  paths, toggle DRM hooks, and guard against insecure segment references.
- **Operational tooling** – Built-in CLI commands validate configuration bundles and run
  health probes; the daemon reloads configuration on `SIGHUP` and can hot-reload TLS
  material when certificates rotate.
- **Defense-in-depth controls** – Configurable rate limiting, CORS policies, sensitive
  logging redaction, and a TTL-driven in-memory secrets store provide safe defaults for
  production environments.
- **First-class observability** – Structured JSON tracing, a Prometheus metrics exporter,
  and dedicated endpoints (`/health`, `/metrics`, `/ip`, `/speedtest`) support fleet
  monitoring and on-call diagnostics.

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
   the route configuration) and normalise requests into an internal representation. TLS
   material can be reloaded automatically when certificates rotate.
2. **Routing orchestrator** – Selects the upstream origin for the request, applies
   middleware (authentication, logging, rate limiting), and controls retries or failover.
3. **Streaming transformation layer** – Performs manifest manipulation (HLS/DASH), URL
   rewriting, optional transmuxing, and integrates with DRM key services. Direct stream
   handlers share retry budgets and header policies with the routing core.

Supporting modules provide telemetry (structured logging, metrics collectors), shared
configuration stores, and async job workers for background housekeeping tasks (e.g.,
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
        certificate_path: "config/tls/dev-cert.pem"
        private_key_path: "config/tls/dev-key.pem"
        watch_for_changes: true
        acme:
          enabled: false
          contact_emails: ["admin@example.com"]
          directory_url: null
          cache_path: "var/acme"
    host_patterns:
      - "vod-edge.example.com"
      - "*.vod.example.com"
    upstream:
      origin: "https://origin.example.com/vod"
      connect_timeout_ms: 2000
      read_timeout_ms: 5000
      request_timeout_ms: 8000
      tls:
        enabled: true
        sni_hostname: "origin.example.com"
        insecure_skip_verify: false
      socks5:
        enabled: false
        address: "127.0.0.1:1080"
        username: null
        password: null
    hls:
      enabled: true
      rewrite_playlist_urls: true
      base_url: "https://cdn.example.com/hls/"
      allow_insecure_segments: false
  - id: "api-pass-through"
    listen:
      host: "127.0.0.1"
      port: 9090
    host_patterns:
      - "api.example.local"
    protocols:
      - http
    upstream:
      origin: "http://internal-api.example.local"
      connect_timeout_ms: 1000
      read_timeout_ms: 3000
      request_timeout_ms: 4000
      tls:
        enabled: false
        sni_hostname: null
        insecure_skip_verify: false
      socks5:
        enabled: false
        address: null
        username: null
        password: null
    hls:
      enabled: false
      rewrite_playlist_urls: false
      base_url: null
      allow_insecure_segments: false

direct_stream:
  proxy_url: null
  api_password: null
  request_timeout_ms: 30000
  response_buffer_bytes: 65536
  allowlist:
    - domain: "media.example.com"
      schemes: ["https"]
      paths:
        - "/vod/**"
  retry:
    max_attempts: 3

secrets:
  default_ttl_secs: 300

sensitive_logging:
  log_sensitive_headers: false
  redact_sensitive_queries: false

cors:
  allow_origins:
    - "https://app.example.com"
  allow_methods:
    - GET
    - OPTIONS
  allow_headers:
    - Content-Type
    - Authorization
```

Each configuration file is validated during start-up and by the CLI validator. Failing
validation prevents the service from booting, which protects against partial rollouts with
inconsistent manifests, insecure TLS policies, or misconfigured header rules.

### Route definitions

Route entries describe how a listener should behave and which upstream it targets:

- **Listeners** – Control the transport protocol (HTTP/1.1, HTTP/2, QUIC), TLS settings for
  inbound traffic, and concurrency limits (to be implemented). When TLS is enabled,
  certificates are reloaded automatically if `watch_for_changes` is `true`, and an ACME
  cache directory can be prepared so external ACME clients can request certificates.
- **Host matching** – `host_patterns` accepts glob syntax (e.g., `*.example.com`) so a single
  listener can service multiple domains. Protocol lists constrain the schemes that may use
  the route, while future `ports` entries will allow listener fan-out by port.
- **Upstreams** – Describe where traffic is proxied, including per-hop timeout knobs
  (connect/read/request), TLS requirements, optional SOCKS5 tunnelling, and retry budgets.
  By default, retries allow three attempts with exponential backoff starting at 100 ms
  (doubling up to 5 s) and 20 % jitter while the budget replenishes over a 10 s window (20 %
  of requests may be retried with a minimum reserve of 10 per second). Setting the
  `SPROX_PROXY_URL` environment variable at runtime forces every route to tunnel through the
  provided SOCKS5 endpoint regardless of the per-route configuration.
- **Header policies** – Per-route allow/deny lists govern which request headers are forwarded
  upstream. The `x_forwarded_for` strategy can be set to `append` (default) or `replace` to
  control how client IP chains are propagated.
- **Streaming toggles** – Enable playlist rewriting, segment URL translation, DRM key
  acquisition, and future transcoding jobs. When `rewrite_playlist_urls` is `true`, a
  `base_url` must be supplied; optional `allow_insecure_segments` can opt in to `http://`
  references even when the manifest is served securely.

### Direct stream settings

The optional `direct_stream` block governs `/proxy/stream`:

- **Proxy URL** – `proxy_url` routes direct stream requests through an outbound HTTP proxy.
  Override it globally with `SPROX_DIRECT_PROXY_URL`.
- **Shared secret** – `api_password` enforces that callers supply a matching password via the
  `x-sprox-api-password` header or `api_password` query parameter. Override with
  `SPROX_DIRECT_API_PASSWORD`.
- **Timeouts and buffering** – Configure request timeouts (`request_timeout_ms`) and the
  initial HTTP/2 response buffer (`response_buffer_bytes`). Both can be overridden at runtime
  via `SPROX_DIRECT_REQUEST_TIMEOUT_MS` and `SPROX_DIRECT_RESPONSE_BUFFER_BYTES`.
- **Allowlist** – Destinations must match the configured allowlist. Each rule specifies a
  domain, the allowed schemes (defaulting to HTTPS), and optional path globs.
- **Retry policy** – Direct stream requests share the same retry/backoff configuration as
  route upstreams, ensuring a consistent error budget across the service.
- **Security guardrails** – Requests that resolve to private, loopback, multicast, or
  documentation IP ranges are rejected automatically before any upstream call occurs.

### Secrets, logging, and CORS

- **Secrets** – `secrets.default_ttl_secs` configures the default lifetime for values stored
  in the in-memory secret cache. Expired entries are purged lazily and never serialized.
- **Sensitive logging** – Toggle whether sensitive headers are logged verbatim and whether
  DRM query parameters should be redacted when telemetry is enabled.
- **CORS** – The `cors` block supplies allowlists for origins, methods, and headers. When a
  list is empty the proxy defaults to `*` for that dimension.

## Operational guidance

Operating a streaming proxy requires careful consideration of security, compliance, and
performance characteristics:

- **TLS** –
  - Terminate TLS at the edge listener when receiving HTTPS traffic from clients. Use
    certificates issued by a trusted CA and enable OCSP stapling where possible.
  - For upstream TLS, set `insecure_skip_verify` to `true` only in controlled testing
    environments; production deployments must validate certificates to avoid MITM attacks.
  - Automate certificate rotation using ACME (Let’s Encrypt) or an internal PKI and keep the
    private keys in restricted file system paths with correct permissions.
  - Enable `watch_for_changes` on TLS listeners so renewed certificates are hot-reloaded
    without downtime. The optional ACME cache path is prepared automatically for external
    clients.
- **Security warnings** –
  - Always review manifest rewriting code paths to ensure URLs are not rewritten to insecure
    schemas. Mixed content (HTTP in HTTPS manifests) can expose session data.
  - Enable request logging and anomaly detection to spot credential stuffing or token reuse
    attempts.
  - When using SOCKS5 proxies, restrict access to authenticated tunnels and prefer mutually
    authenticated TLS between sProx and the proxy server.
  - Configure the direct stream allowlist narrowly; the proxy already rejects destinations
    that fall outside the allowlist, use unsupported schemes, or resolve to private
    networks, but layered defense protects against misconfigurations.
  - Require `api_password` for `/proxy/stream` in production so that only trusted automation
    can invoke it.
- **DRM considerations** –
  - Integrate with a key server over HTTPS and authenticate requests with short-lived tokens.
    Cache keys in memory only for the duration required to fulfil client requests.
  - For Widevine or FairPlay workflows, ensure that sProx does not persist license responses
    to disk and that all DRM metadata is encrypted in transit.
- **Scaling** –
  - Run multiple instances behind a load balancer to handle burst traffic. Horizontal scaling
    is often preferable to single-node vertical scaling due to ABR manifest concurrency
    patterns.
  - Monitor CPU utilisation of manifest processing routines; heavy transmuxing should be
    offloaded to dedicated media workers when possible.
- **Configuration management** –
  - Validate configuration bundles with `sprox validate -c <dir>` before deploys.
  - Reload configuration safely with `SIGHUP`; failures leave the previous configuration
    active.

### Configuration validation and reloads

- Use the built-in CLI to validate configuration bundles before deploying. Running `cargo run
  -- validate -c config` (or the installed binary `sprox validate -c <dir>`) reads
  `<dir>/routes.yaml` with the same loader used at runtime and reports any syntax or semantic
  validation errors without starting the server.
- The runtime watches for `SIGHUP` on Unix targets. Sending `kill -HUP <pid>` forces sProx to
  reload the configuration from disk, rebuild the application state, and atomically swap it
  into the running server. If validation fails the previous configuration is retained, with
  failures logged to aid debugging.
- When the `SPROX_CONFIG` environment variable is set the daemon and the validation command
  both honour it, allowing alternate configuration directories or files to be tested and
  reloaded.

Further operational playbooks (disaster recovery, observability, canary rollouts) will be
added as the implementation matures. For interim guidance consult
[`docs/operational-notes.md`](docs/operational-notes.md).

## Runtime endpoints

### `/health`

Returns `200 OK` to signal readiness and increments the `sprox_health_checks_total`
counter when telemetry is enabled.

### `/metrics`

Exposes Prometheus-formatted metrics describing request rates, latency histograms, direct
stream throughput, and health-check counters. When telemetry is disabled the endpoint
returns `501 Not Implemented`.

### `/ip`

Resolves the caller's IP address by inspecting `Forwarded`, `X-Forwarded-For`, `X-Real-IP`,
`CF-Connecting-IP`, and `X-Client-IP` headers before falling back to the socket's remote
address.

### `/speedtest`

Streams an 8 MiB deterministic payload while emitting structured logs with observed
throughput. Responses are cache-busted with `Cache-Control: no-store`.

### `/keys`

Lists the identifiers currently loaded in the proxy's in-memory secrets store. Entries
expire automatically based on the configured TTL.

### `/keys/clearkey`

Available when the `drm` feature flag is enabled. Serves a JWKS payload backed by the DRM
secret store. Requests have sensitive query parameters redacted from telemetry logs.

### `/proxy/stream`

The `/proxy/stream` endpoint performs a direct byte-range proxy against an upstream URL
that matches the configured allowlist. Downstream callers provide the upstream location via
the mandatory `d` query parameter and may optionally override a curated set of request
headers by prefixing them with `h_`. Underscores in override keys are converted to hyphens
before being sent upstream. For example:

```http
GET /proxy/stream?d=https%3A%2F%2Forigin.local%2Fassets%2Fmovie.mp4&h_referer=https%3A%2F%2Fplayer.example.com HTTP/1.1
Host: sprox.local
Range: bytes=0-1048575
```

Only an allowlisted subset of headers (such as `Range`, `Referer`, `User-Agent`, and
conditional request headers) are forwarded upstream. Responses stream the upstream body
directly to the caller while copying a small set of safe headers (`Content-Type`,
`Content-Length`, `Content-Range`, caching metadata, etc.). If the upstream does not
advertise byte range support the proxy injects `Accept-Ranges: bytes` to maintain playback
compatibility. Standard HTTP range semantics apply: a successful partial request returns
`206 Partial Content` with the appropriate `Content-Range`, while full responses return `200
OK` alongside the upstream `Content-Length`.

Direct stream destinations must be explicitly allowlisted. Requests that do not match the
allowlist, use non-HTTP(S) schemes, or resolve to private/link-local networks are rejected
with `403 Forbidden` before any upstream connection is made. Header overrides that fall
outside of the built-in request allowlist yield `400 Bad Request`, providing explicit
feedback to callers that an override is disallowed. Optional shared secrets prevent public
abuse, and the response header allowlist ensures downstream clients only receive cache-safe
metadata.

Requests that follow redirects are capped at 10 hops. If the upstream returns `206 Partial
Content`, the proxy verifies that range headers are present before streaming the body. Any
reqwest-level failure (DNS, TLS, timeout) is retried according to the configured retry
budget; exhaustion surfaces as a `502 Bad Gateway`.

## Observability and rate limiting

- **Tracing** – When the `telemetry` feature is active, sProx emits JSON logs with request
  spans that respect sensitive logging toggles. DRM routes have `kid` and `sig` query
  parameters redacted by default.
- **Metrics** – Counters and histograms track HTTP responses, upstream latency, bytes
  streamed, and health checks. The Prometheus exporter is process-global and shared by the
  `/metrics` endpoint.
- **Rate limiting** – A token-bucket limiter guards inbound requests. Defaults allow one
  request per 100 ms with burst refills; future configuration fields will expose these knobs
  per deployment.

## Local development

1. **Install prerequisites**
   - Rust toolchain (stable channel) via [`rustup`](https://rustup.rs/). The repository pins
     the toolchain version in `rust-toolchain.toml`.
   - `cargo` components: `rustfmt` and `clippy`. These install automatically when you run
     `rustup component add rustfmt clippy` if they are missing.
   - Optional: FFmpeg and Shaka Packager for validating manifest rewrites and transmuxing
     flows during development.
2. **Clone and bootstrap**
   - `git clone https://github.com/<org>/sProx.git`
   - `cd sProx`
   - Copy `.env.example` to `.env` and customise values for local testing (tokens, TLS file
     paths).
3. **Run the toolchain**
   - Format: `cargo fmt --all`
   - Lint: `cargo clippy --all-targets --all-features -- -D warnings`
   - Test: `cargo test`
   - Build: `cargo build`
4. **Use the CLI**
   - Validate configs: `cargo run -- validate -c config`
   - Health probe: `cargo run -- healthcheck --url http://127.0.0.1:8080/health`
   - Installed binaries expose the same commands as `sprox validate` / `sprox healthcheck`.
5. **Running locally**
   - Start the proxy with `cargo run -- --config config/routes.yaml` (or set `SPROX_CONFIG`
     to pick an alternate config directory).

### Cargo feature flags

- `drm` – Enables DRM-specific functionality, including the Clear Key JWKS endpoint and
  associated secret store plumbing. The flag is enabled by default to preserve the existing
  developer experience, but Real-Debrid/AllDebrid style deployments should disable it to
  avoid exposing DRM routes. Build with `cargo build --no-default-features --features
  "http-proxy config-loader telemetry"` (or the subset of features you require) to run
  without DRM support.

## Environment variables

The proxy reads sensitive runtime configuration from environment variables. Copy
`.env.example` to `.env` and fill in the following entries:

* `API_PASSWORD` – Protects admin or internal APIs exposed by sProx. **Format:** strong
  passphrase string (≥16 characters, mixed casing).
* `SIGNING_SECRET` – Secret used to sign or verify tokens generated by the service.
  **Format:** base64-encoded key material such as `openssl rand -base64 32`.
* `AES_KEY` – AES-256 encryption key for encrypting sensitive payloads at rest.
  **Format:** 32-byte hex string from `openssl rand -hex 32`.
* `REALDEBRID_API_TOKEN` – Personal API token for Real-Debrid integrations. **Source:**
  Real-Debrid dashboard at <https://real-debrid.com/apitoken>.
* `ALLDEBRID_API_TOKEN` – Personal API token for AllDebrid integrations. **Source:**
  AllDebrid dashboard at <https://alldebrid.com/apikeys>.
* `SPROX_CONFIG` – Override the default configuration file path used by the server and the
  CLI validator.
* `SPROX_PROXY_URL` – Force all upstream requests to use the provided SOCKS5 proxy
  regardless of per-route settings.
* `SPROX_DIRECT_PROXY_URL` – Override the HTTP proxy used by `/proxy/stream` requests.
* `SPROX_DIRECT_API_PASSWORD` – Inject the shared secret required for `/proxy/stream`
  without modifying configuration files.
* `SPROX_API_PASSWORD` – Require `Authorization: Bearer` tokens for `/proxy/stream`
  requests and other protected routes.
* `SPROX_DIRECT_REQUEST_TIMEOUT_MS` – Override the direct stream request timeout in
  milliseconds.
* `SPROX_DIRECT_RESPONSE_BUFFER_BYTES` – Override the initial HTTP/2 receive window for
  direct stream responses.

## Containerized workflow

Build and run the proxy in a container to match production-like deployments or to avoid
installing the Rust toolchain locally:

```bash
# Build the optimized image
docker build -t sprox:latest .

# Run the container, exposing the default listener and mounting local configs
docker run --rm \
  -p 8080:8080 \
  --mount "type=bind,src=$(pwd)/config,dst=/config,readonly" \
  --mount "type=bind,src=$(pwd)/.env,dst=/app/.env,readonly" \
  sprox:latest
```

The image executes as a non-root user and expects configuration files at `/config`. The
entrypoint defaults to `--config /config/routes.yaml`, so custom locations can be supplied
via `SPROX_CONFIG` or CLI arguments. Mount `.env` files as read-only bindings to
`/app/.env` (as shown above) to load secrets.

The `scripts/docker-run.sh` helper automates the build/run workflow. It produces a local
`sprox:local` image (override with `IMAGE_NAME`) and starts the container with the
configuration directory and optional `.env` file mounted read-only:

```bash
./scripts/docker-run.sh
```

Pass any additional arguments after the script invocation to forward them to the
containerized binary (for example `./scripts/docker-run.sh --config /config/routes.yaml`).

The container image also exposes a Docker health check that queries the `/health` endpoint
via the `sprox healthcheck` CLI subcommand. When running outside Docker you can invoke the
command manually:

```bash
sprox healthcheck --url http://127.0.0.1:8080/health
```

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
   ├─ main.rs             # Application entry point
   ├─ app.rs              # Axum application builder
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
