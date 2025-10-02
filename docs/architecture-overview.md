# Architecture overview

This document expands on the high-level proxy architecture to illustrate the planned
modules, data flow, and integration points. The implementation is still evolving; the
structure below provides guidance for future development tasks.

## Component map

```
                                        ┌──────────────────────┐
                                        │    Config loader     │
                                        │ (TOML/YAML/ENV merge)│
                                        └──────────┬───────────┘
                                                   │
                                                   ▼
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────────────┐
│  Edge listeners      │    │  Middleware stack    │    │  Streaming transformation    │
│  (Axum router)       │    │  (Tower layers)      │    │  (manifests, segments, DRM)  │
└─────────┬────────────┘    └──────────┬───────────┘    └──────────────┬──────────────┘
          │                             │                               │
          ▼                             ▼                               ▼
  Connection pool             Request context store              Manifest workers
  TLS terminators             Auth & rate limiting               Segment fetchers
          │                             │                               │
          └─────────────┬───────────────┴───────────────┬───────────────┘
                        ▼                               ▼
                Upstream dispatcher              Background jobs
                (hyper client pool)             (scheduler, cache)
```

Configuration data flows through the loader, which merges YAML files with environment
overrides before producing strongly typed route, direct stream, and telemetry settings.
The resulting state is stored in `AppState`, backed by `ArcSwap`, so hot reloads can swap
configs without tearing down listeners. Shared stores (routing engine, retry budgets,
secrets cache) live alongside the Axum router and are updated atomically.

### Edge listeners

- Built on top of Axum/Tokio, exposing HTTP/1.1, HTTP/2, and eventually HTTP/3.
- Performs connection upgrades (WebSocket) and handles graceful shutdown signals.
- Relies on a TLS abstraction so routes can toggle termination independently. Certificate
  material is loaded from disk, reloaded automatically when `watch_for_changes` is set, and
  prepared for external ACME clients when cache paths are provided.

### Middleware stack

- Tower layers enforce cross-cutting policies: authentication, request shaping,
  observability, rate limiting, header normalisation, and CORS.
- Provides structured logging, OpenTelemetry tracing, and metrics emission. Sensitive
  logging settings control whether DRM-related query parameters are redacted and if
  potentially sensitive headers are logged verbatim.
- Maintains a request-scoped context object that downstream layers can inspect. The
  middleware also manages the global token-bucket rate limiter, ensuring bursty clients are
  throttled consistently.

### Streaming transformation layer

- Contains protocol-specific handlers for HLS, DASH, CMAF, and future protocols.
- Rewrites manifests (variant playlists, MPDs) to adjust CDN base URLs and inject DRM
  descriptors.
- Coordinates optional transmuxing pipelines using FFmpeg/Shaka Packager helpers in
  `packagers/`.
- Implements caching adaptors to reduce round-trips for popular manifests.
- Hosts the direct stream endpoint, which issues outbound range requests via `reqwest` with
  configurable retries, allowlists, and header sanitisation.

### Background jobs and utilities

- A lightweight scheduler runs periodic maintenance tasks (certificate renewal, cache
  eviction, DRM key refresh). SIGHUP-driven reloads reuse the same machinery to swap in new
  configuration snapshots.
- Shared primitives live in `src/stream/` for parsing manifests, rewriting URLs, applying
  allowlists, and enforcing retry policies. The in-memory secrets store applies TTLs to DRM
  keys and is exposed via the `/keys` endpoint for operational introspection.
- Telemetry exporters send metrics to Prometheus while request traces are emitted as JSON
  for log aggregation systems. Metrics are scraped via `/metrics` using the embedded
  Prometheus recorder.

### Direct stream pipeline

The `/proxy/stream` handler is implemented as a specialised pipeline sitting alongside the
manifest processors:

1. Parse and validate query parameters, ensuring the destination URL exists and, when
   configured, that the shared API password matches.
2. Enforce allowlist rules (domain globs, scheme restrictions, optional path globs) and
   reject destinations that resolve to private, loopback, multicast, or documentation IP
   ranges.
3. Normalise override headers by converting `h_*` query parameters into canonical HTTP
   headers. Overrides are validated against a curated allowlist to prevent host/header
   spoofing.
4. Issue the upstream request via a lazily constructed `reqwest::Client` that honours
   optional HTTP proxy settings, timeouts, and retry budgets defined in configuration.
5. Stream the upstream response back to the client while enforcing a response-header
   allowlist and ensuring range semantics remain consistent.

## Request lifecycle

1. Listener accepts a client connection and negotiates TLS if enabled.
2. Axum routes the incoming request based on path/prefix matches defined in the
   configuration.
3. Middleware stack authenticates the request, rate limits if necessary, and enriches
   the context with metadata (device type, session ID, geolocation).
4. Routing component selects the upstream origin and issues an outbound request using the
   Hyper client pool. SOCKS5 tunnels or HTTP CONNECT proxies can be inserted here. For
   direct stream requests the specialised pipeline validates and executes the request
   instead of the generic router.
5. Response flows through the streaming layer. If the payload is a manifest, it is parsed
   and rewritten; otherwise it may be streamed back directly (for media segments) or via the
   direct stream responder.
6. DRM hooks request keys or licenses when required, injecting the appropriate headers or
   query parameters into manifests or responses. Secrets are served from the in-memory
   store, respecting per-entry TTLs.
7. The transformed response is streamed back to the client with updated caching and
   security headers while metrics counters and histograms are recorded for observability.

## Extensibility notes

- New authentication mechanisms (e.g., JWT validation, OAuth token introspection) can be
  added as Tower layers without modifying downstream code.
- Additional manifest types should implement a common trait so they can be plugged into
  the processing pipeline with minimal wiring changes.
- Observability exporters should follow the OpenTelemetry standard to remain compatible
  with multiple backends. The Prometheus recorder can be swapped or augmented behind the
  telemetry facade if alternate metrics backends are preferred.
- Rate limiting, CORS policies, and header allowlists are all configuration-driven. Adding
  new knobs only requires extending the config loader and `AppState` rebuild logic.

## Future work

- Pluggable policy engine for per-route authorisation rules.
- QUIC/HTTP3 listener implementation once the Rust ecosystem stabilises.
- Auto-scaling recommendations based on telemetry trends and burst detection.
- External secret-manager integrations that can back the in-memory store with durable
  providers.
