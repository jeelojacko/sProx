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

### Edge listeners

- Built on top of Axum/Tokio, exposing HTTP/1.1, HTTP/2, and eventually HTTP/3.
- Performs connection upgrades (WebSocket) and handles graceful shutdown signals.
- Relies on a TLS abstraction so routes can toggle termination independently.

### Middleware stack

- Tower layers enforce cross-cutting policies: authentication, request shaping,
  observability, rate limiting, and header normalisation.
- Provides structured logging, OpenTelemetry tracing, and metrics emission.
- Maintains a request-scoped context object that downstream layers can inspect.

### Streaming transformation layer

- Contains protocol-specific handlers for HLS, DASH, CMAF, and future protocols.
- Rewrites manifests (variant playlists, MPDs) to adjust CDN base URLs and inject DRM
  descriptors.
- Coordinates optional transmuxing pipelines using FFmpeg/Shaka Packager helpers in
  `packagers/`.
- Implements caching adaptors to reduce round-trips for popular manifests.

### Background jobs and utilities

- A lightweight scheduler runs periodic maintenance tasks (certificate renewal, cache
  eviction, DRM key refresh).
- Shared primitives live in `src/stream/` for parsing manifests, rewriting URLs, and
  applying policy checks.
- Telemetry exporters send metrics to Prometheus or StatsD; logs are structured (JSON) for
  log aggregation systems.

## Request lifecycle

1. Listener accepts a client connection and negotiates TLS if enabled.
2. Axum routes the incoming request based on path/prefix matches defined in the
   configuration.
3. Middleware stack authenticates the request, rate limits if necessary, and enriches
   the context with metadata (device type, session ID, geolocation).
4. Routing component selects the upstream origin and issues an outbound request using the
   Hyper client pool. SOCKS5 tunnels or HTTP CONNECT proxies can be inserted here.
5. Response flows through the streaming layer. If the payload is a manifest, it is parsed
   and rewritten; otherwise it may be streamed back directly (for media segments).
6. DRM hooks request keys or licenses when required, injecting the appropriate headers or
   query parameters into manifests or responses.
7. The transformed response is streamed back to the client with updated caching and
   security headers.

## Extensibility notes

- New authentication mechanisms (e.g., JWT validation, OAuth token introspection) can be
  added as Tower layers without modifying downstream code.
- Additional manifest types should implement a common trait so they can be plugged into
  the processing pipeline with minimal wiring changes.
- Observability exporters should follow the OpenTelemetry standard to remain compatible
  with multiple backends.

## Future work

- Pluggable policy engine for per-route authorisation rules.
- Integrated configuration hot-reload with validation rollback support.
- QUIC/HTTP3 listener implementation once the Rust ecosystem stabilises.
- Auto-scaling recommendations based on telemetry trends and burst detection.
