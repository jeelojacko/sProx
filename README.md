# sProx

sProx is a Rust-based streaming proxy designed to orchestrate HTTP reverse proxying, adaptive bitrate manifest rewriting, and optional DASH-to-HLS conversion workflows. The project skeleton follows a modular layout so future tasks can iteratively flesh out the proxy engine, security primitives, and media tooling.

## Repository layout

```
sProx/
├─ Cargo.toml             # Rust manifest (to be populated in later tasks)
├─ .env.example           # Sample environment variables (secrets are excluded)
├─ config/                # Configuration files (routing rules, TLS toggles)
├─ packagers/             # Helper scripts for FFmpeg/Shaka Packager
├─ src/
│  ├─ main.rs             # Application entry point (to be implemented)
│  ├─ app.rs              # Axum application builder (future work)
│  └─ stream/             # Streaming helpers (HLS, DASH, conversions)
└─ docs/                  # Additional documentation and design notes
```

## Getting started

This repository currently contains the directory scaffolding only. Upcoming tasks will
introduce the Rust crate setup, configuration loader, and the core proxy pipeline.

### Configuration

A sample `config/routes.yaml` file is included to document the expected shape of routing
rules. Each entry under `routes` defines a listener, the upstream origin it connects to,
and optional transport toggles.

```yaml
routes:
  - id: "vod-edge"
    listen:
      host: "0.0.0.0"
      port: 8080
    upstream:
      origin: "https://origin.example.com/vod"
      tls:
        enabled: true
        sni_hostname: "origin.example.com"
        insecure_skip_verify: false
      socks5:
        enabled: false
        address: "127.0.0.1:1080"
    hls:
      enabled: true
      rewrite_playlist_urls: true
      base_url: "https://cdn.example.com/hls/"
```

Schema highlights:

- `listen.host` / `listen.port` – Address where sProx accepts incoming connections for
  the route.
- `upstream.origin` – The absolute URL for the backend service or packager.
- `upstream.tls` – Controls upstream TLS negotiation. Set `enabled` to `true` when the
  origin expects HTTPS, optionally override the `sni_hostname`, and use
  `insecure_skip_verify` only for local testing where certificate validation should be
  bypassed.
- `upstream.socks5` – When `enabled`, outbound traffic is tunnelled through the provided
  SOCKS5 proxy `address`. Username and password fields are available for authenticated
  proxies.
- `hls` – Toggle playlist-aware behaviour. Use `rewrite_playlist_urls` and `base_url` to
  emit absolute URLs pointing at your CDN or edge. `allow_insecure_segments` (see sample)
  can be flipped to permit mixed HTTP/HTTPS playlists during migrations.

## Development tooling

The workspace is configured to use a pinned stable toolchain defined in `rust-toolchain.toml`.
Required components (Rustfmt and Clippy) are installed automatically by `rustup` when the
toolchain is set. A couple of helper scripts are available for common commands:

- `./scripts/fmt.sh` – runs `cargo fmt --all` for full-workspace formatting.
- `./scripts/clippy.sh` – runs Clippy across all targets and features with warnings treated as
  errors.

Additional Cargo aliases are defined in `.cargo/config.toml` for quick linting (for example,
`cargo clippy-all`).

### Editor integration

VS Code users can rely on the repository-provided `.vscode/settings.json`, which enables
`rust-analyzer` with Clippy-based checks and format-on-save for Rust files. Recommended
extensions (Rust Analyzer, Even Better TOML, Crates) are listed in `.vscode/extensions.json`.

To prepare for future development, ensure that you have:

- Rust installed via [rustup](https://rustup.rs/); syncing the toolchain is as easy as running
  `rustup show` inside the repository.
- FFmpeg and/or Shaka Packager available on your development machine if you plan to exercise
  streaming conversion features later on.
=======
To prepare for future development, ensure that you have:

- Rust toolchain (2021 edition or newer) installed via [rustup](https://rustup.rs/).
- FFmpeg and/or Shaka Packager available on your development machine if you plan to
  exercise streaming conversion features later on.


Further documentation and setup steps will be added as the implementation progresses.
