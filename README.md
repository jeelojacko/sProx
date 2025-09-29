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

To prepare for future development, ensure that you have:

- Rust toolchain (2021 edition or newer) installed via [rustup](https://rustup.rs/).
- FFmpeg and/or Shaka Packager available on your development machine if you plan to
  exercise streaming conversion features later on.

Further documentation and setup steps will be added as the implementation progresses.
