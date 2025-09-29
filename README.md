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

Further documentation and setup steps will be added as the implementation progresses.
